from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient

from agenticwf.auth.app import create_app
from agenticwf.auth.directory import ManagementError

from agenticwf_auth_logto import build, endpoints, provider
from agenticwf_auth_logto.management import PAT_TOKEN_TYPE, LogtoDirectory, LogtoTokens, ManagementAPI


def test_organization_and_machine_tokens(verifier, make_token):
    ctx = verifier.context(make_token(aud="urn:logto:organization:org_9", roles=["researcher"]))
    assert ctx.organization_id == "org_9" and ctx.roles == {"researcher"} and not ctx.is_machine
    assert ctx.scopes == {"app:access", "agent:use", "knowledge:read"}
    machine = verifier.context(make_token(sub="app_1"))           # M2M: sub is the application id
    assert machine.is_machine and machine.user_id is None


def test_endpoints_carry_resource_and_consent(settings, logto):
    e = endpoints(settings, logto)
    assert e.authorization == "https://auth.example.org/oidc/auth"
    assert e.end_session == "https://auth.example.org/oidc/session/end"
    assert e.token == "http://127.0.0.1:3001/oidc/token" and e.revocation.endswith("/oidc/token/revocation")
    assert e.auth_params == {"resource": "https://api.example.org", "prompt": "consent"}
    assert e.token_params == {"resource": "https://api.example.org"}
    assert e.internal_headers["X-Forwarded-Host"] == "auth.example.org"


def test_cli_config_and_profiles(settings, logto, verifier, make_token):
    p = provider(settings, logto)
    assert p.client_config == {"auth_url": "https://auth.example.org", "resource": "https://api.example.org",
                               "pat_token_type": PAT_TOKEN_TYPE}
    assert p.lookup_profiles and p.directory is None and p.tokens is None
    r = TestClient(create_app(settings, p, verifier=verifier)).get("/auth/config").json()
    assert r["auth_url"] == "https://auth.example.org" and r["pat_token_type"] == PAT_TOKEN_TYPE   # as before the split
    assert r["scopes"] == settings.cli_scopes


def test_build_from_env(monkeypatch):
    monkeypatch.setenv("LOGTO_ENDPOINT", "https://auth.example.org/")
    monkeypatch.setenv("AUTH_AUDIENCES", "https://api.example.org")
    monkeypatch.setenv("AUTH_CONTEXT_SECRET", "x" * 32)
    monkeypatch.setenv("AUTH_WEB_SCOPES", "openid offline_access app:access")
    settings, p = build()
    assert settings.issuer == "https://auth.example.org/oidc"
    assert settings.jwks_uri == "http://127.0.0.1:3001/oidc/jwks"
    assert settings.cli_scopes == "openid offline_access app:access"   # the CLI asks for what the browser does
    assert p.name == "logto"
    monkeypatch.delenv("LOGTO_ENDPOINT")
    with pytest.raises(RuntimeError, match="LOGTO_ENDPOINT"):
        build()


def test_login_sends_resource(settings, logto, verifier):
    s = replace(settings, web_client_id="web", web_client_secret="x", app_origin="https://app.example.org")
    app = create_app(s, provider(s, logto), verifier=verifier)
    r = TestClient(app, base_url="https://app.example.org", follow_redirects=False).get("/auth/login")
    query = parse_qs(urlsplit(r.headers["location"]).query)
    assert r.headers["location"].startswith("https://auth.example.org/oidc/auth?")
    assert query["resource"] == ["https://api.example.org"] and query["prompt"] == ["consent"]


def _api(settings, logto, handler):
    s = replace(settings, mgmt_client_id="m2m", mgmt_client_secret="s")
    return ManagementAPI(s, logto, http=httpx.Client(base_url="http://logto", transport=httpx.MockTransport(handler)))


def test_tokens_call_the_management_api(settings, logto):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.raw_path.decode(), request.headers.get("authorization"), request.content))
        if request.url.path == "/oidc/token":
            assert b"resource=https%3A%2F%2Fdefault.logto.app%2Fapi" in request.content and b"scope=all" in request.content
            return httpx.Response(200, json={"access_token": "mgmt", "expires_in": 3600})
        if request.method == "POST":
            return httpx.Response(201, json={"name": "ci", "value": "pat_x", "createdAt": 1_000_000, "expiresAt": 2_000_000})
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(200, json=[{"name": "ci", "value": "pat_x", "createdAt": 1_000_000, "expiresAt": None}])

    tokens = LogtoTokens(_api(settings, logto, handler))
    assert not tokens.accepts_bearer
    assert tokens.create("u/1", "ci", 2000) == ("pat_x", {"name": "ci", "created_at": 1000, "expires_at": 2000})
    assert tokens.list("u/1") == [{"name": "ci", "created_at": 1000, "expires_at": None}]   # never the value
    tokens.delete("u/1", "my token")
    paths = [(m, p) for m, p, _, _ in calls]
    assert paths == [("POST", "/oidc/token"), ("POST", "/api/users/u%2F1/personal-access-tokens"),
                     ("GET", "/api/users/u%2F1/personal-access-tokens"),
                     ("DELETE", "/api/users/u%2F1/personal-access-tokens/my%20token")]  # one M2M token, reused
    assert calls[1][2] == "Bearer mgmt" and b'"expiresAt":2000000' in calls[1][3]


def test_directory_maps_organizations(settings, logto):
    calls = []
    roles = [{"id": "r_admin", "name": "admin"}, {"id": "r_member", "name": "member"}]

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path.decode()
        calls.append((request.method, path, request.content))
        if path == "/oidc/token":
            return httpx.Response(200, json={"access_token": "mgmt", "expires_in": 3600})
        if path.startswith("/api/organization-roles"):
            return httpx.Response(200, json=roles)
        if path == "/api/users/alice/organizations":
            return httpx.Response(200, json=[{"id": "o1", "name": "EIC", "organizationRoles": roles},
                                             {"id": "o2", "name": "Other", "organizationRoles": roles[1:]}])
        if path.startswith("/api/organizations/o1/users?"):
            return httpx.Response(200, json=[{"id": "bob", "name": "Bob", "primaryEmail": "bob@x.org",
                                              "organizationRoles": roles[1:]}])
        if path == "/api/users/carol":
            return httpx.Response(200, json={"id": "carol", "primaryEmail": "carol@x.org", "isSuspended": True})
        if path.startswith("/api/organizations/nope"):
            return httpx.Response(404)
        if request.method in ("POST", "PUT"):
            return httpx.Response(201)
        return httpx.Response(404)

    d = LogtoDirectory(_api(settings, logto, handler), logto)
    assert d.user_groups("alice") == [{"id": "o1", "name": "EIC", "admin": True}, {"id": "o2", "name": "Other", "admin": False}]
    assert d.group_members("o1") == [{"id": "bob", "username": "", "name": "Bob", "email": "bob@x.org",
                                      "enabled": True, "admin": False}]
    assert d.user("carol") == {"id": "carol", "username": "", "name": "", "email": "carol@x.org", "enabled": False}
    calls.clear()
    d.add_member("o1", "bob", admin=True)
    changes = [(m, p, c) for m, p, c in calls if m != "GET"]       # role ids are looked up once, first
    assert [(m, p) for m, p, _ in changes] == [("POST", "/api/organizations/o1/users"),
                                               ("PUT", "/api/organizations/o1/users/bob/roles")]
    assert b'"organizationRoleIds":["r_member","r_admin"]' in changes[1][2].replace(b" ", b"")
    with pytest.raises(ManagementError) as exc:
        d.group("nope")
    assert exc.value.status == 404
