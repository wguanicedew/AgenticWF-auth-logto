"""Logto provider of the AgenticWF auth service.

The auth service itself (agenticwf.auth, package agenticwf-auth-server) is in AgenticWF-auth and
provider-neutral; this package plugs Logto OSS into it:

    claims      Logto access tokens -> AuthContext: API resource permissions in `scope`,
                organization tokens by audience (`urn:logto:organization:<id>`)
    endpoints   Logto's /oidc/{auth,token,token/revocation,session/end}, with the API `resource`
                and prompt=consent (Logto issues refresh tokens only then)
    directory   the Management API (management.LogtoDirectory): organizations as groups
    tokens      Logto's personal access tokens (management.LogtoTokens), exchanged by the CLI
    profiles    Logto access tokens carry no username, name or email: authsvc looks them up

Run:  uvicorn --factory agenticwf_auth_logto:create_app
"""

from __future__ import annotations

from functools import partial

from fastapi import FastAPI

from agenticwf.auth import app as core
from agenticwf.auth.config import Settings
from agenticwf.auth.provider import OIDCEndpoints, Provider

from agenticwf_auth_logto.claims import context_from_claims
from agenticwf_auth_logto.management import (PAT_TOKEN_TYPE, LogtoDirectory, LogtoTokens, ManagementAPI,
                                             internal_headers)
from agenticwf_auth_logto.settings import LogtoSettings, settings_from_env

__all__ = ["LogtoSettings", "build", "create_app", "endpoints", "provider"]


def endpoints(settings: Settings, logto: LogtoSettings) -> OIDCEndpoints:
    resource = logto.resource(settings) or ""
    return OIDCEndpoints(
        authorization=f"{logto.endpoint}/oidc/auth",
        end_session=f"{logto.endpoint}/oidc/session/end",
        token=f"{logto.internal_url}/oidc/token",
        revocation=f"{logto.internal_url}/oidc/token/revocation",
        # Logto only issues refresh tokens (offline_access) with prompt=consent; first-party apps
        # are consented automatically. Without `resource`, the access token would be opaque.
        auth_params={"resource": resource, "prompt": "consent"},
        token_params={"resource": resource},
        internal_headers=internal_headers(logto),
    )


def provider(settings: Settings, logto: LogtoSettings, api: ManagementAPI | None = None) -> Provider:
    """The Logto Provider; ``api`` (built when AUTH_MGMT_CLIENT_ID is set) enables groups, profiles and PATs."""
    if api is None and settings.management_enabled:
        api = ManagementAPI(settings, logto)
    return Provider(
        name="logto",
        claims=partial(_claims, settings=settings),
        endpoints=endpoints(settings, logto) if logto.endpoint else None,
        directory=LogtoDirectory(api, logto) if api else None,
        tokens=LogtoTokens(api) if api else None,
        lookup_profiles=True,
        # For `agenticwf`: the resource to ask tokens for, and how its personal access tokens work.
        # `auth_url` stays the Logto endpoint (not the issuer, <endpoint>/oidc): CLIs from before the
        # provider split append /oidc themselves; current ones accept either.
        client_config={"auth_url": logto.endpoint or settings.issuer, "resource": logto.resource(settings),
                       "pat_token_type": PAT_TOKEN_TYPE},
    )


def _claims(claims: dict, settings: Settings):
    return context_from_claims(claims, settings.roles_claim, settings.external_identity_claim)


def build() -> tuple[Settings, Provider]:
    logto = LogtoSettings.from_env()
    settings = settings_from_env(logto)
    return settings, provider(settings, logto)


def create_app() -> FastAPI:
    settings, prov = build()
    return core.create_app(settings, prov)
