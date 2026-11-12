"""The Logto Management API calls authsvc needs, in the auth service's neutral terms.

authsvc calls it as a Machine-to-machine app holding the "Logto Management API access" role
(AUTH_MGMT_CLIENT_ID / AUTH_MGMT_CLIENT_SECRET):

    LogtoDirectory  an agenticwf.auth.directory.Directory: a group is a Logto organization, its
                    members hold the organization role AUTH_GROUP_MEMBER_ROLE (`member`), its admins
                    also AUTH_GROUP_ADMIN_ROLE (`admin`)
    LogtoTokens     an agenticwf.auth.tokens.TokenBackend: Logto's personal access tokens. The CLI
                    exchanges one for short-lived access tokens itself (token exchange on the CLI's
                    Native app), so /verify only ever sees Logto JWTs (``accepts_bearer = False``).
"""

from __future__ import annotations

import threading
import time
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from agenticwf.auth.config import Settings
from agenticwf.auth.directory import ManagementError, ManagementUnavailableError

from agenticwf_auth_logto.settings import LogtoSettings

TOKEN_MARGIN = 60
PAT_TOKEN_TYPE = "urn:logto:token-type:personal_access_token"


def internal_headers(logto: LogtoSettings) -> dict[str, str]:
    """Calls to Logto inside the container present the public host and scheme, as Caddy would."""
    public = urlsplit(logto.endpoint or "")
    return {"Host": public.netloc, "X-Forwarded-Proto": public.scheme or "https", "X-Forwarded-Host": public.netloc}


def _q(value: str) -> str:
    return quote(value, safe="")


def _seconds(ms: Any) -> int | None:
    return int(ms) // 1000 if ms else None


class ManagementAPI:
    """HTTP plumbing: one M2M access token, reused until shortly before it expires."""

    def __init__(self, settings: Settings, logto: LogtoSettings, http: httpx.Client | None = None):
        self._s = settings
        self._logto = logto
        self._http = http or httpx.Client(base_url=logto.internal_url, timeout=10, headers=internal_headers(logto))
        self._token: tuple[str, float] | None = None
        self._lock = threading.Lock()

    def _access_token(self) -> str:
        with self._lock:
            if self._token and self._token[1] - time.time() > TOKEN_MARGIN:
                return self._token[0]
            try:
                r = self._http.post("/oidc/token", auth=(self._s.mgmt_client_id or "", self._s.mgmt_client_secret or ""),
                                    data={"grant_type": "client_credentials", "resource": self._logto.mgmt_resource,
                                          "scope": "all"})
            except httpx.HTTPError as exc:
                raise ManagementUnavailableError(str(exc)) from exc
            if r.status_code != 200:
                raise ManagementError(502, f"Management API token request failed ({r.status_code})")
            body = r.json()
            self._token = (body["access_token"], time.time() + int(body.get("expires_in", 3600)))
            return self._token[0]

    def call(self, method: str, path: str, json: Any = None) -> httpx.Response:
        try:
            r = self._http.request(method, path, json=json, headers={"Authorization": f"Bearer {self._access_token()}"})
        except httpx.HTTPError as exc:
            raise ManagementUnavailableError(str(exc)) from exc
        if r.status_code >= 500:
            raise ManagementUnavailableError(f"Management API returned {r.status_code}")
        return r

    @staticmethod
    def expect(r: httpx.Response, what: str, ok: tuple[int, ...] = (200,)) -> Any:
        if r.status_code == 404:
            raise ManagementError(404, f"{what}: not found.")
        if r.status_code not in ok:
            raise ManagementError(502, f"{what} failed ({r.status_code})")
        return r.json() if r.content and "json" in r.headers.get("content-type", "") else None

    def all(self, path: str, what: str) -> list[dict]:
        items, page = [], 1
        while True:
            sep = "&" if "?" in path else "?"
            batch = self.expect(self.call("GET", f"{path}{sep}page={page}&page_size=100"), what) or []
            items += batch
            if len(batch) < 100:
                return items
            page += 1


def _person(user: dict) -> dict:
    """A Logto user as authsvc shows it. Accounts made while sign-up asked only for an email have no
    username; agenticwf.auth.groups.Profiles lets the email stand in."""
    return {"id": user["id"], "username": user.get("username") or "", "name": user.get("name") or "",
            "email": user.get("primaryEmail") or "", "enabled": not user.get("isSuspended", False)}


def _group(org: dict) -> dict:
    return {"id": org["id"], "name": org.get("name") or org["id"], "description": org.get("description") or ""}


class LogtoDirectory:
    """Organizations as groups; the admin role marks a group's admins."""

    def __init__(self, api: ManagementAPI, logto: LogtoSettings):
        self.api = api
        self._logto = logto
        self._role_ids: dict[str, str] = {}

    def _org(self, org_id: str) -> str:
        return f"/api/organizations/{_q(org_id)}"

    def _role_id(self, name: str) -> str:
        if name not in self._role_ids:
            roles = self.api.all("/api/organization-roles", "listing group roles")
            self._role_ids.update({r["name"]: r["id"] for r in roles})
        if name not in self._role_ids:
            raise ManagementError(409, f"Logto has no organization role {name!r}: create it (Organization template) "
                                       "or restart the container to have it created.")
        return self._role_ids[name]

    def _roles_for(self, admin: bool) -> list[str]:
        return [self._role_id(self._logto.group_member_role)] + ([self._role_id(self._logto.group_admin_role)] if admin else [])

    def _is_admin(self, entry: dict) -> bool:
        return self._logto.group_admin_role in {r["name"] for r in entry.get("organizationRoles") or ()}

    # -- groups --------------------------------------------------------------------------------
    def groups(self) -> list[dict]:
        return [_group(o) for o in self.api.all("/api/organizations", "listing groups")]

    def group(self, group_id: str) -> dict:
        return _group(self.api.expect(self.api.call("GET", self._org(group_id)), "reading the group"))

    def create_group(self, name: str, description: str) -> dict:
        return _group(self.api.expect(self.api.call("POST", "/api/organizations", json={"name": name, "description": description}),
                                      "creating the group", (200, 201)))

    def update_group(self, group_id: str, fields: dict) -> dict:
        return _group(self.api.expect(self.api.call("PATCH", self._org(group_id), json=fields), "changing the group"))

    def delete_group(self, group_id: str) -> None:
        self.api.expect(self.api.call("DELETE", self._org(group_id)), "deleting the group", (204,))

    def group_members(self, group_id: str) -> list[dict]:
        return [{**_person(u), "admin": self._is_admin(u)}
                for u in self.api.all(f"{self._org(group_id)}/users", "listing members")]

    def add_member(self, group_id: str, user_id: str, admin: bool = False) -> None:
        roles = self._roles_for(admin)
        self.api.expect(self.api.call("POST", f"{self._org(group_id)}/users", json={"userIds": [user_id]}),
                        "adding the member", (201, 204))
        self._set_roles(group_id, user_id, roles)

    def remove_member(self, group_id: str, user_id: str) -> None:
        self.api.expect(self.api.call("DELETE", f"{self._org(group_id)}/users/{_q(user_id)}"), "removing the member", (204,))

    def set_admin(self, group_id: str, user_id: str, admin: bool) -> None:
        self._set_roles(group_id, user_id, self._roles_for(admin))

    def _set_roles(self, group_id: str, user_id: str, role_ids: list[str]) -> None:
        """Replace the member's organization roles."""
        self.api.expect(self.api.call("PUT", f"{self._org(group_id)}/users/{_q(user_id)}/roles",
                                      json={"organizationRoleIds": role_ids}), "setting the member's roles", (201, 204))

    def user_groups(self, user_id: str) -> list[dict]:
        found = self.api.expect(self.api.call("GET", f"/api/users/{_q(user_id)}/organizations"),
                                "listing the user's groups") or []
        return [{"id": o["id"], "name": o.get("name") or o["id"], "admin": self._is_admin(o)} for o in found]

    # -- users ---------------------------------------------------------------------------------
    def user(self, user_id: str) -> dict:
        return _person(self.api.expect(self.api.call("GET", f"/api/users/{_q(user_id)}"), "reading the user") or {"id": user_id})

    def find_user(self, email: str) -> dict | None:
        r = self.api.call("GET", f"/api/users?search.primaryEmail={_q(email)}&mode.primaryEmail=exact")
        users = self.api.expect(r, "looking up the user") or []
        return next((_person(u) for u in users if (u.get("primaryEmail") or "").lower() == email.lower()), None)


class LogtoTokens:
    """Logto's personal access tokens, managed for the signed-in user."""

    accepts_bearer = False   # the CLI exchanges them (PAT_TOKEN_TYPE); /verify never sees one

    def __init__(self, api: ManagementAPI):
        self.api = api

    @staticmethod
    def _path(user_id: str) -> str:
        return f"/api/users/{_q(user_id)}/personal-access-tokens"

    @staticmethod
    def _view(token: dict) -> dict:
        """Never the token value: Logto returns it on every listing."""
        return {"name": token["name"], "created_at": _seconds(token.get("createdAt")),
                "expires_at": _seconds(token.get("expiresAt"))}

    def list(self, user_id: str) -> list[dict]:
        r = self.api.call("GET", self._path(user_id))
        if r.status_code != 200:
            raise ManagementError(502, f"listing tokens failed ({r.status_code})")
        return [self._view(t) for t in r.json()]

    def create(self, user_id: str, name: str, expires_at: int) -> tuple[str, dict]:
        r = self.api.call("POST", self._path(user_id), json={"name": name, "expiresAt": expires_at * 1000 if expires_at else None})
        if r.status_code == 422:
            raise ManagementError(409, "A token with this name already exists.")
        if r.status_code not in (200, 201):
            raise ManagementError(502, f"creating the token failed ({r.status_code})")
        body = r.json()
        return body["value"], self._view(body)

    def delete(self, user_id: str, name: str) -> None:
        r = self.api.call("DELETE", f"{self._path(user_id)}/{_q(name)}")
        if r.status_code == 404:
            raise ManagementError(404, "No such token.")
        if r.status_code != 204:
            raise ManagementError(502, f"revoking the token failed ({r.status_code})")

    def resolve(self, raw: str):
        raise NotImplementedError("Logto PATs are exchanged by the CLI, never sent to /verify")
