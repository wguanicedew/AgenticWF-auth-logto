"""Logto settings (LOGTO_*, and the Logto-only AUTH_*), and the provider-neutral ones they imply."""

from __future__ import annotations

import os
from dataclasses import dataclass

from agenticwf.auth.config import Settings


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


@dataclass(frozen=True)
class LogtoSettings:
    endpoint: str | None = None  # public Logto URL, e.g. https://auth.example.org; used for browser redirects
    internal_url: str = "http://127.0.0.1:3001"  # server-to-server calls
    # API resource requested at login (Logto issues a JWT for it); default: the first non-wildcard audience.
    web_resource: str | None = None
    mgmt_resource: str = "https://default.logto.app/api"  # Logto OSS Management API
    group_admin_role: str = "admin"    # organization role of a group's admins
    group_member_role: str = "member"  # organization role given to the members they add

    @classmethod
    def from_env(cls) -> "LogtoSettings":
        return cls(
            endpoint=(_env("LOGTO_ENDPOINT") or "").rstrip("/") or None,
            internal_url=_env("LOGTO_INTERNAL_URL", "http://127.0.0.1:3001").rstrip("/"),
            web_resource=_env("AUTH_WEB_RESOURCE"),
            mgmt_resource=_env("AUTH_MGMT_RESOURCE", "https://default.logto.app/api"),
            group_admin_role=_env("AUTH_GROUP_ADMIN_ROLE", "admin"),
            group_member_role=_env("AUTH_GROUP_MEMBER_ROLE", "member"),
        )

    def resource(self, settings: Settings) -> str | None:
        return self.web_resource or settings.default_audience


def settings_from_env(logto: LogtoSettings) -> Settings:
    """The provider-neutral settings, with Logto's defaults (AUTH_* variables still win)."""
    issuer = f"{logto.endpoint}/oidc" if logto.endpoint else None
    if not (issuer or _env("AUTH_ISSUER")):
        raise RuntimeError("Set LOGTO_ENDPOINT (public Logto URL) or AUTH_ISSUER")
    # Logto puts in a token only the API permissions asked for: the CLI asks for what the browser
    # sign-in does, so a user signed in on the command line is approved as well.
    web_scopes = _env("AUTH_WEB_SCOPES", "openid profile email offline_access")
    settings = Settings.from_env(
        issuer=issuer,
        jwks_uri=f"{logto.internal_url}/oidc/jwks",
        web_scopes=web_scopes,
        cli_scopes=web_scopes,
    )
    if settings.web_enabled and not logto.endpoint:
        raise RuntimeError("Browser login needs LOGTO_ENDPOINT")
    return settings
