"""Logto access tokens -> AuthContext."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from agenticwf.auth.context import AuthContext

ORG_AUDIENCE_PREFIX = "urn:logto:organization:"


def context_from_claims(claims: dict[str, Any], roles_claim: str = "roles",
                        external_identity_claim: str = "external_identity") -> AuthContext:
    """Logto tokens follow RFC 9068: API permissions in `scope`, `sub` = `client_id` for
    machine-to-machine tokens; roles only with a custom JWT claim (`roles`). Organization tokens
    carry the organization in the audience (`urn:logto:organization:<id>`). The token carries no
    username, name or email: authsvc looks them up (Provider.lookup_profiles)."""
    ctx = AuthContext.from_claims(claims, roles_claim, external_identity_claim)
    if not ctx.organization_id:
        org = next((a[len(ORG_AUDIENCE_PREFIX):] for a in ctx.audience if a.startswith(ORG_AUDIENCE_PREFIX)), None)
        if org:
            ctx = replace(ctx, organization_id=org)
    return ctx
