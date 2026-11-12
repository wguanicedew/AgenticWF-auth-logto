import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from agenticwf.auth.authn import TokenVerifier
from agenticwf.auth.config import Settings

from agenticwf_auth_logto import LogtoSettings, provider

ISSUER = "https://auth.example.org/oidc"
AUDIENCE = "https://api.example.org"
SECRET = b"s" * 48


class _Key:
    def __init__(self, key):
        self.key = key


class FakeJWKS:
    def __init__(self, private_key):
        self.public = private_key.public_key()

    def get_signing_key_from_jwt(self, token):
        return _Key(self.public)


@pytest.fixture(scope="session")
def private_key():
    return ec.generate_private_key(ec.SECP384R1())


@pytest.fixture
def logto():
    return LogtoSettings(endpoint="https://auth.example.org")


@pytest.fixture
def settings(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("required_scopes: [app:access]\nrules:\n  - path: /api/**\n    scopes: [agent:use]\n")
    return Settings(issuer=ISSUER, jwks_uri="unused", audiences=(AUDIENCE, "urn:logto:organization:*"),
                    policy_file=policy, context_secret=SECRET, session_store="memory")


@pytest.fixture
def verifier(settings, logto, private_key):
    p = provider(settings, logto)
    return TokenVerifier(settings, jwks_client=FakeJWKS(private_key), claims=p.claims, check_claims=p.check_claims)


@pytest.fixture
def make_token(private_key):
    def _make(**overrides):
        """A Logto-like access token (RFC 9068): API permissions in `scope`, no profile claims."""
        now = int(time.time())
        claims = {"iss": ISSUER, "sub": "user_1", "aud": AUDIENCE, "iat": now, "exp": now + 600,
                  "client_id": "app_1", "scope": "app:access agent:use knowledge:read", "jti": "t1"}
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, private_key, algorithm="ES384", headers={"kid": "k1"})

    return _make
