"""API-key and Bearer-token authentication with scopes.

Clients may authenticate with:

* ``X-API-Key: <secret>`` — primary path for third-party apps
* ``Authorization: Bearer <opaque_token>`` — from ``POST /oauth/token`` stub
* ``Authorization: Bearer <JWT>`` — when ``ZENITH_OIDC_JWKS_URL`` is set
  (validated against the IdP JWKS; see ``api.oidc``)

Demo keys live in ``api.config`` / the runtime ``KeyStore``. Opaque OAuth is a
local stub; prefer an external OIDC IdP for production SLA.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from api.config import Settings, get_settings
from api.errors import ApiError
from api.keystore import get_keystore
from api.oauth import get_token_store
from api.oidc import looks_like_jwt, validate_bearer_jwt

API_KEY_HEADER_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    """Authenticated caller derived from a valid API key, opaque token, or JWT."""

    key_id: str
    scopes: frozenset[str]
    label: str = ""
    auth_via: str = "api_key"  # "api_key" | "bearer" | "oidc_jwt"


async def require_api_key(
    request: Request,
    api_key: str | None = Security(api_key_header),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> Principal:
    # Prefer explicit API key header; fall back to Bearer (JWT or opaque).
    if api_key:
        stored = get_keystore().lookup_by_secret(api_key)
        if stored is None:
            raise ApiError(
                status_code=401,
                code="unauthorized",
                message="Invalid API key",
            )
        principal = Principal(
            key_id=stored.key_id,
            scopes=stored.scopes,
            label=stored.label,
            auth_via="api_key",
        )
        request.state.principal = principal
        return principal

    if bearer is not None and bearer.scheme.lower() == "bearer" and bearer.credentials:
        token = bearer.credentials

        # OIDC JWT path (optional): try when JWKS configured and token looks like JWT.
        if settings.oidc_jwks_url and looks_like_jwt(token):
            jwt_principal = validate_bearer_jwt(token, settings)
            if jwt_principal is None:
                raise ApiError(
                    status_code=401,
                    code="unauthorized",
                    message="Invalid or expired JWT",
                )
            principal = Principal(
                key_id=f"oidc:{jwt_principal.subject}",
                scopes=jwt_principal.scopes,
                label=jwt_principal.label,
                auth_via="oidc_jwt",
            )
            request.state.principal = principal
            return principal

        access = get_token_store().lookup(token)
        if access is None:
            raise ApiError(
                status_code=401,
                code="unauthorized",
                message="Invalid or expired bearer token",
            )
        # Confirm the underlying key is still active (revocation).
        stored = get_keystore().get(access.key_id)
        if stored is None or stored.revoked:
            raise ApiError(
                status_code=401,
                code="unauthorized",
                message="Token revoked",
            )
        principal = Principal(
            key_id=access.key_id,
            scopes=access.scopes,
            label=access.label,
            auth_via="bearer",
        )
        request.state.principal = principal
        return principal

    raise ApiError(
        status_code=401,
        code="unauthorized",
        message=f"Missing {API_KEY_HEADER_NAME} header or Bearer token",
    )


def require_scopes(*needed: str) -> Callable[..., Principal]:
    """Dependency factory: require an authenticated principal with scopes."""

    async def _checker(principal: Principal = Depends(require_api_key)) -> Principal:
        missing = [scope for scope in needed if scope not in principal.scopes]
        if missing:
            raise ApiError(
                status_code=403,
                code="forbidden",
                message=f"Missing required scope(s): {', '.join(missing)}",
            )
        return principal

    return _checker
