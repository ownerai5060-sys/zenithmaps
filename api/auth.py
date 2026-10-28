"""API-key and Bearer-token authentication with scopes.

Clients may authenticate with:

* ``X-API-Key: <secret>`` — primary path for third-party apps
* ``Authorization: Bearer <opaque_token>`` — from ``POST /oauth/token`` stub
* ``Authorization: Bearer <JWT>`` — when ``ZENITH_OIDC_JWKS_URL`` is set
  (validated against the IdP JWKS; see ``api.oidc``)
* Portal HttpOnly cookie holding an opaque SSO ``session_id`` (session store)

Demo keys live in ``api.config`` / the runtime ``KeyStore``. Opaque OAuth is a
local stub; prefer an external OIDC IdP for production SLA.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from api.config import Settings, get_settings
from api.csrf import require_portal_csrf_if_needed
from api.errors import ApiError
from api.keystore import get_keystore
from api.oauth import get_token_store
from api.oidc import looks_like_jwt, validate_bearer_jwt
from api.session_store import get_session_store

API_KEY_HEADER_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    """Authenticated caller derived from a valid API key, opaque token, or JWT."""

    key_id: str
    scopes: frozenset[str]
    label: str = ""
    auth_via: str = "api_key"  # "api_key" | "bearer" | "oidc_jwt" | "portal_cookie"
    session_id: str = ""


def _principal_from_bearer_token(
    token: str, settings: Settings, *, auth_via: str
) -> Principal | None:
    """Resolve opaque / JWT bearer into a Principal, or None if invalid."""
    if settings.oidc_jwks_url and looks_like_jwt(token):
        jwt_principal = validate_bearer_jwt(token, settings)
        if jwt_principal is None:
            return None
        return Principal(
            key_id=f"oidc:{jwt_principal.subject}",
            scopes=jwt_principal.scopes,
            label=jwt_principal.label,
            auth_via="oidc_jwt" if auth_via == "bearer" else auth_via,
        )

    access = get_token_store().lookup(token)
    if access is None:
        return None
    stored = get_keystore().get(access.key_id)
    if stored is None or stored.revoked:
        return None
    return Principal(
        key_id=access.key_id,
        scopes=access.scopes,
        label=access.label,
        auth_via=auth_via,
    )


def _principal_from_portal_cookie(
    cookie_value: str, settings: Settings
) -> Principal | None:
    """Resolve portal cookie: prefer SSO session_id, fall back to legacy bearer."""
    session = get_session_store().get_session(cookie_value)
    if session is not None:
        # Prefer vault state when key_id is a local API key; keep OIDC subjects.
        if not session.key_id.startswith("oidc:"):
            stored = get_keystore().get(session.key_id)
            if stored is None or stored.revoked:
                get_session_store().delete_session(session.session_id)
                return None
            scopes = frozenset(session.scopes & stored.scopes) or stored.scopes
            label = stored.label
        else:
            scopes = session.scopes
            label = session.label
        return Principal(
            key_id=session.key_id,
            scopes=scopes,
            label=label,
            auth_via="portal_cookie",
            session_id=session.session_id,
        )

    # Legacy: cookie used to hold the opaque / IdP access token directly.
    return _principal_from_bearer_token(
        cookie_value, settings, auth_via="portal_cookie"
    )


async def require_api_key(
    request: Request,
    api_key: str | None = Security(api_key_header),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> Principal:
    # Prefer explicit API key header; then Authorization Bearer; then portal cookie.
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
        principal = _principal_from_bearer_token(
            bearer.credentials, settings, auth_via="bearer"
        )
        if principal is None:
            raise ApiError(
                status_code=401,
                code="unauthorized",
                message="Invalid or expired bearer token",
            )
        request.state.principal = principal
        return principal

    cookie_name = settings.portal_cookie_name or "zenith_portal_token"
    cookie_token = (request.cookies.get(cookie_name) or "").strip()
    if cookie_token:
        principal = _principal_from_portal_cookie(cookie_token, settings)
        if principal is None:
            raise ApiError(
                status_code=401,
                code="unauthorized",
                message="Invalid or expired portal session cookie",
            )
        request.state.principal = principal
        # Double-submit CSRF for cookie-authenticated mutations only.
        require_portal_csrf_if_needed(request, settings)
        return principal

    raise ApiError(
        status_code=401,
        code="unauthorized",
        message=(
            f"Missing {API_KEY_HEADER_NAME} header, Bearer token, "
            "or portal session cookie"
        ),
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


def require_any_scope(*accepted: str) -> Callable[..., Principal]:
    """Dependency factory: principal must hold at least one of ``accepted``."""

    async def _checker(principal: Principal = Depends(require_api_key)) -> Principal:
        if not any(scope in principal.scopes for scope in accepted):
            raise ApiError(
                status_code=403,
                code="forbidden",
                message=(
                    "Missing required scope (need one of: "
                    + ", ".join(accepted)
                    + ")"
                ),
            )
        return principal

    return _checker
