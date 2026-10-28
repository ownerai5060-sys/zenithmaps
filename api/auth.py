"""API-key authentication with scopes (M3).

Clients send: ``X-API-Key: <secret>``

Demo keys are defined in ``api.config`` and can be overridden via
``ZENITH_API_KEYS``. This is a workable stub for external-app onboarding,
not a production identity provider.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, Request, Security
from fastapi.security import APIKeyHeader

from api.config import ApiKeyRecord, Settings, get_settings
from api.errors import ApiError

API_KEY_HEADER_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)


@dataclass(frozen=True)
class Principal:
    """Authenticated caller derived from a valid API key."""

    key_id: str
    scopes: frozenset[str]
    label: str = ""


def _lookup_key(settings: Settings, secret: str) -> ApiKeyRecord | None:
    for record in settings.api_keys:
        if record.secret == secret:
            return record
    return None


async def require_api_key(
    request: Request,
    api_key: str | None = Security(api_key_header),
    settings: Settings = Depends(get_settings),
) -> Principal:
    if not api_key:
        raise ApiError(
            status_code=401,
            code="unauthorized",
            message=f"Missing {API_KEY_HEADER_NAME} header",
        )
    record = _lookup_key(settings, api_key)
    if record is None:
        raise ApiError(
            status_code=401,
            code="unauthorized",
            message="Invalid API key",
        )
    principal = Principal(
        key_id=record.key_id, scopes=record.scopes, label=record.label
    )
    request.state.principal = principal
    return principal


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
