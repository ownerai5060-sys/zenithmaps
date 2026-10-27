"""OAuth2 token endpoint (client_credentials stub).

See ``api.oauth`` module docstring for the design contract.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from api.config import Settings, get_settings
from api.errors import REQUEST_ID_HEADER, ApiError, get_request_id
from api.oauth import issue_client_credentials_token

router = APIRouter(tags=["oauth"])


class TokenJsonRequest(BaseModel):
    grant_type: str = Field(..., description="Must be client_credentials")
    client_id: str
    client_secret: str
    scope: Optional[str] = Field(
        default=None,
        description="Optional space-separated subset of the key's scopes",
    )


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str


def _issue(
    *,
    grant_type: str,
    client_id: str,
    client_secret: str,
    scope: str | None,
    settings: Settings,
) -> TokenResponse:
    if not settings.oauth_enabled:
        raise ApiError(
            status_code=503,
            code="service_unavailable",
            message="OAuth token endpoint is disabled",
        )
    if grant_type != "client_credentials":
        raise ApiError(
            status_code=400,
            code="unsupported_grant_type",
            message="Only grant_type=client_credentials is supported",
        )
    access = issue_client_credentials_token(
        client_id,
        client_secret,
        expires_in_s=settings.oauth_token_ttl_s,
        requested_scope=scope,
    )
    if access is None:
        raise ApiError(
            status_code=401,
            code="invalid_client",
            message="Invalid client credentials or requested scope",
        )
    return TokenResponse(
        access_token=access.token,
        token_type="Bearer",
        expires_in=settings.oauth_token_ttl_s,
        scope=" ".join(sorted(access.scopes)),
    )


@router.post(
    "/oauth/token",
    response_model=TokenResponse,
    summary="OAuth2 client_credentials token (stub)",
    responses={
        400: {"description": "Unsupported grant / bad request"},
        401: {"description": "Invalid client"},
        503: {"description": "OAuth disabled"},
    },
)
async def token_endpoint(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> JSONResponse:
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        payload = TokenJsonRequest.model_validate(await request.json())
        result = _issue(
            grant_type=payload.grant_type,
            client_id=payload.client_id,
            client_secret=payload.client_secret,
            scope=payload.scope,
            settings=settings,
        )
    else:
        form = await request.form()
        grant_type = form.get("grant_type")
        client_id = form.get("client_id")
        client_secret = form.get("client_secret")
        scope = form.get("scope")
        if not grant_type or not client_id or not client_secret:
            raise ApiError(
                status_code=400,
                code="bad_request",
                message="grant_type, client_id, and client_secret are required",
            )
        result = _issue(
            grant_type=str(grant_type),
            client_id=str(client_id),
            client_secret=str(client_secret),
            scope=str(scope) if scope else None,
            settings=settings,
        )
    return JSONResponse(
        result.model_dump(),
        headers={REQUEST_ID_HEADER: get_request_id(request)},
    )
