"""OAuth2 / OIDC token + authorize endpoints.

Supports:
- ``client_credentials`` (opaque local stub)
- ``authorization_code`` / ``refresh_token`` (IdP proxy when configured, else local stub)
- ``GET /oauth/authorize`` and ``GET /oauth/callback`` for the auth-code redirect flow
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from api.config import Settings, get_settings
from api.errors import REQUEST_ID_HEADER, ApiError, get_request_id
from api.oauth import (
    exchange_stub_authorization_code,
    get_token_store,
    issue_client_credentials_token,
    issue_stub_authorization_code,
)
from api.oidc_flow import (
    build_authorize_redirect_url,
    exchange_code_with_idp,
    oidc_authorize_configured,
    oidc_client_configured,
    refresh_with_idp,
)

router = APIRouter(tags=["oauth"])


class TokenJsonRequest(BaseModel):
    grant_type: str = Field(
        ...,
        description="client_credentials | authorization_code | refresh_token",
    )
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    scope: Optional[str] = Field(
        default=None,
        description="Optional space-separated subset of the key's scopes",
    )
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    refresh_token: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str
    refresh_token: Optional[str] = None


def _token_json(
    *,
    access_token: str,
    expires_in: int,
    scope: str,
    refresh_token: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": scope,
    }
    if refresh_token:
        body["refresh_token"] = refresh_token
    return body


def _issue_client_credentials(
    *,
    client_id: str,
    client_secret: str,
    scope: str | None,
    settings: Settings,
) -> dict[str, Any]:
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
    return _token_json(
        access_token=access.token,
        expires_in=settings.oauth_token_ttl_s,
        scope=" ".join(sorted(access.scopes)),
    )


def _issue_authorization_code(
    *,
    code: str,
    redirect_uri: str | None,
    settings: Settings,
) -> dict[str, Any]:
    if oidc_client_configured(settings):
        body = exchange_code_with_idp(
            settings, code=code, redirect_uri=redirect_uri
        )
        if "error" in body or body.get("_http_status"):
            status = int(body.pop("_http_status", 401))
            raise ApiError(
                status_code=status if status < 500 else 502,
                code=str(body.get("error") or "invalid_grant"),
                message=str(
                    body.get("error_description")
                    or body.get("message")
                    or "IdP authorization_code exchange failed"
                ),
            )
        return {
            "access_token": body["access_token"],
            "token_type": body.get("token_type", "Bearer"),
            "expires_in": int(body.get("expires_in") or settings.oauth_token_ttl_s),
            "scope": body.get("scope") or settings.oidc_scopes,
            **(
                {"refresh_token": body["refresh_token"]}
                if body.get("refresh_token")
                else {}
            ),
        }

    pair = exchange_stub_authorization_code(
        code,
        redirect_uri=redirect_uri,
        expires_in_s=settings.oauth_token_ttl_s,
        refresh_expires_in_s=settings.oauth_refresh_ttl_s,
    )
    if pair is None:
        raise ApiError(
            status_code=400,
            code="invalid_grant",
            message="Invalid or expired authorization code",
        )
    return _token_json(
        access_token=pair.access.token,
        expires_in=pair.expires_in_s,
        scope=" ".join(sorted(pair.access.scopes)),
        refresh_token=pair.refresh.token if pair.refresh else None,
    )


def _issue_refresh_token(
    *,
    refresh_token: str,
    settings: Settings,
) -> dict[str, Any]:
    if oidc_client_configured(settings):
        body = refresh_with_idp(settings, refresh_token=refresh_token)
        if "error" in body or body.get("_http_status"):
            status = int(body.pop("_http_status", 401))
            raise ApiError(
                status_code=status if status < 500 else 502,
                code=str(body.get("error") or "invalid_grant"),
                message=str(
                    body.get("error_description")
                    or body.get("message")
                    or "IdP refresh_token exchange failed"
                ),
            )
        return {
            "access_token": body["access_token"],
            "token_type": body.get("token_type", "Bearer"),
            "expires_in": int(body.get("expires_in") or settings.oauth_token_ttl_s),
            "scope": body.get("scope") or settings.oidc_scopes,
            **(
                {"refresh_token": body["refresh_token"]}
                if body.get("refresh_token")
                else {}
            ),
        }

    pair = get_token_store().consume_refresh(
        refresh_token,
        expires_in_s=settings.oauth_token_ttl_s,
        refresh_expires_in_s=settings.oauth_refresh_ttl_s,
    )
    if pair is None:
        raise ApiError(
            status_code=400,
            code="invalid_grant",
            message="Invalid or expired refresh token",
        )
    return _token_json(
        access_token=pair.access.token,
        expires_in=pair.expires_in_s,
        scope=" ".join(sorted(pair.access.scopes)),
        refresh_token=pair.refresh.token if pair.refresh else None,
    )


def _issue(
    *,
    grant_type: str,
    client_id: str | None,
    client_secret: str | None,
    scope: str | None,
    code: str | None,
    redirect_uri: str | None,
    refresh_token: str | None,
    settings: Settings,
) -> dict[str, Any]:
    if not settings.oauth_enabled:
        raise ApiError(
            status_code=503,
            code="service_unavailable",
            message="OAuth token endpoint is disabled",
        )
    gt = (grant_type or "").strip()
    if gt == "client_credentials":
        if not client_id or not client_secret:
            raise ApiError(
                status_code=400,
                code="bad_request",
                message="client_id and client_secret are required",
            )
        return _issue_client_credentials(
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            settings=settings,
        )
    if gt == "authorization_code":
        if not code:
            raise ApiError(
                status_code=400,
                code="bad_request",
                message="code is required for authorization_code",
            )
        return _issue_authorization_code(
            code=code, redirect_uri=redirect_uri, settings=settings
        )
    if gt == "refresh_token":
        if not refresh_token:
            raise ApiError(
                status_code=400,
                code="bad_request",
                message="refresh_token is required for refresh_token grant",
            )
        return _issue_refresh_token(refresh_token=refresh_token, settings=settings)
    raise ApiError(
        status_code=400,
        code="unsupported_grant_type",
        message=(
            "Supported grant_type values: client_credentials, "
            "authorization_code, refresh_token"
        ),
    )


@router.post(
    "/oauth/token",
    response_model=TokenResponse,
    summary="OAuth2 token (client_credentials / auth-code / refresh)",
    responses={
        400: {"description": "Unsupported grant / bad request / invalid_grant"},
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
            code=payload.code,
            redirect_uri=payload.redirect_uri,
            refresh_token=payload.refresh_token,
            settings=settings,
        )
    else:
        form = await request.form()
        result = _issue(
            grant_type=str(form.get("grant_type") or ""),
            client_id=str(form["client_id"]) if form.get("client_id") else None,
            client_secret=(
                str(form["client_secret"]) if form.get("client_secret") else None
            ),
            scope=str(form["scope"]) if form.get("scope") else None,
            code=str(form["code"]) if form.get("code") else None,
            redirect_uri=(
                str(form["redirect_uri"]) if form.get("redirect_uri") else None
            ),
            refresh_token=(
                str(form["refresh_token"]) if form.get("refresh_token") else None
            ),
            settings=settings,
        )
    return JSONResponse(
        result,
        headers={REQUEST_ID_HEADER: get_request_id(request)},
    )


@router.get(
    "/oauth/authorize",
    summary="OIDC / OAuth authorize (IdP redirect or local stub code)",
    responses={
        302: {"description": "Redirect to IdP or redirect_uri with code"},
        200: {"description": "Stub JSON when redirect_uri omitted"},
        400: {"description": "Bad request"},
        503: {"description": "OAuth disabled"},
    },
)
async def authorize_endpoint(
    request: Request,
    response_type: str = Query(default="code"),
    client_id: str = Query(default="demo"),
    redirect_uri: Optional[str] = Query(default=None),
    scope: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    settings: Settings = Depends(get_settings),
):
    if not settings.oauth_enabled:
        raise ApiError(
            status_code=503,
            code="service_unavailable",
            message="OAuth authorize endpoint is disabled",
        )
    if response_type != "code":
        raise ApiError(
            status_code=400,
            code="unsupported_response_type",
            message="Only response_type=code is supported",
        )

    # External IdP path.
    if oidc_authorize_configured(settings):
        target = build_authorize_redirect_url(
            settings,
            state=state,
            scope=scope,
            redirect_uri=redirect_uri or settings.oidc_redirect_uri,
        )
        return RedirectResponse(url=target, status_code=302)

    # Local stub: mint a one-time code for client_id (= API key_id).
    auth = issue_stub_authorization_code(
        client_id,
        redirect_uri=redirect_uri or settings.oidc_redirect_uri,
        requested_scope=scope,
    )
    if auth is None:
        raise ApiError(
            status_code=400,
            code="invalid_client",
            message="Unknown or revoked client_id (use an active API key_id)",
        )

    if redirect_uri:
        params = {"code": auth.code}
        if state:
            params["state"] = state
        sep = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(
            url=f"{redirect_uri}{sep}{urlencode(params)}", status_code=302
        )

    return JSONResponse(
        {
            "mode": "local_stub",
            "message": (
                "No ZENITH_OIDC_AUTHORIZE_URL configured; issued a one-time "
                "stub authorization code. Exchange via POST /oauth/token "
                "grant_type=authorization_code. Set IdP env vars for real OIDC."
            ),
            "code": auth.code,
            "client_id": client_id,
            "expires_in": 300,
            "state": state,
            "hint_env": [
                "ZENITH_OIDC_AUTHORIZE_URL",
                "ZENITH_OIDC_TOKEN_URL",
                "ZENITH_OIDC_CLIENT_ID",
                "ZENITH_OIDC_CLIENT_SECRET",
                "ZENITH_OIDC_REDIRECT_URI",
                "ZENITH_OIDC_JWKS_URL",
            ],
            "request_id": get_request_id(request),
        },
        headers={REQUEST_ID_HEADER: get_request_id(request)},
    )


@router.get(
    "/oauth/callback",
    summary="OIDC auth-code callback (exchange code → tokens)",
)
async def callback_endpoint(
    request: Request,
    code: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    error: Optional[str] = Query(default=None),
    error_description: Optional[str] = Query(default=None),
    settings: Settings = Depends(get_settings),
) -> JSONResponse:
    if error:
        raise ApiError(
            status_code=400,
            code=str(error),
            message=error_description or "Authorization denied by IdP",
        )
    if not code:
        raise ApiError(
            status_code=400,
            code="bad_request",
            message="Missing authorization code",
        )
    if not settings.oauth_enabled:
        raise ApiError(
            status_code=503,
            code="service_unavailable",
            message="OAuth is disabled",
        )

    result = _issue_authorization_code(
        code=code,
        redirect_uri=settings.oidc_redirect_uri,
        settings=settings,
    )
    return JSONResponse(
        {
            **result,
            "state": state,
            "mode": "idp" if oidc_client_configured(settings) else "local_stub",
            "request_id": get_request_id(request),
        },
        headers={REQUEST_ID_HEADER: get_request_id(request)},
    )


@router.get(
    "/oauth/oidc-config",
    summary="Effective OIDC / OAuth client configuration (no secrets)",
)
async def oidc_config_endpoint(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> JSONResponse:
    return JSONResponse(
        {
            "oauth_enabled": settings.oauth_enabled,
            "grants": [
                "client_credentials",
                "authorization_code",
                "refresh_token",
            ],
            "authorize": "/oauth/authorize",
            "token": "/oauth/token",
            "callback": "/oauth/callback",
            "idp_authorize_configured": oidc_authorize_configured(settings),
            "idp_token_configured": oidc_client_configured(settings),
            "jwks_configured": bool(settings.oidc_jwks_url),
            "client_id_set": bool(settings.oidc_client_id),
            "redirect_uri": settings.oidc_redirect_uri,
            "scopes": settings.oidc_scopes,
            "issuer": settings.oidc_issuer or None,
            "audience": settings.oidc_audience or None,
            "jwks_url": settings.oidc_jwks_url or None,
            "authorize_url": settings.oidc_authorize_url or None,
            "token_url": settings.oidc_token_url or None,
            "mode": (
                "idp"
                if oidc_client_configured(settings)
                else "local_stub"
            ),
            "request_id": get_request_id(request),
        },
        headers={REQUEST_ID_HEADER: get_request_id(request)},
    )
