"""OAuth2 / OIDC token + authorize endpoints.

Supports:
- ``client_credentials`` (opaque local stub)
- ``authorization_code`` / ``refresh_token`` (IdP proxy when configured, else local stub)
- PKCE S256 on the auth-code flow (required when challenge supplied / when configured)
- ``GET /oauth/authorize`` and ``GET /oauth/callback`` for the auth-code redirect flow
- Portal session helpers: ``/oauth/portal/login|callback|logout|session``
  (HttpOnly cookie so the key portal need not paste an admin key)
"""

from __future__ import annotations

import secrets
from typing import Any, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from api.auth import Principal, require_api_key
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
from api.pkce import code_challenge_s256, generate_code_verifier

router = APIRouter(tags=["oauth"])

PORTAL_CALLBACK_PATH = "/oauth/portal/callback"
PORTAL_DEFAULT_RETURN = "/admin/key-portal"


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
    code_verifier: Optional[str] = Field(
        default=None,
        description="PKCE code_verifier (required when authorize used S256 challenge)",
    )


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
    code_verifier: str | None,
    settings: Settings,
) -> dict[str, Any]:
    if oidc_client_configured(settings):
        body = exchange_code_with_idp(
            settings,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
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
        code_verifier=code_verifier,
        expires_in_s=settings.oauth_token_ttl_s,
        refresh_expires_in_s=settings.oauth_refresh_ttl_s,
    )
    if pair is None:
        raise ApiError(
            status_code=400,
            code="invalid_grant",
            message="Invalid or expired authorization code (or PKCE mismatch)",
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
    code_verifier: str | None,
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
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            settings=settings,
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


def _normalize_pkce(
    *,
    code_challenge: str | None,
    code_challenge_method: str | None,
    required: bool,
) -> tuple[str, str]:
    challenge = (code_challenge or "").strip()
    method = (code_challenge_method or "").strip().upper() or "S256"
    if required and not challenge:
        raise ApiError(
            status_code=400,
            code="invalid_request",
            message="PKCE required: provide code_challenge with method S256",
        )
    if challenge and method != "S256":
        raise ApiError(
            status_code=400,
            code="invalid_request",
            message="Only code_challenge_method=S256 is supported",
        )
    if not challenge:
        return "", ""
    return challenge, "S256"


def _set_portal_cookie(
    response: Response, settings: Settings, access_token: str, *, max_age: int
) -> None:
    response.set_cookie(
        key=settings.portal_cookie_name,
        value=access_token,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
        max_age=max(60, max_age),
    )


def _clear_portal_cookies(response: Response, settings: Settings) -> None:
    response.delete_cookie(settings.portal_cookie_name, path="/")
    response.delete_cookie(settings.portal_pkce_cookie_name, path="/")


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
            code_verifier=payload.code_verifier,
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
            code_verifier=(
                str(form["code_verifier"]) if form.get("code_verifier") else None
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
    code_challenge: Optional[str] = Query(default=None),
    code_challenge_method: Optional[str] = Query(default="S256"),
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

    challenge, method = _normalize_pkce(
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        required=settings.oidc_pkce_required,
    )

    # External IdP path.
    if oidc_authorize_configured(settings):
        target = build_authorize_redirect_url(
            settings,
            state=state,
            scope=scope,
            redirect_uri=redirect_uri or settings.oidc_redirect_uri,
            code_challenge=challenge or None,
            code_challenge_method=method or "S256",
        )
        return RedirectResponse(url=target, status_code=302)

    # Local stub: mint a one-time code for client_id (= API key_id).
    auth = issue_stub_authorization_code(
        client_id,
        redirect_uri=redirect_uri or settings.oidc_redirect_uri,
        requested_scope=scope,
        code_challenge=challenge,
        code_challenge_method=method,
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
                "grant_type=authorization_code"
                + (" with code_verifier (PKCE S256)." if challenge else ".")
                + " Set IdP env vars for real OIDC."
            ),
            "code": auth.code,
            "client_id": client_id,
            "expires_in": 300,
            "state": state,
            "pkce": bool(challenge),
            "code_challenge_method": method or None,
            "hint_env": [
                "ZENITH_OIDC_AUTHORIZE_URL",
                "ZENITH_OIDC_TOKEN_URL",
                "ZENITH_OIDC_CLIENT_ID",
                "ZENITH_OIDC_CLIENT_SECRET",
                "ZENITH_OIDC_REDIRECT_URI",
                "ZENITH_OIDC_JWKS_URL",
                "ZENITH_OIDC_PKCE_REQUIRED",
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
    code_verifier: Optional[str] = Query(default=None),
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

    verifier = (code_verifier or "").strip() or request.cookies.get(
        settings.portal_pkce_cookie_name, ""
    )
    result = _issue_authorization_code(
        code=code,
        redirect_uri=settings.oidc_redirect_uri,
        code_verifier=verifier or None,
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
    "/oauth/portal/login",
    summary="Start portal login (PKCE S256 → IdP or local stub)",
)
async def portal_login(
    request: Request,
    client_id: str = Query(
        default="admin",
        description="Local-stub only: API key_id to mint a code for (ignored with IdP)",
    ),
    scope: Optional[str] = Query(default=None),
    return_to: str = Query(default=PORTAL_DEFAULT_RETURN),
    settings: Settings = Depends(get_settings),
):
    """Bootstrap browser SSO for the key portal.

    Sets a short-lived HttpOnly PKCE verifier cookie, then redirects to
    ``/oauth/authorize`` (IdP or local stub). The portal callback exchanges
    the code and sets ``zenith_portal_token`` so subsequent admin API calls
    need no pasted key.
    """
    if not settings.oauth_enabled:
        raise ApiError(
            status_code=503,
            code="service_unavailable",
            message="OAuth is disabled",
        )

    verifier = generate_code_verifier()
    challenge = code_challenge_s256(verifier)
    state = secrets.token_urlsafe(16)
    # Encode return_to in state lightly: state|return_to (return_to must be path).
    safe_return = return_to if return_to.startswith("/") else PORTAL_DEFAULT_RETURN
    state_payload = f"{state}|{safe_return}"

    # Absolute redirect for real IdPs; relative path for local stub (TestClient-friendly).
    if oidc_authorize_configured(settings):
        portal_redirect = (
            f"{settings.public_base_url.rstrip('/')}{PORTAL_CALLBACK_PATH}"
        )
    else:
        portal_redirect = PORTAL_CALLBACK_PATH
    effective_scope = scope or settings.oidc_scopes or "openid layers:read keys:read"

    if oidc_authorize_configured(settings):
        target = build_authorize_redirect_url(
            settings,
            state=state_payload,
            scope=effective_scope,
            redirect_uri=portal_redirect,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
    else:
        # Local stub authorize with PKCE; redirect_uri = portal callback.
        auth = issue_stub_authorization_code(
            client_id,
            redirect_uri=portal_redirect,
            requested_scope=None,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        if auth is None:
            raise ApiError(
                status_code=400,
                code="invalid_client",
                message=(
                    "Unknown client_id for local portal login "
                    "(use admin or operator key_id)"
                ),
            )
        params = {"code": auth.code, "state": state_payload}
        target = f"{portal_redirect}?{urlencode(params)}"

    response = RedirectResponse(url=target, status_code=302)
    response.set_cookie(
        key=settings.portal_pkce_cookie_name,
        value=verifier,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
        max_age=600,
    )
    return response


@router.get(
    "/oauth/portal/callback",
    summary="Portal OIDC/stub callback → set session cookie",
)
async def portal_callback(
    request: Request,
    code: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    error: Optional[str] = Query(default=None),
    error_description: Optional[str] = Query(default=None),
    settings: Settings = Depends(get_settings),
):
    if error:
        raise ApiError(
            status_code=400,
            code=str(error),
            message=error_description or "Authorization denied",
        )
    if not code:
        raise ApiError(
            status_code=400,
            code="bad_request",
            message="Missing authorization code",
        )

    verifier = (request.cookies.get(settings.portal_pkce_cookie_name) or "").strip()
    if not verifier:
        raise ApiError(
            status_code=400,
            code="invalid_grant",
            message="Missing PKCE verifier cookie — restart /oauth/portal/login",
        )

    if oidc_client_configured(settings) or oidc_authorize_configured(settings):
        portal_redirect = (
            f"{settings.public_base_url.rstrip('/')}{PORTAL_CALLBACK_PATH}"
        )
    else:
        portal_redirect = PORTAL_CALLBACK_PATH
    result = _issue_authorization_code(
        code=code,
        redirect_uri=portal_redirect,
        code_verifier=verifier,
        settings=settings,
    )

    return_to = PORTAL_DEFAULT_RETURN
    if state and "|" in state:
        _, maybe = state.split("|", 1)
        if maybe.startswith("/"):
            return_to = maybe

    response = RedirectResponse(url=return_to, status_code=302)
    _set_portal_cookie(
        response,
        settings,
        result["access_token"],
        max_age=int(result.get("expires_in") or settings.oauth_token_ttl_s),
    )
    response.delete_cookie(settings.portal_pkce_cookie_name, path="/")
    return response


@router.post(
    "/oauth/portal/logout",
    summary="Clear portal session cookie",
)
@router.get(
    "/oauth/portal/logout",
    summary="Clear portal session cookie",
)
async def portal_logout(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> JSONResponse:
    response = JSONResponse(
        {
            "ok": True,
            "message": "Portal session cleared",
            "request_id": get_request_id(request),
        },
        headers={REQUEST_ID_HEADER: get_request_id(request)},
    )
    _clear_portal_cookies(response, settings)
    return response


@router.get(
    "/oauth/portal/session",
    summary="Current portal / API principal (cookie, Bearer, or API key)",
)
async def portal_session(
    request: Request,
    principal: Principal = Depends(require_api_key),
) -> JSONResponse:
    return JSONResponse(
        {
            "authenticated": True,
            "key_id": principal.key_id,
            "scopes": sorted(principal.scopes),
            "label": principal.label,
            "auth_via": principal.auth_via,
            "can_list_keys": bool(
                {"keys:read", "admin:keys"} & set(principal.scopes)
            ),
            "can_manage_keys": "admin:keys" in principal.scopes,
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
            "pkce": {
                "methods": ["S256"],
                "required": settings.oidc_pkce_required,
                "note": (
                    "S256 is always enforced when code_challenge was sent "
                    "at authorize time"
                ),
            },
            "authorize": "/oauth/authorize",
            "token": "/oauth/token",
            "callback": "/oauth/callback",
            "portal_login": "/oauth/portal/login",
            "portal_callback": PORTAL_CALLBACK_PATH,
            "portal_logout": "/oauth/portal/logout",
            "portal_session": "/oauth/portal/session",
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
            "rbac_scopes": {
                "operator_list": "keys:read",
                "admin_manage": "admin:keys",
            },
            "mode": (
                "idp"
                if oidc_client_configured(settings)
                else "local_stub"
            ),
            "request_id": get_request_id(request),
        },
        headers={REQUEST_ID_HEADER: get_request_id(request)},
    )
