"""OAuth2 / OIDC token + authorize endpoints.

Supports:
- ``client_credentials`` (opaque local stub)
- ``authorization_code`` / ``refresh_token`` (IdP proxy when configured, else local stub)
- PKCE S256 on the auth-code flow (required when challenge supplied / when configured)
- ``GET /oauth/authorize`` and ``GET /oauth/callback`` for the auth-code redirect flow
- Local consent stub: ``GET/POST /oauth/consent`` (auth-code + redirect_uri)
- Portal session helpers: ``/oauth/portal/login|callback|logout|session``
  (HttpOnly cookie = opaque SSO session_id; IdP refresh kept server-side)
"""

from __future__ import annotations

import secrets
from typing import Any, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from api.auth import Principal, require_api_key
from api.config import Settings, get_settings
from api.consent import (
    get_consent_store,
    redirect_with_code,
    redirect_with_error,
    render_consent_html,
)
from api.csrf import new_csrf_token, portal_cookies_secure
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
from api.session_store import get_session_store

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


def _wrap_idp_token_response(
    body: dict[str, Any], settings: Settings
) -> dict[str, Any]:
    """Return client tokens; persist IdP refresh server-side as opaque handle."""
    scope = str(body.get("scope") or settings.oidc_scopes or "")
    scopes = frozenset(s for s in scope.split() if s) or frozenset(
        s for s in settings.oidc_default_scopes.split() if s
    )
    subject = str(
        body.get("sub")
        or body.get("client_id")
        or settings.oidc_client_id
        or "idp"
    )
    key_id = subject if subject.startswith("oidc:") else f"oidc:{subject}"
    result: dict[str, Any] = {
        "access_token": body["access_token"],
        "token_type": body.get("token_type", "Bearer"),
        "expires_in": int(body.get("expires_in") or settings.oauth_token_ttl_s),
        "scope": scope or " ".join(sorted(scopes)),
        "_key_id": key_id,
        "_scopes": scopes,
        "_label": f"OIDC {subject}",
        "_idp_access_token": str(body.get("access_token") or ""),
        "_idp_refresh_token": str(body.get("refresh_token") or ""),
    }
    raw_refresh = body.get("refresh_token")
    if raw_refresh:
        stored = get_session_store().store_idp_refresh(
            idp_refresh_token=str(raw_refresh),
            key_id=key_id,
            scopes=scopes,
            label=result["_label"],
            ttl_s=settings.oauth_refresh_ttl_s,
        )
        result["refresh_token"] = stored.handle
        result["_refresh_persisted"] = True
    return result


def _public_token_view(result: dict[str, Any]) -> dict[str, Any]:
    """Strip internal keys before JSON responses."""
    return {k: v for k, v in result.items() if not k.startswith("_")}


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
        return _wrap_idp_token_response(body, settings)

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
    return {
        **_token_json(
            access_token=pair.access.token,
            expires_in=pair.expires_in_s,
            scope=" ".join(sorted(pair.access.scopes)),
            refresh_token=pair.refresh.token if pair.refresh else None,
        ),
        "_key_id": pair.access.key_id,
        "_scopes": pair.access.scopes,
        "_label": pair.access.label,
        "_idp_access_token": "",
        "_idp_refresh_token": "",
    }


def _issue_refresh_token(
    *,
    refresh_token: str,
    settings: Settings,
) -> dict[str, Any]:
    # Prefer server-side IdP refresh handle (opaque) when present.
    stored = get_session_store().consume_idp_refresh(refresh_token)
    if stored is not None:
        if not oidc_client_configured(settings):
            raise ApiError(
                status_code=400,
                code="invalid_grant",
                message="Stored IdP refresh requires ZENITH_OIDC_TOKEN_URL",
            )
        body = refresh_with_idp(
            settings, refresh_token=stored.idp_refresh_token
        )
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
        # Carry forward subject / scopes if IdP omits them.
        body.setdefault("scope", " ".join(sorted(stored.scopes)))
        if "sub" not in body and stored.key_id.startswith("oidc:"):
            body["sub"] = stored.key_id.split(":", 1)[1]
        # If IdP did not rotate refresh, re-persist the same one under new handle.
        if not body.get("refresh_token"):
            body["refresh_token"] = stored.idp_refresh_token
        return _public_token_view(_wrap_idp_token_response(body, settings))

    if oidc_client_configured(settings):
        # Compat: client still holding a raw IdP refresh (pre-persistence).
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
        return _public_token_view(_wrap_idp_token_response(body, settings))

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
        return _public_token_view(
            _issue_authorization_code(
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                settings=settings,
            )
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
    response: Response, settings: Settings, session_id: str, *, max_age: int
) -> None:
    """Set HttpOnly SSO session cookie + readable CSRF double-submit cookie.

    Cookie notes (staging/prod):
    - Session: HttpOnly, SameSite=Lax, Path=/, Secure when public base is https
      (or ``ZENITH_PORTAL_COOKIE_SECURE=true``). Value is opaque ``session_id``
      resolved via the shared session store (Redis / SQLite / memory).
    - CSRF: NOT HttpOnly so portal JS can mirror it into ``X-CSRF-Token``.
    - IdP refresh tokens stay server-side in the session / refresh store.
    """
    secure = portal_cookies_secure(settings)
    age = max(60, max_age)
    response.set_cookie(
        key=settings.portal_cookie_name,
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
        max_age=age,
    )
    if settings.portal_csrf_enabled:
        response.set_cookie(
            key=settings.portal_csrf_cookie_name,
            value=new_csrf_token(),
            httponly=False,
            samesite="lax",
            secure=secure,
            path="/",
            max_age=age,
        )


def _clear_portal_cookies(
    response: Response, settings: Settings, *, session_id: str | None = None
) -> None:
    if session_id:
        get_session_store().delete_session(session_id)
    response.delete_cookie(settings.portal_cookie_name, path="/")
    response.delete_cookie(settings.portal_pkce_cookie_name, path="/")
    response.delete_cookie(settings.portal_csrf_cookie_name, path="/")


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
    # With redirect_uri + consent enabled → HTML consent stub first.
    if redirect_uri and settings.oauth_consent_enabled:
        pending = get_consent_store().create(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope or "",
            state=state or "",
            code_challenge=challenge,
            code_challenge_method=method,
        )
        return HTMLResponse(
            content=render_consent_html(pending),
            status_code=200,
            headers={REQUEST_ID_HEADER: get_request_id(request)},
        )

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
        return RedirectResponse(
            url=redirect_with_code(
                redirect_uri, code=auth.code, state=state or ""
            ),
            status_code=302,
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
            **_public_token_view(result),
            "state": state,
            "mode": "idp" if oidc_client_configured(settings) else "local_stub",
            "refresh_persisted": bool(result.get("_refresh_persisted")),
            "request_id": get_request_id(request),
        },
        headers={REQUEST_ID_HEADER: get_request_id(request)},
    )


@router.get(
    "/oauth/consent",
    summary="Local-stub consent screen (pending_id)",
    response_class=HTMLResponse,
)
async def consent_get(
    request: Request,
    pending_id: str = Query(...),
    settings: Settings = Depends(get_settings),
):
    if not settings.oauth_enabled:
        raise ApiError(
            status_code=503,
            code="service_unavailable",
            message="OAuth is disabled",
        )
    pending = get_consent_store().get(pending_id)
    if pending is None:
        raise ApiError(
            status_code=400,
            code="invalid_request",
            message="Unknown or expired consent request",
        )
    return HTMLResponse(
        content=render_consent_html(pending),
        headers={REQUEST_ID_HEADER: get_request_id(request)},
    )


@router.post(
    "/oauth/consent",
    summary="Approve or deny local-stub consent",
)
async def consent_post(
    request: Request,
    settings: Settings = Depends(get_settings),
):
    if not settings.oauth_enabled:
        raise ApiError(
            status_code=503,
            code="service_unavailable",
            message="OAuth is disabled",
        )
    # Prefer form body (HTML stub); also accept JSON for tests / clients.
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        payload = await request.json()
        pending_id = str(payload.get("pending_id") or "")
        decision = str(payload.get("decision") or "deny")
    else:
        form = await request.form()
        pending_id = str(form.get("pending_id") or "")
        decision = str(form.get("decision") or "deny")
    if not pending_id:
        raise ApiError(
            status_code=400,
            code="invalid_request",
            message="pending_id is required",
        )
    pending = get_consent_store().consume(pending_id)
    if pending is None:
        raise ApiError(
            status_code=400,
            code="invalid_request",
            message="Unknown or expired consent request",
        )
    if (decision or "").strip().lower() != "approve":
        return RedirectResponse(
            url=redirect_with_error(
                pending.redirect_uri,
                error="access_denied",
                state=pending.state,
            ),
            status_code=302,
        )
    auth = issue_stub_authorization_code(
        pending.client_id,
        redirect_uri=pending.redirect_uri,
        requested_scope=pending.scope or None,
        code_challenge=pending.code_challenge,
        code_challenge_method=pending.code_challenge_method,
    )
    if auth is None:
        return RedirectResponse(
            url=redirect_with_error(
                pending.redirect_uri,
                error="invalid_client",
                state=pending.state,
            ),
            status_code=302,
        )
    return RedirectResponse(
        url=redirect_with_code(
            pending.redirect_uri, code=auth.code, state=pending.state
        ),
        status_code=302,
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
        secure=portal_cookies_secure(settings),
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

    ttl = int(result.get("expires_in") or settings.oauth_token_ttl_s)
    scopes = result.get("_scopes")
    if not isinstance(scopes, frozenset):
        scope_str = str(result.get("scope") or "")
        scopes = frozenset(s for s in scope_str.split() if s)
    session = get_session_store().create_session(
        key_id=str(result.get("_key_id") or "unknown"),
        scopes=scopes,
        label=str(result.get("_label") or ""),
        ttl_s=ttl,
        access_token=str(result.get("access_token") or ""),
        idp_access_token=str(result.get("_idp_access_token") or ""),
        idp_refresh_token=str(result.get("_idp_refresh_token") or ""),
    )

    response = RedirectResponse(url=return_to, status_code=302)
    _set_portal_cookie(
        response,
        settings,
        session.session_id,
        max_age=ttl,
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
    cookie_name = settings.portal_cookie_name or "zenith_portal_token"
    session_id = (request.cookies.get(cookie_name) or "").strip() or None
    response = JSONResponse(
        {
            "ok": True,
            "message": "Portal session cleared",
            "request_id": get_request_id(request),
        },
        headers={REQUEST_ID_HEADER: get_request_id(request)},
    )
    _clear_portal_cookies(response, settings, session_id=session_id)
    return response


@router.get(
    "/oauth/portal/session",
    summary="Current portal / API principal (cookie, Bearer, or API key)",
)
async def portal_session(
    request: Request,
    principal: Principal = Depends(require_api_key),
) -> JSONResponse:
    store = get_session_store()
    session_meta = None
    if principal.session_id:
        rec = store.get_session(principal.session_id)
        if rec is not None:
            session_meta = rec.to_public_dict()
    return JSONResponse(
        {
            "authenticated": True,
            "key_id": principal.key_id,
            "scopes": sorted(principal.scopes),
            "label": principal.label,
            "auth_via": principal.auth_via,
            "session_id": principal.session_id or None,
            "session": session_meta,
            "session_store": store.backend_name,
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
            "consent_path": "/oauth/consent",
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
            "portal_cookies": {
                "session": settings.portal_cookie_name,
                "csrf": settings.portal_csrf_cookie_name,
                "csrf_header": "X-CSRF-Token",
                "csrf_enabled": settings.portal_csrf_enabled,
                "secure": portal_cookies_secure(settings),
                "samesite": "lax",
                "value": "opaque_session_id",
                "notes": (
                    "Session cookie holds opaque SSO session_id (HttpOnly); "
                    "CSRF is double-submit (readable cookie + X-CSRF-Token). "
                    "Secure follows ZENITH_PORTAL_COOKIE_SECURE or https "
                    "public base URL. IdP refresh tokens are server-side only."
                ),
            },
            "session_store": {
                "backend": get_session_store().backend_name,
                "configured_backend": settings.session_store_backend,
                "path_set": bool(settings.session_store_path),
                "redis_url_set": bool(settings.redis_url),
            },
            "consent": {
                "enabled": settings.oauth_consent_enabled,
                "path": "/oauth/consent",
                "applies_to": "local_stub_authorize_with_redirect_uri",
            },
            "idp_refresh_persistence": True,
            "mode": (
                "idp"
                if oidc_client_configured(settings)
                else "local_stub"
            ),
            "request_id": get_request_id(request),
        },
        headers={REQUEST_ID_HEADER: get_request_id(request)},
    )
