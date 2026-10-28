"""OIDC authorization-code + refresh helpers (external IdP or local stub).

When ``ZENITH_OIDC_AUTHORIZE_URL`` / ``ZENITH_OIDC_TOKEN_URL`` (+ client id)
are set, authorize redirects to the IdP and token grants proxy to the IdP
token endpoint. Otherwise the local stub in ``api.oauth`` is used so demos
and CI work without a live identity provider.

JWT Bearer validation remains in ``api.oidc`` (JWKS). This module only covers
the interactive / confidential-client token flows.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode

import httpx

from api.config import Settings

logger = logging.getLogger("zenith.oidc_flow")


def oidc_client_configured(settings: Settings) -> bool:
    """True when enough env is set to talk to an external IdP token endpoint."""
    return bool(
        (settings.oidc_token_url or "").strip()
        and (settings.oidc_client_id or "").strip()
    )


def oidc_authorize_configured(settings: Settings) -> bool:
    return bool(
        (settings.oidc_authorize_url or "").strip()
        and (settings.oidc_client_id or "").strip()
    )


def build_authorize_redirect_url(
    settings: Settings,
    *,
    state: str | None = None,
    scope: str | None = None,
    redirect_uri: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str = "S256",
    extra: dict[str, str] | None = None,
) -> str:
    """Build the IdP authorize URL (caller performs the HTTP redirect)."""
    base = (settings.oidc_authorize_url or "").rstrip()
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": (redirect_uri or settings.oidc_redirect_uri or "").strip(),
        "scope": (scope or settings.oidc_scopes or "openid").strip(),
    }
    if state:
        params["state"] = state
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = (
            code_challenge_method or "S256"
        ).upper()
    if extra:
        params.update({k: v for k, v in extra.items() if v})
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{urlencode(params)}"


def exchange_code_with_idp(
    settings: Settings,
    *,
    code: str,
    redirect_uri: str | None = None,
    code_verifier: str | None = None,
) -> dict[str, Any]:
    """POST authorization_code grant to the configured IdP token URL."""
    form: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": (redirect_uri or settings.oidc_redirect_uri or "").strip(),
        "client_id": settings.oidc_client_id,
        "client_secret": settings.oidc_client_secret,
    }
    if code_verifier:
        form["code_verifier"] = code_verifier
    return _idp_token_request(settings, form)


def refresh_with_idp(
    settings: Settings,
    *,
    refresh_token: str,
) -> dict[str, Any]:
    """POST refresh_token grant to the configured IdP token URL."""
    return _idp_token_request(
        settings,
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": settings.oidc_client_id,
            "client_secret": settings.oidc_client_secret,
        },
    )


def _idp_token_request(settings: Settings, form: dict[str, str]) -> dict[str, Any]:
    url = (settings.oidc_token_url or "").strip()
    if not url:
        raise RuntimeError("ZENITH_OIDC_TOKEN_URL is not configured")
    # Drop empty optional fields (some IdPs reject blank client_secret).
    payload = {k: v for k, v in form.items() if v is not None and str(v) != ""}
    with httpx.Client(timeout=10.0) as client:
        response = client.post(
            url,
            data=payload,
            headers={"Accept": "application/json"},
        )
    try:
        body = response.json()
    except Exception:  # noqa: BLE001
        body = {"error": "invalid_response", "error_description": response.text[:500]}
    if response.status_code >= 400:
        logger.info(
            "IdP token exchange failed status=%s body=%s",
            response.status_code,
            body,
        )
        err = body if isinstance(body, dict) else {"error": "idp_error"}
        err["_http_status"] = response.status_code
        return err
    if not isinstance(body, dict):
        return {"error": "invalid_response", "_http_status": 502}
    return body
