"""Portal CSRF double-submit helpers.

Browser portal SSO uses an HttpOnly session cookie. Mutating requests that
authenticate *only* via that cookie must also send ``X-CSRF-Token`` matching
the non-HttpOnly CSRF cookie (double-submit). Explicit ``X-API-Key`` / Bearer
auth does not require CSRF.
"""

from __future__ import annotations

import secrets
from typing import Final

from fastapi import Request

from api.config import Settings
from api.errors import ApiError

CSRF_HEADER_NAME: Final[str] = "X-CSRF-Token"
_UNSAFE_METHODS: Final[frozenset[str]] = frozenset(
    {"POST", "PUT", "PATCH", "DELETE"}
)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def portal_cookies_secure(settings: Settings) -> bool:
    """Whether Secure should be set on portal cookies.

    ``auto`` (default): Secure when ``ZENITH_PUBLIC_BASE_URL`` is https.
    Explicit true/false overrides for local https reverse-proxies / plain HTTP.
    """
    mode = (settings.portal_cookie_secure or "auto").strip().lower()
    if mode in {"1", "true", "yes", "on"}:
        return True
    if mode in {"0", "false", "no", "off"}:
        return False
    return settings.public_base_url.lower().startswith("https://")


def require_portal_csrf_if_needed(request: Request, settings: Settings) -> None:
    """Raise 403 when portal-cookie auth lacks a matching CSRF double-submit."""
    if not settings.portal_csrf_enabled:
        return
    if request.method.upper() not in _UNSAFE_METHODS:
        return
    principal = getattr(request.state, "principal", None)
    if principal is None or getattr(principal, "auth_via", "") != "portal_cookie":
        return

    cookie_name = settings.portal_csrf_cookie_name or "zenith_portal_csrf"
    cookie_token = (request.cookies.get(cookie_name) or "").strip()
    header_token = (request.headers.get(CSRF_HEADER_NAME) or "").strip()
    if not cookie_token or not header_token or not secrets.compare_digest(
        cookie_token, header_token
    ):
        raise ApiError(
            status_code=403,
            code="csrf_failed",
            message=(
                f"Portal cookie mutations require matching {CSRF_HEADER_NAME} "
                f"and {cookie_name} cookie (double-submit CSRF)"
            ),
        )
