"""Streamlit ↔ portal SSO bridge helpers (honest limits).

What works
----------
* **Same parent domain** — set ``ZENITH_PORTAL_COOKIE_DOMAIN=.example.com`` and
  serve API + Streamlit under ``*.example.com`` (or one reverse-proxy origin).
  The browser then sends the HttpOnly portal cookie to both hosts. Streamlit
  1.37+ exposes inbound cookies via ``st.context.cookies``; this helper can
  forward them to ``POST /oauth/portal/token-exchange`` for a Bearer token.
* **Same-origin reverse proxy** — mount Streamlit and API under one host so
  cookies are host-only and shared without a Domain attribute.
* **Explicit Bearer / API key** — always supported (fallback for Cloud /
  cross-site Streamlit).

What does **not** work without infra
------------------------------------
* Streamlit Cloud (or any third-party host) **cannot** read Zenith's HttpOnly
  cookie from another registrable domain. There is no secure browser API for
  that. Use an API key, ``client_credentials``, or host Streamlit yourself
  behind the shared domain.
* This is **not** a full IdP-initiated Streamlit login UI — prefer the static
  key portal for interactive SSO, then exchange when the cookie is present.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping

import httpx

DEFAULT_COOKIE_NAME = "zenith_portal_token"
DEFAULT_CSRF_COOKIE = "zenith_portal_csrf"


@dataclass(frozen=True)
class ResolvedAuth:
    """Credentials resolved for ``ZenithApiClient`` / raw httpx calls."""

    api_key: str | None = None
    bearer_token: str | None = None
    cookies: dict[str, str] | None = None
    csrf_token: str | None = None
    source: str = "none"
    notes: tuple[str, ...] = ()


def shared_cookie_domain_docs() -> str:
    """Short operator-facing notes (also mirrored in the ops runbook)."""
    return (
        "Set ZENITH_PORTAL_COOKIE_DOMAIN to a parent domain (leading dot), "
        "e.g. .maps.example.com, and put API + Streamlit on sibling hosts. "
        "Use HTTPS + ZENITH_PORTAL_COOKIE_SECURE=auto|true. Cross-site "
        "Streamlit Cloud cannot share that cookie — use an API key there."
    )


def _streamlit_cookies() -> dict[str, str]:
    """Best-effort read of inbound browser cookies inside Streamlit."""
    try:
        import streamlit as st  # type: ignore[import-not-found]
    except Exception:
        return {}
    try:
        ctx = getattr(st, "context", None)
        raw = getattr(ctx, "cookies", None) if ctx is not None else None
        if raw is None:
            return {}
        if isinstance(raw, Mapping):
            return {str(k): str(v) for k, v in raw.items()}
        # Some Streamlit builds expose a cookie manager with .get / .to_dict
        to_dict = getattr(raw, "to_dict", None)
        if callable(to_dict):
            data = to_dict()
            if isinstance(data, Mapping):
                return {str(k): str(v) for k, v in data.items()}
    except Exception:
        return {}
    return {}


def exchange_portal_session(
    base_url: str,
    *,
    cookies: Mapping[str, str],
    csrf_cookie_name: str = DEFAULT_CSRF_COOKIE,
    timeout_s: float = 10.0,
) -> dict[str, Any]:
    """POST ``/oauth/portal/token-exchange`` forwarding portal cookies."""
    cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items() if v)
    headers = {"Accept": "application/json"}
    csrf = (cookies.get(csrf_cookie_name) or "").strip()
    if csrf:
        headers["X-CSRF-Token"] = csrf
    if cookie_header:
        headers["Cookie"] = cookie_header
    url = f"{base_url.rstrip('/')}/oauth/portal/token-exchange"
    with httpx.Client(timeout=timeout_s) as client:
        response = client.post(url, headers=headers)
    response.raise_for_status()
    return response.json()


def resolve_streamlit_auth(
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    bearer_token: str | None = None,
    cookie_name: str | None = None,
    try_cookie_exchange: bool = True,
) -> ResolvedAuth:
    """Resolve auth for Streamlit pages with clear precedence + notes.

    Order: explicit bearer → explicit API key → env bearer → env API key →
    Streamlit cookie (+ optional token exchange).
    """
    notes: list[str] = []
    base = (base_url or os.getenv("ZENITH_API_BASE_URL") or "http://127.0.0.1:8000").rstrip(
        "/"
    )
    cookie_nm = cookie_name or os.getenv(
        "ZENITH_PORTAL_COOKIE_NAME", DEFAULT_COOKIE_NAME
    )

    bearer = (bearer_token or os.getenv("ZENITH_PORTAL_BEARER") or "").strip() or None
    if bearer:
        return ResolvedAuth(bearer_token=bearer, source="bearer", notes=tuple(notes))

    key = (api_key or os.getenv("ZENITH_API_KEY") or "").strip() or None
    # Treat empty / placeholder as "try cookie next" only when exchange enabled.
    if key and not try_cookie_exchange:
        return ResolvedAuth(api_key=key, source="api_key", notes=tuple(notes))

    cookies = _streamlit_cookies()
    session_val = (cookies.get(cookie_nm) or "").strip()
    if session_val and try_cookie_exchange:
        try:
            exchanged = exchange_portal_session(base, cookies=cookies)
            token = str(exchanged.get("access_token") or "").strip()
            if token:
                notes.append(
                    "Used portal cookie → /oauth/portal/token-exchange Bearer"
                )
                return ResolvedAuth(
                    bearer_token=token,
                    cookies=dict(cookies),
                    csrf_token=(cookies.get(DEFAULT_CSRF_COOKIE) or None),
                    source="portal_exchange",
                    notes=tuple(notes),
                )
        except Exception as exc:  # noqa: BLE001
            notes.append(f"token-exchange failed: {exc}")
            # Fall through: forward cookies directly (same-site API calls).
            notes.append(
                "Forwarding portal cookie to API (CSRF required on mutations)"
            )
            return ResolvedAuth(
                cookies={cookie_nm: session_val, **{
                    k: v
                    for k, v in cookies.items()
                    if k in {DEFAULT_CSRF_COOKIE, cookie_nm}
                }},
                csrf_token=(cookies.get(DEFAULT_CSRF_COOKIE) or None),
                source="portal_cookie",
                notes=tuple(notes),
            )

    if key:
        notes.append(
            "No shared portal cookie visible to Streamlit; using API key. "
            + shared_cookie_domain_docs()
        )
        return ResolvedAuth(api_key=key, source="api_key", notes=tuple(notes))

    notes.append(
        "No bearer, API key, or portal cookie. "
        + shared_cookie_domain_docs()
    )
    return ResolvedAuth(source="none", notes=tuple(notes))
