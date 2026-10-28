"""Optional OIDC / JWT Bearer validation via JWKS (production IdP path).

When ``ZENITH_OIDC_JWKS_URL`` is set, Bearer credentials that look like JWTs
(three base64url segments) are validated against the remote JWKS. Opaque
OAuth stub tokens continue to work alongside this path.

Configure an external IdP to issue access tokens whose ``aud`` / ``iss`` match
``ZENITH_OIDC_AUDIENCE`` / ``ZENITH_OIDC_ISSUER`` (when set). Scopes are read
from the ``scope`` (space-delimited) or ``scp`` claim; if absent, the default
``ZENITH_OIDC_DEFAULT_SCOPES`` (default ``layers:read``) is applied.

This module caches JWKS in-process for Bearer JWT validation. Authorization-code
and refresh flows live in ``api.oidc_flow`` + ``/oauth/authorize`` /
``/oauth/token`` / ``/oauth/callback`` (IdP proxy when env is set, else local stub).
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx

from api.config import Settings, get_settings

logger = logging.getLogger("zenith.oidc")


@dataclass(frozen=True)
class JwtPrincipal:
    subject: str
    scopes: frozenset[str]
    claims: dict[str, Any]
    label: str = ""


class JwksCache:
    """Fetch and cache a JWKS document."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._keys: dict[str, Any] = {}
        self._fetched_at: float = 0.0
        self._url: str = ""
        self._ttl_s: float = 300.0

    def reset(self) -> None:
        with self._lock:
            self._keys = {}
            self._fetched_at = 0.0
            self._url = ""

    def get_key(self, kid: str | None, *, jwks_url: str, ttl_s: float = 300.0) -> Any:
        with self._lock:
            stale = (
                not self._keys
                or self._url != jwks_url
                or (time.time() - self._fetched_at) > ttl_s
            )
        if stale:
            self._refresh(jwks_url)
        with self._lock:
            if kid and kid in self._keys:
                return self._keys[kid]
            # Fall back to first key when kid missing (some IdPs omit kid).
            if self._keys:
                return next(iter(self._keys.values()))
        return None

    def _refresh(self, jwks_url: str) -> None:
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(jwks_url)
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:  # noqa: BLE001
            logger.warning("JWKS fetch failed url=%s: %s", jwks_url, exc)
            return
        keys = payload.get("keys") or []
        mapped: dict[str, Any] = {}
        for jwk in keys:
            kid = jwk.get("kid") or f"idx-{len(mapped)}"
            mapped[kid] = jwk
        with self._lock:
            self._keys = mapped
            self._url = jwks_url
            self._fetched_at = time.time()


_JWKS = JwksCache()


def get_jwks_cache() -> JwksCache:
    return _JWKS


def looks_like_jwt(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


def _scopes_from_claims(claims: dict[str, Any], default: frozenset[str]) -> frozenset[str]:
    raw = claims.get("scope")
    if isinstance(raw, str) and raw.strip():
        return frozenset(s for s in raw.split() if s)
    scp = claims.get("scp")
    if isinstance(scp, list):
        return frozenset(str(s) for s in scp if s)
    if isinstance(scp, str) and scp.strip():
        return frozenset(s for s in scp.split() if s)
    return default


def validate_bearer_jwt(
    token: str,
    settings: Settings | None = None,
) -> JwtPrincipal | None:
    """Validate a JWT against configured JWKS. Returns None if OIDC disabled."""
    cfg = settings or get_settings()
    jwks_url = (cfg.oidc_jwks_url or "").strip()
    if not jwks_url:
        return None
    if not looks_like_jwt(token):
        return None

    try:
        import jwt
        from jwt import PyJWK
    except ImportError:
        logger.warning(
            "ZENITH_OIDC_JWKS_URL set but PyJWT is not installed; JWT auth skipped"
        )
        return None

    try:
        header = jwt.get_unverified_header(token)
    except Exception:  # noqa: BLE001
        return None

    jwk = _JWKS.get_key(header.get("kid"), jwks_url=jwks_url)
    if jwk is None:
        return None

    try:
        key = PyJWK.from_dict(jwk).key
        options = {"require": ["exp"]}
        decode_kwargs: dict[str, Any] = {
            "algorithms": [header.get("alg") or "RS256"],
            "options": options,
        }
        if cfg.oidc_audience:
            decode_kwargs["audience"] = cfg.oidc_audience
        else:
            decode_kwargs["options"] = {**options, "verify_aud": False}
        if cfg.oidc_issuer:
            decode_kwargs["issuer"] = cfg.oidc_issuer
        claims = jwt.decode(token, key=key, **decode_kwargs)
    except Exception as exc:  # noqa: BLE001
        logger.info("JWT validation failed: %s", exc)
        return None

    subject = str(claims.get("sub") or claims.get("client_id") or "oidc")
    defaults = frozenset(
        s for s in (cfg.oidc_default_scopes or "layers:read").split() if s
    )
    scopes = _scopes_from_claims(claims, defaults)
    label = str(claims.get("name") or claims.get("preferred_username") or "")
    return JwtPrincipal(subject=subject, scopes=scopes, claims=claims, label=label)
