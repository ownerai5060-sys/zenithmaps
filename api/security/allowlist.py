"""WMS/URL allowlist — no open arbitrary URL proxy / SSRF (M6).

The platform API never fetches arbitrary user-supplied URLs. Callers may only
reference hosts (and optionally layer names) that appear in settings.
"""

from __future__ import annotations

from urllib.parse import urlparse

from api.config import Settings, get_settings
from api.models import UrlCheckResponse

# Schemes that are never acceptable for upstream map services.
_BLOCKED_SCHEMES = frozenset({"file", "ftp", "gopher", "data", "javascript"})


def _normalize_host(hostname: str | None) -> str | None:
    if not hostname:
        return None
    host = hostname.lower().rstrip(".")
    # Strip IPv6 brackets if present.
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def is_host_allowed(host: str, settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    return host.lower() in settings.wms_allowed_hosts


def check_wms_url(
    url: str,
    layer_name: str | None = None,
    settings: Settings | None = None,
) -> UrlCheckResponse:
    """Return whether a candidate WMS/tile URL is allowlisted.

    This endpoint is intentionally a *validator*, not a proxy: it does not
    fetch the URL. Rejects non-http(s), credentials-in-URL, and non-allowlisted
    hosts to reduce SSRF risk if a future proxy is added.
    """
    settings = settings or get_settings()

    if not settings.enforce_wms_allowlist:
        return UrlCheckResponse(allowed=True, host=None, reason="allowlist_disabled")

    try:
        parsed = urlparse(url.strip())
    except Exception:
        return UrlCheckResponse(allowed=False, reason="invalid_url")

    scheme = (parsed.scheme or "").lower()
    if scheme in _BLOCKED_SCHEMES:
        return UrlCheckResponse(allowed=False, reason=f"blocked_scheme:{scheme}")
    if scheme not in {"http", "https"}:
        return UrlCheckResponse(allowed=False, reason="unsupported_scheme")

    if parsed.username or parsed.password:
        return UrlCheckResponse(allowed=False, reason="credentials_in_url")

    host = _normalize_host(parsed.hostname)
    if not host:
        return UrlCheckResponse(allowed=False, reason="missing_host")

    # Block obvious loopback / link-local targets even if somehow listed.
    if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} or host.startswith(
        "169.254."
    ):
        return UrlCheckResponse(allowed=False, host=host, reason="blocked_host")

    if not is_host_allowed(host, settings):
        return UrlCheckResponse(
            allowed=False, host=host, reason="host_not_allowlisted"
        )

    if layer_name and settings.wms_allowed_layers:
        if layer_name not in settings.wms_allowed_layers:
            return UrlCheckResponse(
                allowed=False,
                host=host,
                reason="layer_not_allowlisted",
            )

    return UrlCheckResponse(allowed=True, host=host, reason=None)
