"""Webhook egress URL validation / soft SSRF hardening.

Registration and delivery both call :func:`validate_webhook_egress_url`.
Rules (always applied):

* scheme http/https only
* no credentials in URL
* block loopback, link-local, private IPv4/IPv6 literals, cloud metadata hosts
* non-local http rejected when ``webhooks_require_https`` is true

When ``ZENITH_WEBHOOK_ALLOWED_HOSTS`` is non-empty, the hostname must match
that allowlist (production egress policy). Empty allowlist keeps soft
hardening only — suitable for local/staging demos.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from api.config import Settings, get_settings

_METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
        "instance-data",
    }
)

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


def _is_blocked_ip(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def validate_webhook_egress_url(
    url: str, settings: Settings | None = None
) -> str:
    """Return cleaned URL or raise ``ValueError`` with a stable reason."""
    settings = settings or get_settings()
    raw = (url or "").strip()
    if not raw:
        raise ValueError("url is required")
    try:
        parsed = urlparse(raw)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("invalid_url") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise ValueError("webhook URL must be http or https")
    if parsed.username or parsed.password:
        raise ValueError("credentials_in_url")

    host = (parsed.hostname or "").lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise ValueError("webhook URL missing host")

    if host in _METADATA_HOSTS or host.endswith(".metadata.google.internal"):
        raise ValueError("webhook host is blocked")
    if host.startswith("169.254.") or _is_blocked_ip(host):
        raise ValueError("webhook host is blocked")

    is_local = host in _LOCAL_HOSTS
    if scheme == "http" and not is_local:
        if getattr(settings, "webhooks_require_https", True):
            raise ValueError("non-local webhook URLs must use https")

    # Production egress allowlist (optional). Localhost always allowed for tests.
    allowed = getattr(settings, "webhook_allowed_hosts", frozenset()) or frozenset()
    if allowed and not is_local and host not in allowed:
        raise ValueError("webhook host not in egress allowlist")

    return raw
