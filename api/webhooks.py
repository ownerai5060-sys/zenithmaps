"""Catalog-change webhooks with durable delivery log + HMAC stub (N3+).

Operators register callback URLs. The API fires a best-effort HTTP POST when:

* an admin API key is created, or
* the catalog version is bumped via the admin endpoint.

Deliveries are fire-and-forget for the triggering request, but each attempt is
recorded in the delivery log (SQLite when ``ZENITH_WEBHOOK_LOG_PATH`` is set).
When ``ZENITH_WEBHOOK_SIGNING_SECRET`` is set, requests include::

    X-Zenith-Signature: sha256=<hex hmac of raw JSON body>

Failed pings never fail the triggering request. Soft SSRF guard: only ``https``
(and ``http`` for localhost in tests).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from api.config import get_settings
from api.webhook_log import get_delivery_log

logger = logging.getLogger("zenith.webhooks")

SIGNATURE_HEADER = "X-Zenith-Signature"


@dataclass
class WebhookSubscription:
    id: str
    url: str
    events: frozenset[str]
    label: str = ""
    created_at: float = 0.0
    last_ping_at: float | None = None
    last_status: str | None = None
    last_error: str | None = None
    active: bool = True


@dataclass
class WebhookDelivery:
    event: str
    payload: dict[str, Any]
    attempted: int = 0
    succeeded: int = 0
    failures: list[str] = field(default_factory=list)


_ALLOWED_EVENTS = frozenset({"catalog.updated", "admin.key_created", "webhook.ping"})


class WebhookRegistry:
    """Thread-safe in-memory webhook subscription store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, WebhookSubscription] = {}

    def reset(self) -> None:
        with self._lock:
            self._items.clear()

    def list(self, *, include_inactive: bool = False) -> list[WebhookSubscription]:
        with self._lock:
            items = list(self._items.values())
        if not include_inactive:
            items = [w for w in items if w.active]
        return sorted(items, key=lambda w: w.created_at)

    def get(self, webhook_id: str) -> WebhookSubscription | None:
        with self._lock:
            return self._items.get(webhook_id)

    def register(
        self,
        url: str,
        *,
        events: list[str] | None = None,
        label: str = "",
        webhook_id: str | None = None,
    ) -> WebhookSubscription:
        cleaned = _validate_webhook_url(url)
        event_set = frozenset(events or ["catalog.updated", "admin.key_created"])
        unknown = event_set - _ALLOWED_EVENTS
        if unknown:
            raise ValueError(f"Unsupported events: {sorted(unknown)}")
        wid = webhook_id or f"wh_{secrets.token_hex(6)}"
        with self._lock:
            if wid in self._items and self._items[wid].active:
                raise KeyError(f"Webhook id '{wid}' already exists")
            sub = WebhookSubscription(
                id=wid,
                url=cleaned,
                events=event_set,
                label=label,
                created_at=time.time(),
            )
            self._items[wid] = sub
            return sub

    def delete(self, webhook_id: str) -> WebhookSubscription | None:
        with self._lock:
            sub = self._items.get(webhook_id)
            if sub is None:
                return None
            sub.active = False
            return sub

    def record_ping(
        self,
        webhook_id: str,
        *,
        status: str,
        error: str | None = None,
    ) -> None:
        with self._lock:
            sub = self._items.get(webhook_id)
            if sub is None:
                return
            sub.last_ping_at = time.time()
            sub.last_status = status
            sub.last_error = error


_registry = WebhookRegistry()


def get_webhook_registry() -> WebhookRegistry:
    return _registry


def _validate_webhook_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        raise ValueError("url is required")
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if scheme not in {"http", "https"}:
        raise ValueError("webhook URL must be http or https")
    if not host:
        raise ValueError("webhook URL missing host")
    if host.startswith("169.254.") or host in {"metadata.google.internal"}:
        raise ValueError("webhook host is blocked")
    if scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
        settings = get_settings()
        if getattr(settings, "webhooks_require_https", True):
            raise ValueError("non-local webhook URLs must use https")
    return raw


def build_event_payload(event: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    from api.catalog import get_catalog_version

    return {
        "event": event,
        "api_version": "v1",
        "catalog_version": get_catalog_version(),
        "occurred_at": time.time(),
        "data": data or {},
    }


def sign_payload(body: bytes, secret: str) -> str:
    """Return ``sha256=<hex>`` HMAC over the raw JSON body (stub signature header)."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _delivery_headers(event: str, body: bytes) -> dict[str, str]:
    settings = get_settings()
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "zenith-api-webhook/0.5",
        "X-Zenith-Event": event,
    }
    secret = (settings.webhook_signing_secret or "").strip()
    if secret:
        headers[SIGNATURE_HEADER] = sign_payload(body, secret)
    return headers


def _post_one(
    sub: WebhookSubscription,
    event: str,
    payload: dict[str, Any],
    *,
    http: httpx.Client,
) -> tuple[bool, str | None, int | None, str | None]:
    """Returns (ok, error, http_status, signature_header)."""
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    headers = _delivery_headers(event, body)
    signature = headers.get(SIGNATURE_HEADER)
    try:
        response = http.post(sub.url, content=body, headers=headers)
        if response.status_code >= 400:
            msg = f"HTTP {response.status_code}"
            get_webhook_registry().record_ping(sub.id, status="error", error=msg)
            get_delivery_log().append(
                webhook_id=sub.id,
                event=event,
                url=sub.url,
                status="error",
                http_status=response.status_code,
                error=msg,
                signature_header=signature,
            )
            return False, msg, response.status_code, signature
        get_webhook_registry().record_ping(sub.id, status="ok", error=None)
        get_delivery_log().append(
            webhook_id=sub.id,
            event=event,
            url=sub.url,
            status="ok",
            http_status=response.status_code,
            error=None,
            signature_header=signature,
        )
        return True, None, response.status_code, signature
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.warning("webhook delivery failed id=%s: %s", sub.id, exc)
        get_webhook_registry().record_ping(sub.id, status="error", error=str(exc))
        get_delivery_log().append(
            webhook_id=sub.id,
            event=event,
            url=sub.url,
            status="error",
            http_status=None,
            error=str(exc),
            signature_header=signature,
        )
        return False, str(exc), None, signature


def deliver_webhooks(
    event: str,
    data: dict[str, Any] | None = None,
    *,
    timeout_s: float = 3.0,
    client: httpx.Client | None = None,
) -> WebhookDelivery:
    """POST JSON payload to all active subscriptions listening for ``event``."""
    payload = build_event_payload(event, data)
    delivery = WebhookDelivery(event=event, payload=payload)
    registry = get_webhook_registry()
    targets = [w for w in registry.list() if event in w.events]
    owns_client = client is None
    http = client or httpx.Client(timeout=timeout_s)
    try:
        for sub in targets:
            delivery.attempted += 1
            ok, err, _status, _sig = _post_one(sub, event, payload, http=http)
            if ok:
                delivery.succeeded += 1
            elif err:
                delivery.failures.append(f"{sub.id}: {err}")
    finally:
        if owns_client:
            http.close()
    return delivery


def notify_catalog_updated(*, reason: str, actor: str | None = None) -> WebhookDelivery:
    return deliver_webhooks(
        "catalog.updated",
        {"reason": reason, "actor": actor},
    )


def notify_key_created(*, key_id: str, actor: str | None = None) -> WebhookDelivery:
    return deliver_webhooks(
        "admin.key_created",
        {"key_id": key_id, "actor": actor},
    )


def ping_one(
    webhook_id: str,
    *,
    actor: str | None = None,
    timeout_s: float = 3.0,
    client: httpx.Client | None = None,
) -> WebhookDelivery:
    """Force a test delivery to a single subscription (ignores its event filter)."""
    registry = get_webhook_registry()
    sub = registry.get(webhook_id)
    if sub is None or not sub.active:
        raise KeyError(webhook_id)
    payload = build_event_payload(
        "webhook.ping",
        {"webhook_id": webhook_id, "actor": actor},
    )
    delivery = WebhookDelivery(event="webhook.ping", payload=payload)
    owns_client = client is None
    http = client or httpx.Client(timeout=timeout_s)
    delivery.attempted = 1
    try:
        ok, err, _status, _sig = _post_one(sub, "webhook.ping", payload, http=http)
        if ok:
            delivery.succeeded = 1
        elif err:
            delivery.failures.append(f"{sub.id}: {err}")
    finally:
        if owns_client:
            http.close()
    return delivery
