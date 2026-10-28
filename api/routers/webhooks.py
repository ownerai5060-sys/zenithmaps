"""Admin webhook registration + catalog version bump (N3)."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, HttpUrl

from api.auth import Principal
from api.catalog import bump_catalog_version, get_catalog_meta
from api.errors import ApiError
from api.models import CatalogBumpResponse, CatalogMeta
from api.rate_limit import require_rate_limited
from api.webhooks import (
    get_webhook_registry,
    notify_catalog_updated,
    ping_one,
)

router = APIRouter(prefix="/admin", tags=["admin"])


class RegisterWebhookRequest(BaseModel):
    url: HttpUrl
    events: list[str] = Field(
        default_factory=lambda: ["catalog.updated", "admin.key_created"]
    )
    label: str = ""
    webhook_id: Optional[str] = None


class WebhookPublic(BaseModel):
    id: str
    url: str
    events: list[str]
    label: str
    created_at: float
    last_ping_at: Optional[float] = None
    last_status: Optional[str] = None
    last_error: Optional[str] = None
    active: bool = True


class WebhookListResponse(BaseModel):
    items: list[WebhookPublic]
    count: int


class WebhookPingResponse(BaseModel):
    delivery: dict[str, Any]


class CatalogBumpRequest(BaseModel):
    reason: str = "manual"


def _public(sub) -> WebhookPublic:
    return WebhookPublic(
        id=sub.id,
        url=sub.url,
        events=sorted(sub.events),
        label=sub.label,
        created_at=sub.created_at,
        last_ping_at=sub.last_ping_at,
        last_status=sub.last_status,
        last_error=sub.last_error,
        active=sub.active,
    )


@router.get(
    "/webhooks",
    response_model=WebhookListResponse,
    summary="List registered catalog webhooks",
)
def list_webhooks(
    include_inactive: bool = False,
    _principal: Principal = Depends(require_rate_limited("admin:keys")),
) -> WebhookListResponse:
    items = [
        _public(w)
        for w in get_webhook_registry().list(include_inactive=include_inactive)
    ]
    return WebhookListResponse(items=items, count=len(items))


@router.post(
    "/webhooks",
    response_model=WebhookPublic,
    status_code=201,
    summary="Register a catalog-change webhook URL",
)
def register_webhook(
    body: RegisterWebhookRequest,
    _principal: Principal = Depends(require_rate_limited("admin:keys")),
) -> WebhookPublic:
    try:
        sub = get_webhook_registry().register(
            str(body.url),
            events=body.events,
            label=body.label,
            webhook_id=body.webhook_id,
        )
    except ValueError as exc:
        raise ApiError(status_code=400, code="bad_request", message=str(exc)) from exc
    except KeyError as exc:
        raise ApiError(status_code=409, code="conflict", message=str(exc)) from exc
    return _public(sub)


@router.delete(
    "/webhooks/{webhook_id}",
    response_model=WebhookPublic,
    summary="Deactivate a webhook subscription",
)
def delete_webhook(
    webhook_id: str,
    _principal: Principal = Depends(require_rate_limited("admin:keys")),
) -> WebhookPublic:
    sub = get_webhook_registry().delete(webhook_id)
    if sub is None:
        raise ApiError(
            status_code=404,
            code="not_found",
            message=f"Webhook '{webhook_id}' was not found",
        )
    return _public(sub)


@router.post(
    "/webhooks/{webhook_id}/ping",
    response_model=WebhookPingResponse,
    summary="Send a test ping to one webhook",
)
def ping_webhook(
    webhook_id: str,
    principal: Principal = Depends(require_rate_limited("admin:keys")),
) -> WebhookPingResponse:
    try:
        delivery = ping_one(webhook_id, actor=principal.key_id)
    except KeyError:
        raise ApiError(
            status_code=404,
            code="not_found",
            message=f"Webhook '{webhook_id}' was not found",
        ) from None
    return WebhookPingResponse(
        delivery={
            "event": delivery.event,
            "attempted": delivery.attempted,
            "succeeded": delivery.succeeded,
            "failures": delivery.failures,
            "payload": delivery.payload,
        }
    )


@router.get(
    "/catalog",
    response_model=CatalogMeta,
    summary="Catalog version metadata",
)
def catalog_meta(
    _principal: Principal = Depends(require_rate_limited("admin:keys")),
) -> CatalogMeta:
    return CatalogMeta(**get_catalog_meta())


@router.post(
    "/catalog/bump",
    response_model=CatalogBumpResponse,
    summary="Bump catalog version and ping webhooks",
)
def catalog_bump(
    body: CatalogBumpRequest,
    principal: Principal = Depends(require_rate_limited("admin:keys")),
) -> CatalogBumpResponse:
    meta = bump_catalog_version(reason=body.reason)
    delivery = notify_catalog_updated(reason=body.reason, actor=principal.key_id)
    return CatalogBumpResponse(
        version=meta["version"],
        updated_at=meta["updated_at"],
        layer_count=meta["layer_count"],
        reason=meta["reason"],
        webhook={
            "attempted": delivery.attempted,
            "succeeded": delivery.succeeded,
            "failures": delivery.failures,
        },
    )
