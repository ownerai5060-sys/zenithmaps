"""Allowlist validation endpoints (M6) — validator only, never a proxy."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from api.auth import Principal
from api.config import Settings, get_settings
from api.models import UrlCheckRequest, UrlCheckResponse
from api.rate_limit import require_rate_limited
from api.security.allowlist import check_wms_url

router = APIRouter(prefix="/security", tags=["security"])


@router.post(
    "/check-url",
    response_model=UrlCheckResponse,
    summary="Check whether a WMS/tile URL is allowlisted",
    description=(
        "Validates a candidate URL against the configured host/layer allowlist. "
        "Does **not** fetch or proxy the URL (SSRF-safe)."
    ),
)
def check_url(
    body: UrlCheckRequest,
    _principal: Principal = Depends(require_rate_limited("layers:read")),
    settings: Settings = Depends(get_settings),
) -> UrlCheckResponse:
    return check_wms_url(body.url, body.layer_name, settings=settings)


@router.get(
    "/allowlist",
    summary="Return configured WMS host/layer allowlist",
)
def get_allowlist(
    _principal: Principal = Depends(require_rate_limited("layers:read")),
    settings: Settings = Depends(get_settings),
) -> dict:
    return {
        "hosts": sorted(settings.wms_allowed_hosts),
        "layers": sorted(settings.wms_allowed_layers),
        "enforce": settings.enforce_wms_allowlist,
    }
