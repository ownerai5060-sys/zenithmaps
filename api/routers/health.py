"""Health, readiness, and lightweight metrics endpoints (S2)."""

from __future__ import annotations

from fastapi import APIRouter, Query

from api import __version__
from api.config import get_settings
from api.metrics import get_metrics
from api.models import HealthResponse, MetricsResponse, UpstreamStatus
from api.upstream import catalog_upstream_status

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse, summary="Liveness + upstream status")
def healthz(
    check_upstreams: bool | None = Query(
        default=None,
        description=(
            "When true, probe catalog WMS GetCapabilities. "
            "Defaults to ZENITH_HEALTH_CHECK_UPSTREAMS."
        ),
    ),
) -> HealthResponse:
    settings = get_settings()
    do_probe = (
        settings.health_check_upstreams if check_upstreams is None else check_upstreams
    )
    upstreams_raw = catalog_upstream_status(
        settings=settings,
        skip_network=not do_probe,
    )
    upstreams = [UpstreamStatus(**item) for item in upstreams_raw]
    degraded = any(u.status in {"down", "degraded"} for u in upstreams)
    return HealthResponse(
        status="degraded" if degraded else "ok",
        api_version=settings.api_version,
        service=f"zenith-api/{__version__}",
        upstreams=upstreams,
        metrics=get_metrics().snapshot(),
    )


@router.get("/metrics", response_model=MetricsResponse, summary="In-process request metrics")
def metrics() -> MetricsResponse:
    settings = get_settings()
    return MetricsResponse(
        service=f"zenith-api/{__version__}",
        api_version=settings.api_version,
        metrics=get_metrics().snapshot(),
    )
