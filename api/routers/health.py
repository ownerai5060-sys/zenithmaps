"""Health, readiness, JSON metrics, and Prometheus scrape (S2 + observability)."""

from __future__ import annotations

from fastapi import APIRouter, Query, Response

from api import __version__
from api.config import get_settings
from api.errors import ApiError
from api.metrics import get_metrics, prometheus_available, render_prometheus
from api.models import HealthResponse, MetricsResponse, UpstreamStatus
from api.rate_limit import get_rate_limiter
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
    snap = get_metrics().snapshot()
    snap["rate_limit_backend"] = get_rate_limiter().name
    return HealthResponse(
        status="degraded" if degraded else "ok",
        api_version=settings.api_version,
        service=f"zenith-api/{__version__}",
        upstreams=upstreams,
        metrics=snap,
    )


@router.get("/metrics", response_model=MetricsResponse, summary="In-process request metrics")
def metrics() -> MetricsResponse:
    settings = get_settings()
    snap = get_metrics().snapshot()
    snap["rate_limit_backend"] = get_rate_limiter().name
    return MetricsResponse(
        service=f"zenith-api/{__version__}",
        api_version=settings.api_version,
        metrics=snap,
    )


@router.get(
    "/metrics/prometheus",
    summary="Prometheus text exposition (env-driven)",
    include_in_schema=True,
)
def metrics_prometheus() -> Response:
    settings = get_settings()
    if not settings.prometheus_enabled:
        raise ApiError(
            status_code=404,
            code="not_found",
            message="Prometheus metrics are disabled (ZENITH_PROMETHEUS_ENABLED=false)",
        )
    if not prometheus_available():
        raise ApiError(
            status_code=503,
            code="service_unavailable",
            message="prometheus_client is not installed",
        )
    body, content_type = render_prometheus()
    return Response(content=body, media_type=content_type)
