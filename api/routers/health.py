"""Health and readiness endpoints (unauthenticated)."""

from __future__ import annotations

from fastapi import APIRouter

from api import __version__
from api.config import get_settings
from api.models import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse, summary="Liveness probe")
def healthz() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        api_version=settings.api_version,
        service=f"zenith-api/{__version__}",
    )
