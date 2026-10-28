"""WFS-style features query (N1) — stub GeoJSON for catalog layers."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from api.auth import Principal
from api.errors import ApiError
from api.features import query_features
from api.models import FeatureCollectionResponse
from api.rate_limit import require_rate_limited

router = APIRouter(tags=["features"])


@router.get(
    "/layers/{layer_id}/features",
    response_model=FeatureCollectionResponse,
    summary="Query stub GeoJSON features for a catalog layer",
    description=(
        "Minimal WFS-style FeatureCollection for integration testing. "
        "Features are **stubs** derived from catalog metadata — not a live "
        "OGC WFS or PostGIS extract. Optional ``bbox=west,south,east,north`` "
        "and ``limit`` filter the stub set."
    ),
)
def layer_features(
    layer_id: str,
    bbox: Optional[str] = Query(
        default=None,
        description="Optional west,south,east,north in EPSG:4326",
    ),
    limit: int = Query(default=50, ge=1, le=500),
    _principal: Principal = Depends(require_rate_limited("layers:read")),
) -> FeatureCollectionResponse:
    try:
        payload = query_features(layer_id, bbox=bbox, limit=limit)
    except KeyError:
        raise ApiError(
            status_code=404,
            code="not_found",
            message=f"Layer '{layer_id}' was not found",
        ) from None
    except ValueError as exc:
        raise ApiError(
            status_code=400,
            code="bad_request",
            message=str(exc),
        ) from exc
    return FeatureCollectionResponse(**payload)
