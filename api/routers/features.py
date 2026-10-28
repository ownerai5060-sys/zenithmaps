"""WFS-lite features query — GeoJSON FeatureCollection for catalog layers."""

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
    summary="WFS-lite GeoJSON features for a catalog layer",
    description=(
        "**WFS-lite**: bbox + limit FeatureCollection (not a full OGC WFS). "
        "Tries optional PostGIS (`ZENITH_DATABASE_URL`) first, then bundled "
        "fixtures under `api/fixtures/`, then deterministic stubs. "
        "Optional ``bbox=west,south,east,north`` and ``limit`` filters apply "
        "to fixture/stub backends (PostGIS applies them in SQL)."
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
