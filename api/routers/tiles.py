"""Catalog tile URL discovery (N4) — no Zenith-hosted WMTS/CDN."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from api.auth import Principal
from api.errors import ApiError
from api.models import TileLayerInfo, TileListResponse
from api.rate_limit import require_rate_limited
from api.tiles import list_tile_layers, tile_info_for_layer

router = APIRouter(prefix="/tiles", tags=["tiles"])


@router.get(
    "",
    response_model=TileListResponse,
    summary="List allowlisted catalog tile URL templates",
    description=(
        "Exposes XYZ/WMTS-style ``tile_url_template`` values already present "
        "on catalog layers. Zenith does **not** host or proxy tiles; clients "
        "fetch allowlisted upstreams directly. No open CDN endpoints are invented."
    ),
)
def tiles_list(
    _principal: Principal = Depends(require_rate_limited("layers:read")),
) -> TileListResponse:
    return list_tile_layers()


@router.get(
    "/{layer_id}",
    response_model=TileLayerInfo,
    summary="Get tile metadata for one catalog layer",
)
def tiles_detail(
    layer_id: str,
    _principal: Principal = Depends(require_rate_limited("layers:read")),
) -> TileLayerInfo:
    info = tile_info_for_layer(layer_id)
    if info is None:
        raise ApiError(
            status_code=404,
            code="not_found",
            message=f"Layer '{layer_id}' was not found",
        )
    if not info.tile_url_template:
        raise ApiError(
            status_code=404,
            code="tiles_not_available",
            message=f"No tile URL template for layer '{layer_id}'",
        )
    return info
