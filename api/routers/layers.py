"""Layers catalog, metadata, structured legend, and GetLegendGraphic (M2/S1)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response

from api.auth import Principal
from api.catalog import get_layer, get_legend, list_layer_summaries
from api.errors import ApiError
from api.legend_graphic import fetch_legend_graphic
from api.models import LayerDetail, LayerListResponse, Legend
from api.rate_limit import require_rate_limited
from api.security.allowlist import check_wms_url

router = APIRouter(prefix="/layers", tags=["layers"])


@router.get(
    "",
    response_model=LayerListResponse,
    summary="List catalog layers",
)
def list_layers(
    _principal: Principal = Depends(require_rate_limited("layers:read")),
) -> LayerListResponse:
    items = list_layer_summaries()
    return LayerListResponse(items=items, count=len(items))


@router.get(
    "/{layer_id}",
    response_model=LayerDetail,
    summary="Get layer metadata",
)
def layer_detail(
    layer_id: str,
    _principal: Principal = Depends(require_rate_limited("layers:read")),
) -> LayerDetail:
    layer = get_layer(layer_id)
    if layer is None:
        raise ApiError(
            status_code=404,
            code="not_found",
            message=f"Layer '{layer_id}' was not found",
        )
    # Defense in depth: catalog WMS entries must still be allowlisted.
    if layer.wms is not None:
        check = check_wms_url(str(layer.wms.service_url), layer.wms.layer_name)
        if not check.allowed:
            raise ApiError(
                status_code=403,
                code="forbidden",
                message=f"Layer WMS source rejected by allowlist ({check.reason})",
            )
    return layer


@router.get(
    "/{layer_id}/legend",
    response_model=Legend,
    summary="Get structured legend JSON",
    description=(
        "Returns categorical legend entries plus optional "
        "`get_legend_graphic_url` (upstream OGC) and `legend_image_path` "
        "(Zenith image proxy)."
    ),
)
def layer_legend(
    layer_id: str,
    _principal: Principal = Depends(require_rate_limited("layers:read")),
) -> Legend:
    if get_layer(layer_id) is None:
        raise ApiError(
            status_code=404,
            code="not_found",
            message=f"Layer '{layer_id}' was not found",
        )
    legend = get_legend(layer_id)
    if legend is None:
        raise ApiError(
            status_code=404,
            code="legend_not_available",
            message=f"No structured legend for layer '{layer_id}'",
        )
    return legend


@router.get(
    "/{layer_id}/legend/image",
    summary="Proxy GetLegendGraphic image (allowlisted catalog only)",
    description=(
        "Fetches OGC GetLegendGraphic from the layer's allowlisted WMS source "
        "and returns the image bytes. Does not accept arbitrary URLs (SSRF-safe)."
    ),
    responses={
        200: {
            "content": {"image/png": {}, "image/jpeg": {}, "image/gif": {}},
            "description": "Legend graphic image",
        }
    },
)
def layer_legend_image(
    layer_id: str,
    _principal: Principal = Depends(require_rate_limited("layers:read")),
) -> Response:
    content, media_type = fetch_legend_graphic(layer_id)
    return Response(
        content=content,
        media_type=media_type,
        headers={"Cache-Control": "public, max-age=3600"},
    )
