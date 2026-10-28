"""GetLegendGraphic helpers for official (catalog) WMS layers (S1).

Builds OGC GetLegendGraphic URLs and optionally fetches the image for
allowlisted catalog layers only — never for arbitrary user URLs (SSRF-safe).
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from api.catalog import get_layer
from api.errors import ApiError
from api.security.allowlist import check_wms_url

DEFAULT_LEGEND_FORMAT = "image/png"
DEFAULT_TIMEOUT_S = 10.0


def build_get_legend_graphic_url(
    service_url: str,
    layer_name: str,
    *,
    version: str = "1.3.0",
    image_format: str = DEFAULT_LEGEND_FORMAT,
    width: int | None = None,
    height: int | None = None,
) -> str:
    """Construct a WMS GetLegendGraphic request URL."""
    parsed = urlparse(service_url.strip())
    # Drop any existing query; GetLegendGraphic is a fresh request.
    base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    # Some WMS endpoints are path-only; ensure we hit the same service root.
    if not base.endswith("/") and "?" not in service_url:
        # Keep path as-is (Terrascope uses /wms/v2 without trailing slash).
        pass
    params: dict[str, str] = {
        "SERVICE": "WMS",
        "REQUEST": "GetLegendGraphic",
        "VERSION": version,
        "LAYER": layer_name,
        "FORMAT": image_format,
        "TRANSPARENT": "TRUE",
    }
    if width is not None:
        params["WIDTH"] = str(width)
    if height is not None:
        params["HEIGHT"] = str(height)
    return f"{base}?{urlencode(params)}"


def legend_graphic_url_for_layer(
    layer_id: str,
    *,
    image_format: str = DEFAULT_LEGEND_FORMAT,
) -> Optional[str]:
    """Return GetLegendGraphic URL for a catalog WMS layer, or None."""
    layer = get_layer(layer_id)
    if layer is None or layer.wms is None:
        return None
    check = check_wms_url(str(layer.wms.service_url), layer.wms.layer_name)
    if not check.allowed:
        return None
    return build_get_legend_graphic_url(
        str(layer.wms.service_url),
        layer.wms.layer_name,
        version=layer.wms.version,
        image_format=image_format,
    )


def fetch_legend_graphic(
    layer_id: str,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> tuple[bytes, str]:
    """Fetch GetLegendGraphic bytes for an allowlisted catalog layer.

    Returns ``(content, media_type)``. Raises ``ApiError`` on failure.
    """
    layer = get_layer(layer_id)
    if layer is None:
        raise ApiError(
            status_code=404,
            code="not_found",
            message=f"Layer '{layer_id}' was not found",
        )
    if layer.wms is None:
        raise ApiError(
            status_code=404,
            code="legend_graphic_not_available",
            message=f"Layer '{layer_id}' has no WMS source for GetLegendGraphic",
        )

    check = check_wms_url(str(layer.wms.service_url), layer.wms.layer_name)
    if not check.allowed:
        raise ApiError(
            status_code=403,
            code="forbidden",
            message=f"Layer WMS source rejected by allowlist ({check.reason})",
        )

    url = build_get_legend_graphic_url(
        str(layer.wms.service_url),
        layer.wms.layer_name,
        version=layer.wms.version,
    )
    try:
        with httpx.Client(timeout=timeout_s, follow_redirects=False) as client:
            response = client.get(url)
    except httpx.TimeoutException as exc:
        raise ApiError(
            status_code=502,
            code="bad_gateway",
            message="Upstream WMS GetLegendGraphic timed out",
        ) from exc
    except httpx.HTTPError as exc:
        raise ApiError(
            status_code=502,
            code="bad_gateway",
            message="Upstream WMS GetLegendGraphic request failed",
        ) from exc

    if response.status_code >= 400:
        raise ApiError(
            status_code=502,
            code="bad_gateway",
            message=(
                f"Upstream WMS returned HTTP {response.status_code} "
                "for GetLegendGraphic"
            ),
        )

    media_type = response.headers.get("content-type", DEFAULT_LEGEND_FORMAT)
    # Strip charset / parameters for Response media_type when possible.
    media_type = media_type.split(";")[0].strip() or DEFAULT_LEGEND_FORMAT
    return response.content, media_type
