"""In-repo layer catalog used by the platform API (M2).

This is a curated, allowlisted catalog — not an open WMS proxy. Upstream
URLs here must also pass the host/layer allowlist in ``api.security.allowlist``.
"""

from __future__ import annotations

import threading
import time
from copy import deepcopy
from typing import Any

from api.models import (
    LayerDetail,
    LayerSummary,
    Legend,
    LegendEntry,
    WmsSource,
)

# Monotonic catalog revision for webhook consumers (N3). Bumped explicitly
# via admin API — in-memory only (resets on process restart).
_catalog_lock = threading.Lock()
_catalog_version: int = 1
_catalog_updated_at: float = time.time()

# ESA WorldCover class colors (same palette leafmap.builtin_legends uses).
_ESA_WORLDCOVER_ENTRIES: list[LegendEntry] = [
    LegendEntry(label="Tree cover", color="#006400"),
    LegendEntry(label="Shrubland", color="#ffbb22"),
    LegendEntry(label="Grassland", color="#ffff4c"),
    LegendEntry(label="Cropland", color="#f096ff"),
    LegendEntry(label="Built-up", color="#fa0000"),
    LegendEntry(label="Bare / sparse vegetation", color="#b4b4b4"),
    LegendEntry(label="Snow and ice", color="#f0f0f0"),
    LegendEntry(label="Permanent water bodies", color="#0064c8"),
    LegendEntry(label="Herbaceous wetland", color="#0096a0"),
    LegendEntry(label="Mangroves", color="#00cf75"),
    LegendEntry(label="Moss and lichen", color="#fae6a0"),
]


_LAYERS: dict[str, dict[str, Any]] = {
    "esa-worldcover-2020": {
        "id": "esa-worldcover-2020",
        "title": "ESA WorldCover 2020",
        "description": (
            "Global land cover map at 10 m resolution for 2020 "
            "(ESA WorldCover via Terrascope WMS)."
        ),
        "kind": "wms",
        "tags": ["landcover", "esa", "wms", "global"],
        "bbox": [-180.0, -90.0, 180.0, 90.0],
        "crs": ["EPSG:4326", "EPSG:3857"],
        "wms": {
            "service_url": "https://services.terrascope.be/wms/v2",
            "layer_name": "WORLDCOVER_2020_MAP",
            "version": "1.3.0",
            "format": "image/png",
            "transparent": True,
            "attribution": "© ESA WorldCover / VITO Terrascope",
        },
        "legend_available": True,
        "extra": {"year": 2020, "resolution_m": 10},
    },
    "esa-worldcover-2021": {
        "id": "esa-worldcover-2021",
        "title": "ESA WorldCover 2021",
        "description": (
            "Global land cover map at 10 m resolution for 2021 "
            "(ESA WorldCover via Terrascope WMS)."
        ),
        "kind": "wms",
        "tags": ["landcover", "esa", "wms", "global"],
        "bbox": [-180.0, -90.0, 180.0, 90.0],
        "crs": ["EPSG:4326", "EPSG:3857"],
        "wms": {
            "service_url": "https://services.terrascope.be/wms/v2",
            "layer_name": "WORLDCOVER_2021_MAP",
            "version": "1.3.0",
            "format": "image/png",
            "transparent": True,
            "attribution": "© ESA WorldCover / VITO Terrascope",
        },
        "legend_available": True,
        "extra": {"year": 2021, "resolution_m": 10},
    },
    "opentopomap": {
        "id": "opentopomap",
        "title": "OpenTopoMap",
        "description": "OpenStreetMap-based topographic basemap (XYZ tiles).",
        "kind": "xyz",
        "tags": ["basemap", "terrain", "xyz"],
        "bbox": [-180.0, -90.0, 180.0, 90.0],
        "crs": ["EPSG:3857"],
        "wms": None,
        "legend_available": False,
        "extra": {
            "tile_url_template": "https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png",
            "attribution": "© OpenStreetMap contributors, SRTM | © OpenTopoMap",
        },
    },
}

_LEGENDS: dict[str, Legend] = {
    "esa-worldcover-2020": Legend(
        layer_id="esa-worldcover-2020",
        title="ESA WorldCover 2020",
        type="categorical",
        entries=list(_ESA_WORLDCOVER_ENTRIES),
        source="leafmap.builtin_legends['ESA_WorldCover']",
        notes="Colors mirror the ESA WorldCover class palette.",
    ),
    "esa-worldcover-2021": Legend(
        layer_id="esa-worldcover-2021",
        title="ESA WorldCover 2021",
        type="categorical",
        entries=list(_ESA_WORLDCOVER_ENTRIES),
        source="leafmap.builtin_legends['ESA_WorldCover']",
        notes="Same class palette as 2020; year differs in the source product.",
    ),
}


def list_layer_summaries() -> list[LayerSummary]:
    items: list[LayerSummary] = []
    for raw in _LAYERS.values():
        items.append(
            LayerSummary(
                id=raw["id"],
                title=raw["title"],
                description=raw["description"],
                kind=raw["kind"],
                tags=list(raw["tags"]),
            )
        )
    return sorted(items, key=lambda item: item.id)


def get_layer(layer_id: str) -> LayerDetail | None:
    raw = _LAYERS.get(layer_id)
    if raw is None:
        return None
    data = deepcopy(raw)
    wms_raw = data.pop("wms", None)
    wms = WmsSource(**wms_raw) if wms_raw else None
    return LayerDetail(wms=wms, **data)


def get_legend(layer_id: str) -> Legend | None:
    if layer_id not in _LAYERS:
        return None
    legend = _LEGENDS.get(layer_id)
    if legend is None:
        return None
    # Enrich with GetLegendGraphic metadata when the layer has a WMS source (S1).
    from api.legend_graphic import legend_graphic_url_for_layer

    graphic = legend_graphic_url_for_layer(layer_id)
    return legend.model_copy(
        update={
            "get_legend_graphic_url": graphic,
            "legend_image_path": (
                f"/api/v1/layers/{layer_id}/legend/image" if graphic else None
            ),
        }
    )


def known_layer_ids() -> frozenset[str]:
    return frozenset(_LAYERS.keys())


def get_catalog_version() -> int:
    with _catalog_lock:
        return _catalog_version


def get_catalog_meta() -> dict[str, Any]:
    with _catalog_lock:
        return {
            "version": _catalog_version,
            "updated_at": _catalog_updated_at,
            "layer_count": len(_LAYERS),
        }


def bump_catalog_version(*, reason: str = "manual") -> dict[str, Any]:
    """Increment catalog version (triggers webhook when caller notifies)."""
    global _catalog_version, _catalog_updated_at
    with _catalog_lock:
        _catalog_version += 1
        _catalog_updated_at = time.time()
        return {
            "version": _catalog_version,
            "updated_at": _catalog_updated_at,
            "reason": reason,
            "layer_count": len(_LAYERS),
        }


def reset_catalog_version(version: int = 1) -> None:
    """Test helper — reset revision counter."""
    global _catalog_version, _catalog_updated_at
    with _catalog_lock:
        _catalog_version = version
        _catalog_updated_at = time.time()
