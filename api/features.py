"""Stub WFS-style GeoJSON features for catalog layers (N1).

There is no live vector store or OGC WFS upstream in this repo. This module
returns small, deterministic sample FeatureCollections derived from each
layer's bbox / metadata so third-party apps can exercise a features query
shape. Real WFS / PostGIS-backed queries remain a future gap.
"""

from __future__ import annotations

from typing import Any, Optional

from api.catalog import get_layer, known_layer_ids


def _parse_bbox(bbox: str | None) -> Optional[tuple[float, float, float, float]]:
    if not bbox or not bbox.strip():
        return None
    parts = [p.strip() for p in bbox.split(",")]
    if len(parts) != 4:
        raise ValueError("bbox must be west,south,east,north")
    west, south, east, north = (float(p) for p in parts)
    if west > east or south > north:
        raise ValueError("bbox bounds are inverted")
    return west, south, east, north


def _point_in_bbox(
    lon: float, lat: float, bbox: tuple[float, float, float, float]
) -> bool:
    west, south, east, north = bbox
    return west <= lon <= east and south <= lat <= north


def _stub_features_for_layer(layer_id: str) -> list[dict[str, Any]]:
    """Deterministic sample features per catalog layer (not real WFS data)."""
    layer = get_layer(layer_id)
    if layer is None:
        return []

    if layer_id.startswith("esa-worldcover"):
        year = (layer.extra or {}).get("year", 2020)
        # Representative sample points (not a full land-cover extract).
        samples = [
            (51.3890, 35.6892, "Built-up", "Tehran sample"),
            (2.3522, 48.8566, "Built-up", "Paris sample"),
            (-74.0060, 40.7128, "Built-up", "New York sample"),
            (37.7749, -1.2921, "Grassland", "Nairobi region sample"),
            (139.6917, 35.6895, "Built-up", "Tokyo sample"),
            (12.4964, 41.9028, "Built-up", "Rome sample"),
            (151.2093, -33.8688, "Built-up", "Sydney sample"),
            (-46.6333, -23.5505, "Built-up", "São Paulo sample"),
        ]
        features: list[dict[str, Any]] = []
        for i, (lon, lat, klass, note) in enumerate(samples, start=1):
            features.append(
                {
                    "type": "Feature",
                    "id": f"{layer_id}-sample-{i}",
                    "geometry": {"type": "Point", "coordinates": [lon, lat]},
                    "properties": {
                        "layer_id": layer_id,
                        "class": klass,
                        "note": note,
                        "year": year,
                        "source": "stub",
                    },
                }
            )
        # Tiny bbox polygon echoing catalog extent (clipped conceptually).
        features.append(
            {
                "type": "Feature",
                "id": f"{layer_id}-extent-hint",
                "geometry": {
                    "type": "Polygon",
                    "coordinates": [
                        [
                            [-10.0, -10.0],
                            [10.0, -10.0],
                            [10.0, 10.0],
                            [-10.0, 10.0],
                            [-10.0, -10.0],
                        ]
                    ],
                },
                "properties": {
                    "layer_id": layer_id,
                    "class": "extent_hint",
                    "note": "Stub extent polygon for clients; not authoritative.",
                    "source": "stub",
                },
            }
        )
        return features

    if layer_id == "opentopomap":
        return [
            {
                "type": "Feature",
                "id": "opentopomap-center",
                "geometry": {"type": "Point", "coordinates": [0.0, 0.0]},
                "properties": {
                    "layer_id": layer_id,
                    "note": "XYZ basemap — no vector attributes; stub marker only.",
                    "source": "stub",
                },
            }
        ]

    return [
        {
            "type": "Feature",
            "id": f"{layer_id}-stub-1",
            "geometry": {"type": "Point", "coordinates": [0.0, 0.0]},
            "properties": {
                "layer_id": layer_id,
                "note": "Generic stub feature; replace with real WFS later.",
                "source": "stub",
            },
        }
    ]


def query_features(
    layer_id: str,
    *,
    bbox: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Return a GeoJSON FeatureCollection for ``layer_id``.

    Raises ``KeyError`` if the layer is unknown, ``ValueError`` for bad params.
    """
    if layer_id not in known_layer_ids():
        raise KeyError(layer_id)
    if limit < 1 or limit > 500:
        raise ValueError("limit must be between 1 and 500")

    parsed_bbox = _parse_bbox(bbox)
    features = _stub_features_for_layer(layer_id)

    if parsed_bbox is not None:
        filtered: list[dict[str, Any]] = []
        for feat in features:
            geom = feat.get("geometry") or {}
            gtype = geom.get("type")
            coords = geom.get("coordinates")
            if gtype == "Point" and isinstance(coords, list) and len(coords) >= 2:
                if _point_in_bbox(float(coords[0]), float(coords[1]), parsed_bbox):
                    filtered.append(feat)
            elif gtype == "Polygon":
                # Include polygon if any ring vertex falls inside bbox.
                ring = (coords or [[]])[0]
                if any(
                    _point_in_bbox(float(c[0]), float(c[1]), parsed_bbox)
                    for c in ring
                    if isinstance(c, (list, tuple)) and len(c) >= 2
                ):
                    filtered.append(feat)
            else:
                filtered.append(feat)
        features = filtered

    truncated = features[:limit]
    return {
        "type": "FeatureCollection",
        "features": truncated,
        "numberMatched": len(features),
        "numberReturned": len(truncated),
        "layer_id": layer_id,
        "mode": "stub",
        "notes": (
            "Stub GeoJSON for integration testing. Not a live WFS or "
            "authoritative extract of the catalog layer."
        ),
    }
