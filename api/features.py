"""WFS-lite GeoJSON features for catalog layers.

Surface name: **WFS-lite** — a minimal bbox/limit FeatureCollection query,
not a full OGC WFS.

Backend priority
----------------
1. Optional PostGIS when ``ZENITH_DATABASE_URL`` is set (table
   ``ZENITH_FEATURES_TABLE``, default ``zenith_features``). Any connection /
   query failure falls through gracefully.
2. Bundled GeoJSON fixtures under ``api/fixtures/{layer_id}.geojson``.
3. Deterministic in-code stub samples (last resort).

Response ``mode`` is always ``wfs_lite``; ``backend`` reports which source
served the features.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Literal, Optional

from api.catalog import get_layer, known_layer_ids
from api.config import get_settings

logger = logging.getLogger("zenith.features")

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

FeatureBackend = Literal["postgis", "fixture", "stub"]


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


def _filter_by_bbox(
    features: list[dict[str, Any]],
    parsed_bbox: tuple[float, float, float, float] | None,
) -> list[dict[str, Any]]:
    if parsed_bbox is None:
        return features
    filtered: list[dict[str, Any]] = []
    for feat in features:
        geom = feat.get("geometry") or {}
        gtype = geom.get("type")
        coords = geom.get("coordinates")
        if gtype == "Point" and isinstance(coords, list) and len(coords) >= 2:
            if _point_in_bbox(float(coords[0]), float(coords[1]), parsed_bbox):
                filtered.append(feat)
        elif gtype == "Polygon":
            ring = (coords or [[]])[0]
            if any(
                _point_in_bbox(float(c[0]), float(c[1]), parsed_bbox)
                for c in ring
                if isinstance(c, (list, tuple)) and len(c) >= 2
            ):
                filtered.append(feat)
        else:
            filtered.append(feat)
    return filtered


def _stub_features_for_layer(layer_id: str) -> list[dict[str, Any]]:
    """Deterministic sample features when no fixture / PostGIS is available."""
    layer = get_layer(layer_id)
    if layer is None:
        return []

    if layer_id.startswith("esa-worldcover"):
        year = (layer.extra or {}).get("year", 2020)
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
                "note": "Generic stub feature; replace with fixture or PostGIS.",
                "source": "stub",
            },
        }
    ]


def _load_fixture_features(layer_id: str) -> list[dict[str, Any]] | None:
    path = FIXTURES_DIR / f"{layer_id}.geojson"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("fixture load failed layer=%s: %s", layer_id, exc)
        return None
    feats = data.get("features")
    if not isinstance(feats, list):
        return None
    return feats


def _query_postgis(
    layer_id: str,
    *,
    bbox: tuple[float, float, float, float] | None,
    limit: int,
    database_url: str,
    table: str,
) -> list[dict[str, Any]] | None:
    """Return GeoJSON features from PostGIS, or None to signal fallback.

    Expected table columns (minimal)::

        layer_id TEXT, geom geometry(Geometry, 4326), properties JSONB, id TEXT

    Optional; missing driver / table / errors → None (caller falls back).
    """
    try:
        import psycopg  # type: ignore[import-untyped]
    except ImportError:
        logger.info(
            "ZENITH_DATABASE_URL set but psycopg is not installed; "
            "falling back to fixtures"
        )
        return None

    west, south, east, north = bbox or (-180.0, -90.0, 180.0, 90.0)
    # Identifiers are env-controlled; quote conservatively.
    safe_table = "".join(c for c in table if c.isalnum() or c in "._")
    if not safe_table or safe_table != table:
        logger.warning("invalid ZENITH_FEATURES_TABLE=%r; skipping PostGIS", table)
        return None

    sql = f"""
        SELECT COALESCE(id::text, ''),
               ST_AsGeoJSON(geom)::json,
               COALESCE(properties, '{{}}'::jsonb)
        FROM {safe_table}
        WHERE layer_id = %s
          AND geom && ST_MakeEnvelope(%s, %s, %s, %s, 4326)
          AND ST_Intersects(geom, ST_MakeEnvelope(%s, %s, %s, %s, 4326))
        LIMIT %s
    """
    params = (
        layer_id,
        west,
        south,
        east,
        north,
        west,
        south,
        east,
        north,
        limit,
    )
    try:
        with psycopg.connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001 — graceful fallback is the contract
        logger.warning("PostGIS features query failed; falling back: %s", exc)
        return None

    features: list[dict[str, Any]] = []
    for fid, geom, props in rows:
        properties = props if isinstance(props, dict) else {}
        properties = {**properties, "layer_id": layer_id, "source": "postgis"}
        features.append(
            {
                "type": "Feature",
                "id": fid or None,
                "geometry": geom,
                "properties": properties,
            }
        )
    return features


def query_features(
    layer_id: str,
    *,
    bbox: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Return a GeoJSON FeatureCollection for ``layer_id`` (WFS-lite).

    Raises ``KeyError`` if the layer is unknown, ``ValueError`` for bad params.
    """
    if layer_id not in known_layer_ids():
        raise KeyError(layer_id)
    if limit < 1 or limit > 500:
        raise ValueError("limit must be between 1 and 500")

    parsed_bbox = _parse_bbox(bbox)
    settings = get_settings()
    backend: FeatureBackend = "stub"
    features: list[dict[str, Any]] = []
    notes = (
        "WFS-lite FeatureCollection (bbox + limit). Not a full OGC WFS. "
        "Prefer PostGIS when configured; otherwise bundled fixtures / stubs."
    )

    db_url = (settings.database_url or "").strip()
    if db_url:
        postgis_feats = _query_postgis(
            layer_id,
            bbox=parsed_bbox,
            limit=limit,
            database_url=db_url,
            table=settings.features_table,
        )
        if postgis_feats is not None:
            # PostGIS already applied bbox + limit.
            return {
                "type": "FeatureCollection",
                "features": postgis_feats,
                "numberMatched": len(postgis_feats),
                "numberReturned": len(postgis_feats),
                "layer_id": layer_id,
                "mode": "wfs_lite",
                "backend": "postgis",
                "notes": notes,
            }

    fixture = _load_fixture_features(layer_id)
    if fixture is not None:
        features = fixture
        backend = "fixture"
    else:
        features = _stub_features_for_layer(layer_id)
        backend = "stub"

    features = _filter_by_bbox(features, parsed_bbox)
    truncated = features[:limit]
    return {
        "type": "FeatureCollection",
        "features": truncated,
        "numberMatched": len(features),
        "numberReturned": len(truncated),
        "layer_id": layer_id,
        "mode": "wfs_lite",
        "backend": backend,
        "notes": notes,
    }
