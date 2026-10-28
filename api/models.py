"""Pydantic response models for the stable `/api/v1` surface (M2)."""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl


class LegendEntry(BaseModel):
    """One legend class / swatch."""

    label: str
    color: str = Field(..., description="CSS color (hex or named)")
    description: Optional[str] = None


class Legend(BaseModel):
    """Structured legend JSON for a catalog layer (S1: richer + graphic URL)."""

    layer_id: str
    title: str
    type: Literal["categorical", "continuous", "other"] = "categorical"
    entries: list[LegendEntry] = Field(default_factory=list)
    source: Optional[str] = None
    notes: Optional[str] = None
    # OGC GetLegendGraphic URL against the allowlisted upstream WMS (if any).
    get_legend_graphic_url: Optional[str] = Field(
        default=None,
        description="Upstream WMS GetLegendGraphic URL (allowlisted catalog only)",
    )
    # Zenith-proxied image endpoint (same-origin, API-key required).
    legend_image_path: Optional[str] = Field(
        default=None,
        description="Relative path to Zenith GetLegendGraphic image proxy",
    )


class LayerSummary(BaseModel):
    """Item in the layers catalog list."""

    id: str
    title: str
    description: str
    kind: Literal["wms", "xyz", "geojson", "other"]
    tags: list[str] = Field(default_factory=list)


class LayerListResponse(BaseModel):
    items: list[LayerSummary]
    count: int


class WmsSource(BaseModel):
    """Allowlisted WMS endpoint metadata (no open proxy)."""

    service_url: HttpUrl
    layer_name: str
    version: str = "1.3.0"
    format: str = "image/png"
    transparent: bool = True
    attribution: Optional[str] = None


class LayerDetail(BaseModel):
    """Full layer metadata including optional WMS source."""

    id: str
    title: str
    description: str
    kind: Literal["wms", "xyz", "geojson", "other"]
    tags: list[str] = Field(default_factory=list)
    bbox: Optional[list[float]] = Field(
        default=None,
        description="Optional [west, south, east, north] in EPSG:4326",
    )
    crs: list[str] = Field(default_factory=lambda: ["EPSG:4326"])
    wms: Optional[WmsSource] = None
    legend_available: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)


class UrlCheckRequest(BaseModel):
    """Validate a candidate WMS/tile URL against the allowlist (M6)."""

    url: str
    layer_name: Optional[str] = None


class UrlCheckResponse(BaseModel):
    allowed: bool
    host: Optional[str] = None
    reason: Optional[str] = None


class UpstreamStatus(BaseModel):
    url: str
    probe: str = "GetCapabilities"
    status: Literal["up", "degraded", "down", "skipped"]
    http_status: Optional[int] = None
    latency_ms: Optional[float] = None
    error: Optional[str] = None


class HealthResponse(BaseModel):
    """Liveness + optional upstream / metrics snapshot (S2)."""

    status: Literal["ok", "degraded"] = "ok"
    api_version: str
    service: str
    upstreams: list[UpstreamStatus] = Field(default_factory=list)
    metrics: Optional[dict[str, Any]] = None


class MetricsResponse(BaseModel):
    service: str
    api_version: str
    metrics: dict[str, Any]


class FeatureCollectionResponse(BaseModel):
    """GeoJSON FeatureCollection wrapper for WFS-lite queries."""

    type: Literal["FeatureCollection"] = "FeatureCollection"
    features: list[dict[str, Any]] = Field(default_factory=list)
    numberMatched: int = 0
    numberReturned: int = 0
    layer_id: str
    mode: Literal["wfs_lite", "stub", "live"] = "wfs_lite"
    backend: Literal["postgis", "fixture", "stub"] = "fixture"
    notes: Optional[str] = None


class TileLayerInfo(BaseModel):
    """Allowlisted XYZ/WMTS-style tile template from the catalog (N4)."""

    layer_id: str
    title: str
    kind: Literal["wms", "xyz", "geojson", "other"]
    tile_url_template: Optional[str] = None
    attribution: Optional[str] = None
    hosts: list[str] = Field(default_factory=list)
    allowlisted: bool = False
    notes: Optional[str] = None


class TileListResponse(BaseModel):
    items: list[TileLayerInfo]
    count: int
    zenith_hosts_tiles: bool = False
    notes: Optional[str] = None


class CatalogMeta(BaseModel):
    version: int
    updated_at: float
    layer_count: int


class CatalogBumpResponse(CatalogMeta):
    reason: str
    webhook: Optional[dict[str, Any]] = None
