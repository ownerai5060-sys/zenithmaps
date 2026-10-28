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
    """Structured legend JSON for a catalog layer."""

    layer_id: str
    title: str
    type: Literal["categorical", "continuous", "other"] = "categorical"
    entries: list[LegendEntry] = Field(default_factory=list)
    source: Optional[str] = None
    notes: Optional[str] = None


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


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    api_version: str
    service: str
