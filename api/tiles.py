"""Allowlisted XYZ / WMTS-style tile metadata from the catalog (N4).

Zenith does **not** host its own tile CDN or WMTS endpoint. This module only
exposes tile URL templates already present on catalog layers (e.g. OpenTopoMap)
and validates hosts against the same allowlist used for WMS URLs.
"""

from __future__ import annotations

from urllib.parse import urlparse

from api.catalog import get_layer, list_layer_summaries
from api.config import get_settings
from api.models import TileLayerInfo, TileListResponse
from api.security.allowlist import check_wms_url


def _hosts_from_template(template: str) -> list[str]:
    """Expand common ``{s}`` subdomain placeholders for allowlist checks."""
    parsed = urlparse(template.replace("{s}", "a"))
    host = (parsed.hostname or "").lower()
    if not host:
        return []
    if "{s}" in template or template.startswith("https://{s}."):
        # OpenTopoMap-style a/b/c subdomains.
        base = host
        if base.startswith("a."):
            stem = base[2:]
            return [f"{sub}.{stem}" for sub in ("a", "b", "c")]
        return [host]
    return [host]


def tile_info_for_layer(layer_id: str) -> TileLayerInfo | None:
    layer = get_layer(layer_id)
    if layer is None:
        return None
    extra = dict(layer.extra or {})
    template = extra.get("tile_url_template")
    if not template:
        return TileLayerInfo(
            layer_id=layer.id,
            title=layer.title,
            kind=layer.kind,
            tile_url_template=None,
            attribution=None,
            hosts=[],
            allowlisted=False,
            notes="No tile_url_template on this catalog entry.",
        )

    hosts = _hosts_from_template(str(template))
    settings = get_settings()
    # Prefer checking a concrete host (replace {s}).
    probe = str(template).replace("{s}", "a").replace("{z}", "0").replace(
        "{x}", "0"
    ).replace("{y}", "0")
    check = check_wms_url(probe, settings=settings)
    attribution = extra.get("attribution")
    return TileLayerInfo(
        layer_id=layer.id,
        title=layer.title,
        kind=layer.kind,
        tile_url_template=str(template),
        attribution=str(attribution) if attribution else None,
        hosts=hosts,
        allowlisted=bool(check.allowed),
        notes=(
            "Catalog tile URL only — Zenith does not proxy or CDN these tiles. "
            "Clients fetch upstream directly when allowlisted."
            if check.allowed
            else f"Tile host not allowlisted ({check.reason})."
        ),
    )


def list_tile_layers() -> TileListResponse:
    items: list[TileLayerInfo] = []
    for summary in list_layer_summaries():
        info = tile_info_for_layer(summary.id)
        if info is not None and info.tile_url_template:
            items.append(info)
    return TileListResponse(
        items=items,
        count=len(items),
        zenith_hosts_tiles=False,
        notes=(
            "No Zenith-operated WMTS/XYZ CDN. Only allowlisted catalog templates "
            "are listed. Do not invent open public CDN endpoints via this API."
        ),
    )
