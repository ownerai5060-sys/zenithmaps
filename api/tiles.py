"""Allowlisted XYZ / WMTS-style tile metadata from the catalog (N4).

Zenith does **not** host its own tile CDN or WMTS endpoint. This module only
exposes tile URL templates already present on catalog layers (e.g. OpenTopoMap)
and validates hosts against the WMS allowlist plus optional
``ZENITH_TILE_CDN_BASE_URLS`` (policy allowlist — no CDN infra invented).
"""

from __future__ import annotations

from urllib.parse import urlparse

from api.catalog import get_layer, list_layer_summaries
from api.config import Settings, get_settings
from api.models import TileCdnPolicy, TileLayerInfo, TileListResponse
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


def cdn_policy(settings: Settings | None = None) -> TileCdnPolicy:
    settings = settings or get_settings()
    bases = [b.rstrip("/") for b in settings.tile_cdn_base_urls if b.strip()]
    return TileCdnPolicy(
        zenith_hosts_tiles=False,
        allowlisted_cdn_base_urls=bases,
    )


def _host_in_cdn_bases(host: str, settings: Settings) -> bool:
    for base in settings.tile_cdn_base_urls:
        parsed = urlparse(base.strip())
        base_host = (parsed.hostname or "").lower()
        if base_host and host == base_host:
            return True
    return False


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
    allowed = bool(check.allowed)
    if not allowed and hosts and all(_host_in_cdn_bases(h, settings) for h in hosts):
        allowed = True
        reason_note = "Host allowlisted via ZENITH_TILE_CDN_BASE_URLS policy."
    elif allowed:
        reason_note = (
            "Catalog tile URL only — Zenith does not proxy or CDN these tiles. "
            "Clients fetch upstream directly when allowlisted."
        )
    else:
        reason_note = f"Tile host not allowlisted ({check.reason})."
    attribution = extra.get("attribution")
    return TileLayerInfo(
        layer_id=layer.id,
        title=layer.title,
        kind=layer.kind,
        tile_url_template=str(template),
        attribution=str(attribution) if attribution else None,
        hosts=hosts,
        allowlisted=allowed,
        notes=reason_note,
    )


def list_tile_layers() -> TileListResponse:
    settings = get_settings()
    policy = cdn_policy(settings)
    items: list[TileLayerInfo] = []
    for summary in list_layer_summaries():
        info = tile_info_for_layer(summary.id)
        if info is not None and info.tile_url_template:
            items.append(info)
    return TileListResponse(
        items=items,
        count=len(items),
        zenith_hosts_tiles=False,
        cdn_policy=policy,
        notes=(
            "No Zenith-operated WMTS/XYZ CDN. Only allowlisted catalog templates "
            "(plus optional ZENITH_TILE_CDN_BASE_URLS) are listed. Do not invent "
            "open public CDN endpoints via this API."
        ),
    )
