"""Upstream WMS reachability checks for health (S2)."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from api.catalog import list_layer_summaries, get_layer
from api.config import Settings, get_settings

DEFAULT_TIMEOUT_S = 5.0


def _capabilities_url(service_url: str, version: str = "1.3.0") -> str:
    parsed = urlparse(service_url.strip())
    base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    params = {
        "SERVICE": "WMS",
        "REQUEST": "GetCapabilities",
        "VERSION": version,
    }
    return f"{base}?{urlencode(params)}"


def check_wms_upstream(
    service_url: str,
    *,
    version: str = "1.3.0",
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """Probe a WMS GetCapabilities endpoint; return status dict."""
    url = _capabilities_url(service_url, version=version)
    started = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout_s, follow_redirects=False) as client:
            response = client.get(url)
        latency_ms = round((time.perf_counter() - started) * 1000, 3)
        ok = 200 <= response.status_code < 400
        return {
            "url": service_url,
            "probe": "GetCapabilities",
            "status": "up" if ok else "degraded",
            "http_status": response.status_code,
            "latency_ms": latency_ms,
        }
    except httpx.TimeoutException:
        return {
            "url": service_url,
            "probe": "GetCapabilities",
            "status": "down",
            "http_status": None,
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
            "error": "timeout",
        }
    except httpx.HTTPError as exc:
        return {
            "url": service_url,
            "probe": "GetCapabilities",
            "status": "down",
            "http_status": None,
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
            "error": type(exc).__name__,
        }


def catalog_upstream_status(
    *,
    settings: Settings | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    skip_network: bool = False,
) -> list[dict[str, Any]]:
    """Check unique WMS service URLs referenced by the catalog."""
    settings = settings or get_settings()
    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    for summary in list_layer_summaries():
        layer = get_layer(summary.id)
        if layer is None or layer.wms is None:
            continue
        url = str(layer.wms.service_url)
        if url in seen:
            continue
        seen.add(url)
        if skip_network:
            results.append(
                {
                    "url": url,
                    "probe": "GetCapabilities",
                    "status": "skipped",
                    "http_status": None,
                    "latency_ms": None,
                    "error": "network_probes_disabled",
                }
            )
            continue
        # Only probe allowlisted hosts.
        host = urlparse(url).hostname
        if host and host.lower() not in settings.wms_allowed_hosts:
            results.append(
                {
                    "url": url,
                    "probe": "GetCapabilities",
                    "status": "skipped",
                    "http_status": None,
                    "latency_ms": None,
                    "error": "host_not_allowlisted",
                }
            )
            continue
        results.append(
            check_wms_upstream(url, version=layer.wms.version, timeout_s=timeout_s)
        )
    return results
