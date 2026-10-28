"""In-process request metrics (S2) + optional Prometheus export.

JSON snapshot remains at ``GET /metrics``. When ``ZENITH_PROMETHEUS_ENABLED``
is true (default), ``GET /metrics/prometheus`` serves Prometheus text format
via ``prometheus_client``.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    _PROM_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PROM_AVAILABLE = False
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"


@dataclass
class MetricsStore:
    started_at: float = field(default_factory=time.time)
    request_count: int = 0
    error_count: int = 0
    # Ring buffer of recent latencies in milliseconds.
    _latencies_ms: Deque[float] = field(default_factory=lambda: deque(maxlen=500))
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def reset(self) -> None:
        with self._lock:
            self.started_at = time.time()
            self.request_count = 0
            self.error_count = 0
            self._latencies_ms.clear()

    def record(self, *, latency_ms: float, is_error: bool, path: str = "") -> None:
        with self._lock:
            self.request_count += 1
            if is_error:
                self.error_count += 1
            self._latencies_ms.append(latency_ms)
        if _PROM_AVAILABLE:
            _record_prometheus(latency_ms=latency_ms, is_error=is_error, path=path)

    def snapshot(self) -> dict:
        with self._lock:
            samples = list(self._latencies_ms)
            request_count = self.request_count
            error_count = self.error_count
            started_at = self.started_at
        avg_ms = sum(samples) / len(samples) if samples else 0.0
        p95_ms = 0.0
        if samples:
            ordered = sorted(samples)
            idx = min(len(ordered) - 1, int(len(ordered) * 0.95))
            p95_ms = ordered[idx]
        return {
            "uptime_s": round(time.time() - started_at, 3),
            "request_count": request_count,
            "error_count": error_count,
            "latency_ms": {
                "samples": len(samples),
                "avg": round(avg_ms, 3),
                "p95": round(p95_ms, 3),
            },
            "prometheus_available": _PROM_AVAILABLE,
        }


_METRICS = MetricsStore()

if _PROM_AVAILABLE:
    _REGISTRY = CollectorRegistry()
    _REQ_COUNTER = Counter(
        "zenith_http_requests_total",
        "Total HTTP requests handled by Zenith API",
        ["result"],
        registry=_REGISTRY,
    )
    _LATENCY = Histogram(
        "zenith_http_request_duration_seconds",
        "HTTP request latency in seconds",
        ["path"],
        registry=_REGISTRY,
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    )
    _UP = Gauge(
        "zenith_api_up",
        "1 if the API process is serving metrics",
        registry=_REGISTRY,
    )
    _UP.set(1)


def _normalize_path(path: str) -> str:
    if not path:
        return "unknown"
    # Keep cardinality low: collapse layer ids.
    parts = path.strip("/").split("/")
    out: list[str] = []
    skip_next = False
    for i, part in enumerate(parts):
        if skip_next:
            skip_next = False
            out.append("{id}")
            continue
        out.append(part)
        if part == "layers" and i + 1 < len(parts):
            skip_next = True
    return "/" + "/".join(out)


def _record_prometheus(*, latency_ms: float, is_error: bool, path: str) -> None:
    result = "error" if is_error else "ok"
    _REQ_COUNTER.labels(result=result).inc()
    _LATENCY.labels(path=_normalize_path(path)).observe(latency_ms / 1000.0)


def get_metrics() -> MetricsStore:
    return _METRICS


def prometheus_available() -> bool:
    return _PROM_AVAILABLE


def render_prometheus() -> tuple[bytes, str]:
    """Return ``(body, content_type)`` for Prometheus scrape."""
    if not _PROM_AVAILABLE:
        return (
            b"# prometheus_client not installed\n",
            "text/plain; charset=utf-8",
        )
    return generate_latest(_REGISTRY), CONTENT_TYPE_LATEST
