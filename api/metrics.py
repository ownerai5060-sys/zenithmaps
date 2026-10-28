"""Lightweight in-process request metrics (S2).

Tracks request counts, error counts, and a simple latency sample for
``GET /metrics`` and richer ``/healthz`` payloads. Not a Prometheus exporter.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque


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

    def record(self, *, latency_ms: float, is_error: bool) -> None:
        with self._lock:
            self.request_count += 1
            if is_error:
                self.error_count += 1
            self._latencies_ms.append(latency_ms)

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
        }


_METRICS = MetricsStore()


def get_metrics() -> MetricsStore:
    return _METRICS
