"""In-memory per-API-key rate limiting (S3).

Uses a simple fixed window counter keyed by ``key_id``. Suitable for a single
process demo/staging deployment — not a distributed limiter.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, Request
from starlette.middleware.base import BaseHTTPMiddleware

from api.auth import Principal, require_api_key
from api.config import Settings, get_settings
from api.errors import ApiError


@dataclass
class _WindowCounter:
    window_start: float
    count: int


class RateLimiter:
    """Thread-safe fixed-window rate limiter."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, _WindowCounter] = defaultdict(
            lambda: _WindowCounter(window_start=0.0, count=0)
        )

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()

    def check(
        self,
        key_id: str,
        *,
        limit: int,
        window_s: float,
    ) -> tuple[bool, int, int, int]:
        """Return ``(allowed, limit, remaining, reset_epoch_s)``."""
        now = time.time()
        with self._lock:
            counter = self._counters[key_id]
            if counter.window_start == 0.0 or now - counter.window_start >= window_s:
                counter.window_start = now
                counter.count = 0
            counter.count += 1
            reset_at = int(counter.window_start + window_s)
            remaining = max(0, limit - counter.count)
            allowed = counter.count <= limit
            return allowed, limit, remaining, reset_at


_GLOBAL_LIMITER = RateLimiter()


def get_rate_limiter() -> RateLimiter:
    return _GLOBAL_LIMITER


def apply_rate_limit(
    principal: Principal,
    settings: Settings | None = None,
    limiter: RateLimiter | None = None,
) -> dict[str, str]:
    """Enforce rate limit for ``principal``; return headers to attach.

    Raises ``ApiError`` with 429 when exceeded.
    """
    settings = settings or get_settings()
    limiter = limiter or get_rate_limiter()
    if not settings.rate_limit_enabled:
        return {}

    allowed, limit, remaining, reset_at = limiter.check(
        principal.key_id,
        limit=settings.rate_limit_requests,
        window_s=float(settings.rate_limit_window_s),
    )
    headers = {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(reset_at),
    }
    if not allowed:
        retry_after = max(1, reset_at - int(time.time()))
        raise ApiError(
            status_code=429,
            code="rate_limited",
            message=(
                f"Rate limit exceeded for key '{principal.key_id}' "
                f"({limit} requests per {settings.rate_limit_window_s}s)"
            ),
            headers={**headers, "Retry-After": str(retry_after)},
        )
    return headers


def require_rate_limited(
    *scopes: str,
) -> Callable[..., Principal]:
    """Auth + optional scopes + rate-limit dependency for protected routes."""

    from api.auth import require_scopes

    scope_dep = require_scopes(*scopes) if scopes else require_api_key

    async def _checker(
        request: Request,
        principal: Principal = Depends(scope_dep),
        settings: Settings = Depends(get_settings),
    ) -> Principal:
        headers = apply_rate_limit(principal, settings=settings)
        request.state.rate_limit_headers = headers
        return principal

    return _checker


class RateLimitHeaderMiddleware(BaseHTTPMiddleware):
    """Attach rate-limit headers from ``request.state`` onto responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        extra = getattr(request.state, "rate_limit_headers", None)
        if isinstance(extra, dict):
            for key, value in extra.items():
                response.headers[key] = value
        return response
