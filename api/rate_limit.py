"""Per-API-key rate limiting with pluggable backends.

Default: in-process fixed window (single worker).
Optional: Redis fixed window when ``ZENITH_REDIS_URL`` is set and the ``redis``
package is installed (``ZENITH_RATE_LIMIT_BACKEND=auto|redis``).

Fallback: if Redis is requested but unavailable, the API logs a warning and
uses the in-memory backend so staging stays usable.
"""

from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, Request
from starlette.middleware.base import BaseHTTPMiddleware

from api.auth import Principal, require_api_key
from api.config import Settings, get_settings
from api.errors import ApiError

logger = logging.getLogger("zenith.api.rate_limit")


@dataclass
class _WindowCounter:
    window_start: float
    count: int


class RateLimitBackend(ABC):
    """Distributed-capable rate-limit interface."""

    name: str = "abstract"

    @abstractmethod
    def reset(self) -> None:
        """Clear counters (tests / process restart semantics)."""

    @abstractmethod
    def check(
        self,
        key_id: str,
        *,
        limit: int,
        window_s: float,
    ) -> tuple[bool, int, int, int]:
        """Return ``(allowed, limit, remaining, reset_epoch_s)``."""


class InMemoryRateLimitBackend(RateLimitBackend):
    """Thread-safe fixed-window limiter (single process)."""

    name = "memory"

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


class RedisRateLimitBackend(RateLimitBackend):
    """Fixed-window limiter backed by Redis INCR + EXPIRE.

    Key shape: ``zenith:rl:{key_id}:{window_id}`` where window_id is
    ``floor(now / window_s)``.
    """

    name = "redis"

    def __init__(self, redis_url: str) -> None:
        try:
            import redis  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover - exercised via factory
            raise RuntimeError(
                "redis package is not installed; pip install redis"
            ) from exc
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        # Fail fast if URL is wrong.
        self._client.ping()

    def reset(self) -> None:
        # Best-effort: delete known prefix keys (tests should prefer memory).
        for key in self._client.scan_iter(match="zenith:rl:*", count=100):
            self._client.delete(key)

    def check(
        self,
        key_id: str,
        *,
        limit: int,
        window_s: float,
    ) -> tuple[bool, int, int, int]:
        now = time.time()
        window_id = int(now // window_s)
        reset_at = int((window_id + 1) * window_s)
        redis_key = f"zenith:rl:{key_id}:{window_id}"
        count = int(self._client.incr(redis_key))
        if count == 1:
            self._client.expire(redis_key, int(window_s) + 1)
        remaining = max(0, limit - count)
        allowed = count <= limit
        return allowed, limit, remaining, reset_at


# Back-compat alias used by older tests / imports.
RateLimiter = InMemoryRateLimitBackend

_BACKEND: RateLimitBackend | None = None
_BACKEND_LOCK = threading.Lock()


def _build_backend(settings: Settings | None = None) -> RateLimitBackend:
    settings = settings or get_settings()
    choice = settings.rate_limit_backend
    want_redis = choice == "redis" or (
        choice == "auto" and bool(settings.redis_url)
    )
    if want_redis:
        if not settings.redis_url:
            logger.warning(
                "ZENITH_RATE_LIMIT_BACKEND=redis but ZENITH_REDIS_URL is empty; "
                "falling back to in-memory"
            )
        else:
            try:
                backend = RedisRateLimitBackend(settings.redis_url)
                logger.info("Rate limit backend: redis")
                return backend
            except Exception as exc:  # noqa: BLE001 — intentional soft fallback
                logger.warning(
                    "Redis rate limit unavailable (%s); falling back to in-memory",
                    exc,
                )
    logger.info("Rate limit backend: memory")
    return InMemoryRateLimitBackend()


def get_rate_limiter() -> RateLimitBackend:
    """Return the process-wide rate-limit backend (lazy init)."""
    global _BACKEND
    with _BACKEND_LOCK:
        if _BACKEND is None:
            _BACKEND = _build_backend()
        return _BACKEND


def reset_rate_limiter(settings: Settings | None = None) -> RateLimitBackend:
    """Rebuild backend from current settings (tests / config reload)."""
    global _BACKEND
    with _BACKEND_LOCK:
        _BACKEND = _build_backend(settings)
        return _BACKEND


def apply_rate_limit(
    principal: Principal,
    settings: Settings | None = None,
    limiter: RateLimitBackend | None = None,
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
        "X-RateLimit-Backend": limiter.name,
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


def require_rate_limited_any(
    *accepted: str,
) -> Callable[..., Principal]:
    """Auth + at-least-one scope + rate-limit (portal operator vs admin)."""

    from api.auth import require_any_scope

    scope_dep = require_any_scope(*accepted) if accepted else require_api_key

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
