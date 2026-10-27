"""Zenith Maps Platform API entrypoint (M1–M7 + S1–S3).

Architecture decision (M1)
--------------------------
This repository remains the **UI demo** (Streamlit + leafmap under ``Home.py``
and ``pages/``). The durable integration surface for external apps lives in
this FastAPI package (``api/``) and is versioned under ``/api/v1``.

Run locally::

    uvicorn api.main:app --reload --port 8000

Interactive OpenAPI docs: http://127.0.0.1:8000/docs
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from api import __version__
from api.config import get_settings
from api.errors import (
    REQUEST_ID_HEADER,
    ApiError,
    api_error_handler,
    get_request_id,
    http_exception_handler,
    new_request_id,
    unhandled_exception_handler,
    validation_exception_handler,
)
from api.metrics import get_metrics
from api.rate_limit import RateLimitHeaderMiddleware
from api.routers import health, layers, security


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a request_id to every request/response (M5)."""

    async def dispatch(self, request: Request, call_next):
        incoming = request.headers.get(REQUEST_ID_HEADER)
        request_id = incoming.strip() if incoming else new_request_id()
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request_id
        return response


class MetricsMiddleware(BaseHTTPMiddleware):
    """Record per-request latency and error counts (S2)."""

    async def dispatch(self, request: Request, call_next):
        started = time.perf_counter()
        response = await call_next(request)
        latency_ms = (time.perf_counter() - started) * 1000
        is_error = response.status_code >= 500
        get_metrics().record(latency_ms=latency_ms, is_error=is_error)
        return response


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Eagerly load settings so misconfigured env fails at startup.
    get_settings()
    get_metrics().reset()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version=__version__,
        description=(
            "Stable HTTP API for Zenith Maps catalog, layer metadata, structured "
            "legends, and allowlisted GetLegendGraphic. Streamlit pages in this "
            "repo are a UI demo; external apps should integrate against `/api/v1`."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
        expose_headers=[
            REQUEST_ID_HEADER,
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "Retry-After",
        ],
    )
    # Starlette applies middleware in reverse add order for requests.
    application.add_middleware(RateLimitHeaderMiddleware)
    application.add_middleware(MetricsMiddleware)
    application.add_middleware(RequestIdMiddleware)

    application.add_exception_handler(ApiError, api_error_handler)
    application.add_exception_handler(StarletteHTTPException, http_exception_handler)
    application.add_exception_handler(
        RequestValidationError, validation_exception_handler
    )
    application.add_exception_handler(Exception, unhandled_exception_handler)

    application.include_router(health.router)
    application.include_router(layers.router, prefix="/api/v1")
    application.include_router(security.router, prefix="/api/v1")

    @application.get("/api/v1", include_in_schema=True, tags=["meta"])
    async def api_v1_root(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "name": settings.app_name,
                "version": settings.api_version,
                "package_version": __version__,
                "docs": "/docs",
                "endpoints": {
                    "layers": "/api/v1/layers",
                    "layer_detail": "/api/v1/layers/{layer_id}",
                    "legend": "/api/v1/layers/{layer_id}/legend",
                    "legend_image": "/api/v1/layers/{layer_id}/legend/image",
                    "check_url": "/api/v1/security/check-url",
                    "allowlist": "/api/v1/security/allowlist",
                    "healthz": "/healthz",
                    "metrics": "/metrics",
                },
                "request_id": get_request_id(request),
            },
            headers={REQUEST_ID_HEADER: get_request_id(request)},
        )

    return application


app = create_app()
