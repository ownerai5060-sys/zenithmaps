"""Unified error envelope for `/api/v1` (M5).

Every error response uses:

    {
      "code": "<stable_machine_code>",
      "message": "<human-readable>",
      "request_id": "<uuid>"
    }
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


REQUEST_ID_HEADER = "X-Request-ID"


def new_request_id() -> str:
    return str(uuid.uuid4())


def get_request_id(request: Request) -> str:
    existing = getattr(request.state, "request_id", None)
    if existing:
        return str(existing)
    return new_request_id()


def error_body(code: str, message: str, request_id: str) -> dict[str, str]:
    return {"code": code, "message": message, "request_id": request_id}


def error_response(
    status_code: int,
    code: str,
    message: str,
    request_id: str,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=error_body(code, message, request_id),
        headers={REQUEST_ID_HEADER: request_id},
    )


def http_status_to_code(status_code: int) -> str:
    mapping = {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        405: "method_not_allowed",
        409: "conflict",
        422: "validation_error",
        429: "rate_limited",
        500: "internal_error",
        502: "bad_gateway",
        503: "service_unavailable",
    }
    return mapping.get(status_code, f"http_{status_code}")


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    request_id = get_request_id(request)
    detail = exc.detail
    if isinstance(detail, dict) and "code" in detail and "message" in detail:
        code = str(detail["code"])
        message = str(detail["message"])
    else:
        code = http_status_to_code(exc.status_code)
        message = str(detail) if detail else code
    return error_response(exc.status_code, code, message, request_id)


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    request_id = get_request_id(request)
    # Keep message short; full pydantic errors stay out of the public envelope.
    message = "Request validation failed"
    errors: list[Any] = exc.errors()
    if errors:
        first = errors[0]
        loc = ".".join(str(part) for part in first.get("loc", ()) if part != "body")
        msg = first.get("msg", message)
        message = f"{loc}: {msg}" if loc else str(msg)
    return error_response(422, "validation_error", message, request_id)


async def unhandled_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    request_id = get_request_id(request)
    return error_response(
        500,
        "internal_error",
        "An unexpected error occurred",
        request_id,
    )


class ApiError(Exception):
    """Raise inside route handlers for a controlled error envelope."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = headers or {}
        super().__init__(message)


async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    request_id = get_request_id(request)
    response = error_response(exc.status_code, exc.code, exc.message, request_id)
    for key, value in exc.headers.items():
        response.headers[key] = value
    return response
