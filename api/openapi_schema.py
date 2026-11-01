"""OpenAPI / Swagger enrichment for partner-contract readiness (docs only).

Runtime auth, error handling, and route behavior are unchanged. This module
only customizes the generated ``/openapi.json`` so external clients see:

* ``ErrorEnvelope`` (``code``, ``message``, ``request_id``) on error responses
* 401 / 403 / 429 (and aligned 422) on authenticated operations
* ``POST /oauth/token`` requestBody (JSON + form)
* Useful examples on key endpoints
* securitySchemes for portal cookie, CSRF header, and OAuth2 scopes
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from api import __version__
from api.errors import ErrorEnvelope
from api.routers.oauth import TokenJsonRequest

ERROR_ENVELOPE_REF = {"$ref": "#/components/schemas/ErrorEnvelope"}

_SCOPE_DESCRIPTIONS = {
    "layers:read": "Read catalog layers, legends, features, tiles, allowlist checks",
    "keys:read": "List API keys (secrets omitted) via the admin keys API / portal",
    "admin:keys": "Create, rotate, revoke keys; manage webhooks and catalog bumps",
}

_AUTH_ERROR_RESPONSES: dict[str, dict[str, Any]] = {
    "401": {
        "description": "Missing or invalid credentials (API key, Bearer, or portal cookie)",
        "content": {
            "application/json": {
                "schema": ERROR_ENVELOPE_REF,
                "example": {
                    "code": "unauthorized",
                    "message": (
                        "Missing X-API-Key header, Bearer token, "
                        "or portal session cookie"
                    ),
                    "request_id": "00000000-0000-4000-8000-000000000001",
                },
            }
        },
    },
    "403": {
        "description": "Authenticated but missing required scope(s)",
        "content": {
            "application/json": {
                "schema": ERROR_ENVELOPE_REF,
                "example": {
                    "code": "forbidden",
                    "message": "Missing required scope(s): admin:keys",
                    "request_id": "00000000-0000-4000-8000-000000000002",
                },
            }
        },
    },
    "422": {
        "description": "Request validation failed (Zenith error envelope)",
        "content": {
            "application/json": {
                "schema": ERROR_ENVELOPE_REF,
                "example": {
                    "code": "validation_error",
                    "message": "body.url: Field required",
                    "request_id": "00000000-0000-4000-8000-000000000003",
                },
            }
        },
    },
    "429": {
        "description": "Rate limited — see X-RateLimit-* and Retry-After headers",
        "content": {
            "application/json": {
                "schema": ERROR_ENVELOPE_REF,
                "example": {
                    "code": "rate_limited",
                    "message": "Rate limit exceeded",
                    "request_id": "00000000-0000-4000-8000-000000000004",
                },
            }
        },
    },
}

_TOKEN_REQUEST_EXAMPLES = {
    "client_credentials": {
        "summary": "client_credentials (JSON)",
        "value": {
            "grant_type": "client_credentials",
            "client_id": "demo",
            "client_secret": "demo-secret",
            "scope": "layers:read",
        },
    },
    "authorization_code_pkce": {
        "summary": "authorization_code + PKCE",
        "value": {
            "grant_type": "authorization_code",
            "client_id": "demo",
            "code": "stub-auth-code",
            "redirect_uri": "http://127.0.0.1:8000/oauth/callback",
            "code_verifier": "pkce-code-verifier-example",
        },
    },
    "refresh_token": {
        "summary": "refresh_token",
        "value": {
            "grant_type": "refresh_token",
            "client_id": "demo",
            "client_secret": "demo-secret",
            "refresh_token": "opaque-refresh-token",
        },
    },
}

_OPERATION_EXAMPLES: dict[tuple[str, str], dict[str, Any]] = {
    ("/api/v1/layers", "get"): {
        "200": {
            "description": "Catalog layer summaries",
            "content": {
                "application/json": {
                    "example": {
                        "items": [
                            {
                                "id": "demo-wms",
                                "title": "Demo WMS layer",
                                "description": "Allowlisted demo WMS",
                                "kind": "wms",
                                "tags": ["demo"],
                            }
                        ],
                        "count": 1,
                    }
                }
            },
        }
    },
    ("/api/v1/layers/{layer_id}/legend", "get"): {
        "200": {
            "description": "Structured legend JSON",
            "content": {
                "application/json": {
                    "example": {
                        "layer_id": "demo-wms",
                        "title": "Demo legend",
                        "type": "categorical",
                        "entries": [
                            {"label": "A", "color": "#1f77b4"},
                            {"label": "B", "color": "#ff7f0e"},
                        ],
                        "legend_image_path": "/api/v1/layers/demo-wms/legend/image",
                    }
                }
            },
        }
    },
    ("/api/v1/layers/{layer_id}/features", "get"): {
        "200": {
            "description": "WFS-lite FeatureCollection",
            "content": {
                "application/json": {
                    "example": {
                        "type": "FeatureCollection",
                        "features": [
                            {
                                "type": "Feature",
                                "geometry": {
                                    "type": "Point",
                                    "coordinates": [51.4, 35.7],
                                },
                                "properties": {"name": "demo"},
                            }
                        ],
                        "numberMatched": 1,
                        "numberReturned": 1,
                        "layer_id": "demo-geojson",
                        "mode": "wfs_lite",
                        "backend": "fixture",
                    }
                }
            },
        }
    },
    ("/api/v1/security/check-url", "post"): {
        "200": {
            "description": "Allowlist decision (no fetch/proxy)",
            "content": {
                "application/json": {
                    "examples": {
                        "allowed": {
                            "summary": "Allowed host/layer",
                            "value": {
                                "allowed": True,
                                "host": "example.com",
                                "reason": None,
                            },
                        },
                        "rejected": {
                            "summary": "Rejected host",
                            "value": {
                                "allowed": False,
                                "host": "evil.example",
                                "reason": "host_not_allowlisted",
                            },
                        },
                    }
                }
            },
        }
    },
    ("/api/v1/admin/keys", "post"): {
        "200": {
            "description": "Created key (secret shown once)",
            "content": {
                "application/json": {
                    "example": {
                        "key_id": "partner-1",
                        "scopes": ["layers:read"],
                        "label": "Partner app",
                        "created_at": 1730000000.0,
                        "rotated_at": 0.0,
                        "revoked": False,
                        "revoked_at": None,
                        "secret": "zn_live_example_secret_once",
                    }
                }
            },
        }
    },
    ("/api/v1/admin/webhooks", "post"): {
        "200": {
            "description": "Registered webhook subscription",
            "content": {
                "application/json": {
                    "example": {
                        "id": "wh_demo",
                        "url": "https://hooks.example.com/zenith",
                        "events": ["catalog.updated"],
                        "label": "Partner hook",
                        "created_at": 1730000000.0,
                        "last_ping_at": None,
                        "last_status": None,
                        "last_error": None,
                        "active": True,
                    }
                }
            },
        }
    },
    ("/oauth/token", "post"): {
        "200": {
            "description": "Issued access token",
            "content": {
                "application/json": {
                    "example": {
                        "access_token": "opaque-access-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "scope": "layers:read",
                    }
                }
            },
        }
    },
}


def _schema_from_model(model: type) -> dict[str, Any]:
    """Pydantic v2 JSON schema suitable for OpenAPI components."""
    schema = model.model_json_schema(ref_template="#/components/schemas/{model}")
    # Inline $defs into the top-level object when present.
    defs = schema.pop("$defs", None) or schema.pop("definitions", None)
    if defs:
        # TokenJsonRequest / ErrorEnvelope are flat — ignore nested defs.
        _ = defs
    schema.pop("title", None)
    return schema


def _error_content_uses_fastapi_validation(content: Any) -> bool:
    if not isinstance(content, dict):
        return False
    app_json = content.get("application/json") or {}
    schema = app_json.get("schema") or {}
    ref = schema.get("$ref", "")
    return "HTTPValidationError" in ref


def _ensure_error_envelope_response(
    responses: dict[str, Any], status: str, template: dict[str, Any]
) -> None:
    existing = responses.get(status)
    if existing is None:
        responses[status] = dict(template)
        return
    # Replace misleading FastAPI validation body with ErrorEnvelope.
    if status == "422" or _error_content_uses_fastapi_validation(
        existing.get("content")
    ):
        merged = dict(template)
        if existing.get("description") and status != "422":
            merged["description"] = existing["description"]
        responses[status] = merged
        return
    # Keep existing description when present; ensure ErrorEnvelope body.
    if "content" not in existing:
        updated = dict(existing)
        updated["content"] = template["content"]
        if "description" not in updated:
            updated["description"] = template["description"]
        responses[status] = updated


def _patch_authenticated_responses(paths: dict[str, Any]) -> None:
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.startswith("x-") or not isinstance(operation, dict):
                continue
            responses = operation.setdefault("responses", {})
            # Always replace misleading FastAPI 422 validation bodies.
            if "422" in responses or _error_content_uses_fastapi_validation(
                (responses.get("422") or {}).get("content")
            ):
                _ensure_error_envelope_response(
                    responses, "422", _AUTH_ERROR_RESPONSES["422"]
                )
            security = operation.get("security")
            if not security:
                continue
            for status, template in _AUTH_ERROR_RESPONSES.items():
                if status == "422":
                    continue
                _ensure_error_envelope_response(responses, status, template)


def _replace_all_http_validation_errors(paths: dict[str, Any]) -> None:
    """Any remaining HTTPValidationError response bodies → ErrorEnvelope."""
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.startswith("x-") or not isinstance(operation, dict):
                continue
            responses = operation.get("responses") or {}
            for status, body in list(responses.items()):
                if not isinstance(body, dict):
                    continue
                if _error_content_uses_fastapi_validation(body.get("content")):
                    _ensure_error_envelope_response(
                        responses,
                        status,
                        _AUTH_ERROR_RESPONSES.get(status)
                        or _AUTH_ERROR_RESPONSES["422"],
                    )


def _patch_token_request_body(paths: dict[str, Any]) -> None:
    token_op = (paths.get("/oauth/token") or {}).get("post")
    if not isinstance(token_op, dict):
        return
    token_op["requestBody"] = {
        "required": True,
        "description": (
            "OAuth2 token request. Accepts JSON or "
            "application/x-www-form-urlencoded with the same fields "
            "(grant_type, client_id, client_secret, scope, code, "
            "redirect_uri, refresh_token, code_verifier)."
        ),
        "content": {
            "application/json": {
                "schema": {"$ref": "#/components/schemas/TokenJsonRequest"},
                "examples": _TOKEN_REQUEST_EXAMPLES,
            },
            "application/x-www-form-urlencoded": {
                "schema": {"$ref": "#/components/schemas/TokenJsonRequest"},
                "examples": {
                    "client_credentials_form": {
                        "summary": "client_credentials (form)",
                        "value": {
                            "grant_type": "client_credentials",
                            "client_id": "demo",
                            "client_secret": "demo-secret",
                            "scope": "layers:read",
                        },
                    }
                },
            },
        },
    }
    responses = token_op.setdefault("responses", {})
    for status, code, message in (
        ("400", "bad_request", "Unsupported grant_type or invalid_grant"),
        ("401", "unauthorized", "Invalid client"),
        ("503", "service_unavailable", "OAuth token endpoint is disabled"),
    ):
        _ensure_error_envelope_response(
            responses,
            status,
            {
                "description": responses.get(status, {}).get("description")
                or message,
                "content": {
                    "application/json": {
                        "schema": ERROR_ENVELOPE_REF,
                        "example": {
                            "code": code,
                            "message": message,
                            "request_id": "00000000-0000-4000-8000-000000000010",
                        },
                    }
                },
            },
        )


def _patch_examples(paths: dict[str, Any]) -> None:
    for (path, method), response_map in _OPERATION_EXAMPLES.items():
        operation = (paths.get(path) or {}).get(method)
        if not isinstance(operation, dict):
            continue
        responses = operation.setdefault("responses", {})
        for status, patch in response_map.items():
            existing = responses.get(status) or {}
            merged = dict(existing)
            merged["description"] = patch.get(
                "description", existing.get("description", "Successful Response")
            )
            content = dict(merged.get("content") or {})
            for media_type, media_body in (patch.get("content") or {}).items():
                current = dict(content.get(media_type) or {})
                current.update(media_body)
                # Preserve schema $ref when we only add examples.
                if "schema" in (existing.get("content") or {}).get(media_type, {}):
                    current.setdefault(
                        "schema",
                        existing["content"][media_type]["schema"],
                    )
                content[media_type] = current
            merged["content"] = content
            responses[status] = merged


def _add_security_schemes(components: dict[str, Any], *, cookie_name: str) -> None:
    schemes = components.setdefault("securitySchemes", {})
    # Preserve FastAPI-generated APIKeyHeader / HTTPBearer; enrich descriptions.
    if "APIKeyHeader" in schemes:
        schemes["APIKeyHeader"] = {
            **schemes["APIKeyHeader"],
            "description": (
                "Primary third-party auth. Send the API key secret as "
                "`X-API-Key`. Scopes are bound to the key "
                f"({', '.join(_SCOPE_DESCRIPTIONS)})."
            ),
        }
    if "HTTPBearer" in schemes:
        schemes["HTTPBearer"] = {
            **schemes["HTTPBearer"],
            "description": (
                "Opaque token from `POST /oauth/token`, or OIDC JWT when "
                "JWKS is configured. Bearer carries the same scopes as the "
                "issuing client/key."
            ),
        }
    schemes["PortalSessionCookie"] = {
        "type": "apiKey",
        "in": "cookie",
        "name": cookie_name,
        "description": (
            "HttpOnly portal SSO cookie (opaque session_id). Used by the "
            "key portal / browser flows. Mutating requests that authenticate "
            "via this cookie also require the CSRF header."
        ),
    }
    schemes["CsrfHeader"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-CSRF-Token",
        "description": (
            "Double-submit CSRF token for cookie-authenticated mutations. "
            "Must match the non-HttpOnly CSRF cookie issued at portal login. "
            "Not required for X-API-Key or Bearer auth."
        ),
    }
    schemes["OAuth2ClientCredentials"] = {
        "type": "oauth2",
        "description": (
            "Documented OAuth2 client_credentials scopes for partners. "
            "Token endpoint: `/oauth/token`. Runtime also accepts "
            "authorization_code + PKCE and refresh_token."
        ),
        "flows": {
            "clientCredentials": {
                "tokenUrl": "/oauth/token",
                "scopes": dict(_SCOPE_DESCRIPTIONS),
            }
        },
    }


def _strip_unused_validation_schemas(schema: dict[str, Any]) -> None:
    """Drop FastAPI's default HTTPValidationError when nothing references it."""
    components = schema.get("components") or {}
    schemas = components.get("schemas") or {}
    paths_blob = str(schema.get("paths") or {})
    other_schemas = {
        k: v
        for k, v in schemas.items()
        if k not in {"HTTPValidationError", "ValidationError"}
    }
    other_blob = str(other_schemas)
    for name in ("HTTPValidationError", "ValidationError"):
        needle = f"#/components/schemas/{name}"
        if needle not in paths_blob and needle not in other_blob:
            schemas.pop(name, None)


def enrich_openapi_schema(
    schema: dict[str, Any], *, portal_cookie_name: str = "zenith_portal_token"
) -> dict[str, Any]:
    """Mutate a FastAPI-generated OpenAPI dict in place and return it."""
    components = schema.setdefault("components", {})
    schemas = components.setdefault("schemas", {})
    schemas["ErrorEnvelope"] = _schema_from_model(ErrorEnvelope)
    schemas["TokenJsonRequest"] = _schema_from_model(TokenJsonRequest)

    paths = schema.setdefault("paths", {})
    _patch_authenticated_responses(paths)
    _replace_all_http_validation_errors(paths)
    _patch_token_request_body(paths)
    _patch_examples(paths)
    _add_security_schemes(components, cookie_name=portal_cookie_name)
    _strip_unused_validation_schemas(schema)

    # Clarify package vs URL versioning for partners.
    info = schema.setdefault("info", {})
    description = info.get("description") or ""
    version_note = (
        "\n\n**Versioning:** URL contract is `/api/v1`. "
        f"`info.version` is the Python package release ({__version__}). "
        "Errors always use the `ErrorEnvelope` schema "
        "(`code`, `message`, `request_id`)."
    )
    if "ErrorEnvelope" not in description:
        info["description"] = description + version_note
    return schema


def install_custom_openapi(application: FastAPI, *, portal_cookie_name: str) -> None:
    """Replace ``application.openapi`` with an enriched generator."""

    def custom_openapi() -> dict[str, Any]:
        if application.openapi_schema is not None:
            return application.openapi_schema
        schema = get_openapi(
            title=application.title,
            version=application.version,
            openapi_version=application.openapi_version,
            summary=application.summary,
            description=application.description,
            routes=application.routes,
            tags=application.openapi_tags,
            servers=application.servers,
            terms_of_service=application.terms_of_service,
            contact=application.contact,
            license_info=application.license_info,
            separate_input_output_schemas=application.separate_input_output_schemas,
        )
        enrich_openapi_schema(schema, portal_cookie_name=portal_cookie_name)
        application.openapi_schema = schema
        return application.openapi_schema

    application.openapi = custom_openapi  # type: ignore[method-assign]
