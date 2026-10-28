"""Minimal HTTP client for the Zenith platform API (`/api/v1`).

Used by Streamlit pages so the UI consumes the same catalog/legend contract
as external apps (S6). Secrets should come from env / Streamlit secrets —
never hard-code production keys.
"""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx

DEFAULT_BASE_URL = os.getenv("ZENITH_API_BASE_URL", "http://127.0.0.1:8000")
DEFAULT_API_KEY = os.getenv("ZENITH_API_KEY", "zenith_demo_key_layers_read")


class ZenithApiError(RuntimeError):
    """Raised when the platform API returns an error envelope or transport fails."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.request_id = request_id


class ZenithApiClient:
    """Thin wrapper around ``httpx`` for catalog and legend endpoints."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        timeout_s: float = 10.0,
    ) -> None:
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.api_key = api_key or DEFAULT_API_KEY
        self.timeout_s = timeout_s

    def _headers(self) -> dict[str, str]:
        return {"X-API-Key": self.api_key, "Accept": "application/json"}

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = f"{self.base_url}{path}"
        try:
            with httpx.Client(timeout=self.timeout_s) as client:
                response = client.request(
                    method, url, headers=self._headers(), **kwargs
                )
        except httpx.HTTPError as exc:
            raise ZenithApiError(f"API transport error: {exc}") from exc

        if response.status_code >= 400:
            code = None
            message = response.text
            request_id = response.headers.get("X-Request-ID")
            try:
                body = response.json()
                code = body.get("code")
                message = body.get("message", message)
                request_id = body.get("request_id", request_id)
            except Exception:
                pass
            raise ZenithApiError(
                message,
                status_code=response.status_code,
                code=code,
                request_id=request_id,
            )
        if response.headers.get("content-type", "").startswith("application/json"):
            return response.json()
        return response.content

    def healthz(self, *, check_upstreams: bool = False) -> dict[str, Any]:
        return self._request(
            "GET",
            "/healthz",
            params={"check_upstreams": str(check_upstreams).lower()},
        )

    def list_layers(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/layers")

    def get_layer(self, layer_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/layers/{layer_id}")

    def get_legend(self, layer_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/layers/{layer_id}/legend")

    def legend_entries_as_dict(self, layer_id: str) -> Optional[dict[str, str]]:
        """Return ``{label: color}`` suitable for ``leafmap.add_legend``."""
        legend = self.get_legend(layer_id)
        entries = legend.get("entries") or []
        if not entries:
            return None
        return {str(e["label"]): str(e["color"]) for e in entries}

    def find_layer_id_for_wms(
        self, service_url: str, layer_name: str
    ) -> Optional[str]:
        """Match a WMS URL+layer name to a catalog layer id, if any."""
        listing = self.list_layers()
        for item in listing.get("items", []):
            detail = self.get_layer(item["id"])
            wms = detail.get("wms") or {}
            if not wms:
                continue
            if (
                str(wms.get("service_url", "")).rstrip("/") == service_url.rstrip("/")
                and wms.get("layer_name") == layer_name
            ):
                return detail["id"]
        return None

    def list_api_keys(self, *, include_revoked: bool = False) -> dict[str, Any]:
        """List API keys (``keys:read`` or ``admin:keys``). Secrets omitted."""
        return self._request(
            "GET",
            "/api/v1/admin/keys",
            params={"include_revoked": str(include_revoked).lower()},
        )

    def create_api_key(
        self,
        *,
        key_id: str | None = None,
        scopes: list[str] | None = None,
        label: str = "",
    ) -> dict[str, Any]:
        """Create an API key; secret is returned once (requires ``admin:keys``)."""
        payload: dict[str, Any] = {
            "scopes": scopes or ["layers:read"],
            "label": label,
        }
        if key_id:
            payload["key_id"] = key_id
        return self._request("POST", "/api/v1/admin/keys", json=payload)

    def revoke_api_key(self, key_id: str) -> dict[str, Any]:
        """Revoke an API key (requires ``admin:keys``)."""
        return self._request("DELETE", f"/api/v1/admin/keys/{key_id}")

    def rotate_api_key(self, key_id: str) -> dict[str, Any]:
        """Rotate an API key secret (requires ``admin:keys``; secret once)."""
        return self._request("POST", f"/api/v1/admin/keys/{key_id}/rotate")
