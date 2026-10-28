"""Minimal httpx client for Zenith `/api/v1` (N2).

Covers the happy-path catalog / features / tiles / health calls used by
third-party apps. Not a full OpenAPI-generated SDK.
"""

from __future__ import annotations

from typing import Any

import httpx


class ZenithMapsClient:
    """Thin wrapper around the Zenith Platform API."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        *,
        api_key: str | None = None,
        bearer_token: str | None = None,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        headers: dict[str, str] = {"Accept": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        self._client = httpx.Client(
            base_url=self.base_url,
            headers=headers,
            timeout=timeout,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ZenithMapsClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _get(self, path: str, **params: Any) -> Any:
        response = self._client.get(path, params={k: v for k, v in params.items() if v is not None})
        response.raise_for_status()
        if "application/json" in response.headers.get("content-type", ""):
            return response.json()
        return response.content

    def healthz(self, *, check_upstreams: bool = False) -> dict[str, Any]:
        return self._get("/healthz", check_upstreams=str(check_upstreams).lower())

    def list_layers(self) -> dict[str, Any]:
        return self._get("/api/v1/layers")

    def get_layer(self, layer_id: str) -> dict[str, Any]:
        return self._get(f"/api/v1/layers/{layer_id}")

    def get_legend(self, layer_id: str) -> dict[str, Any]:
        return self._get(f"/api/v1/layers/{layer_id}/legend")

    def get_features(
        self,
        layer_id: str,
        *,
        bbox: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        return self._get(
            f"/api/v1/layers/{layer_id}/features",
            bbox=bbox,
            limit=limit,
        )

    def list_tiles(self) -> dict[str, Any]:
        return self._get("/api/v1/tiles")

    def get_tiles(self, layer_id: str) -> dict[str, Any]:
        return self._get(f"/api/v1/tiles/{layer_id}")

    def check_url(self, url: str, layer_name: str | None = None) -> dict[str, Any]:
        response = self._client.post(
            "/api/v1/security/check-url",
            json={"url": url, "layer_name": layer_name},
        )
        response.raise_for_status()
        return response.json()

    def fetch_token(
        self,
        client_id: str,
        client_secret: str,
        *,
        grant_type: str = "client_credentials",
    ) -> dict[str, Any]:
        response = self._client.post(
            "/oauth/token",
            json={
                "grant_type": grant_type,
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        response.raise_for_status()
        return response.json()
