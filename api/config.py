"""Runtime configuration for the Zenith platform API.

Secrets and allowlists are loaded from environment variables so local demos
and staging can differ without code changes. Demo API keys below are stubs
suitable for development only — never use them in production.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import FrozenSet


@dataclass(frozen=True)
class ApiKeyRecord:
    """One issued API key and its granted scopes."""

    key_id: str
    secret: str
    scopes: FrozenSet[str]
    label: str = ""


@dataclass(frozen=True)
class Settings:
    """Application settings (M3 auth, M6 allowlist, M7 CORS)."""

    app_name: str = "Zenith Maps Platform API"
    api_version: str = "v1"
    # Comma-separated browser origins allowed to call the API (M7).
    cors_origins: tuple[str, ...] = (
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8501",
        "http://127.0.0.1:8501",
    )
    # Hostnames (lowercase, no port) that may appear in WMS/tile URLs (M6).
    wms_allowed_hosts: FrozenSet[str] = frozenset(
        {
            "services.terrascope.be",
        }
    )
    # Optional layer-name allowlist per host. Empty set = any layer on that host.
    wms_allowed_layers: FrozenSet[str] = frozenset(
        {
            "WORLDCOVER_2020_MAP",
            "WORLDCOVER_2021_MAP",
        }
    )
    api_keys: tuple[ApiKeyRecord, ...] = field(default_factory=tuple)
    # When True, reject any outbound/proxy pattern that is not allowlisted.
    enforce_wms_allowlist: bool = True


def _parse_csv(value: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None or value.strip() == "":
        return default
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _default_demo_keys() -> tuple[ApiKeyRecord, ...]:
    """Workable stub keys for local/external-app demos (M3).

    Override with ZENITH_API_KEYS JSON for real deployments:
    [{"key_id":"demo","secret":"...","scopes":["layers:read"],"label":"Demo"}]
    """
    return (
        ApiKeyRecord(
            key_id="demo",
            secret="zenith_demo_key_layers_read",
            scopes=frozenset({"layers:read"}),
            label="Demo third-party app (layers:read)",
        ),
        ApiKeyRecord(
            key_id="readonly",
            secret="zenith_readonly_key",
            scopes=frozenset({"layers:read"}),
            label="Read-only integration key",
        ),
    )


def _load_api_keys_from_env() -> tuple[ApiKeyRecord, ...] | None:
    raw = os.getenv("ZENITH_API_KEYS")
    if not raw:
        return None
    data = json.loads(raw)
    records: list[ApiKeyRecord] = []
    for item in data:
        records.append(
            ApiKeyRecord(
                key_id=str(item["key_id"]),
                secret=str(item["secret"]),
                scopes=frozenset(item.get("scopes", ["layers:read"])),
                label=str(item.get("label", "")),
            )
        )
    return tuple(records)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings built from env + safe defaults."""
    keys = _load_api_keys_from_env() or _default_demo_keys()
    cors = _parse_csv(
        os.getenv("ZENITH_CORS_ORIGINS"),
        (
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8501",
            "http://127.0.0.1:8501",
        ),
    )
    hosts = _parse_csv(
        os.getenv("ZENITH_WMS_ALLOWED_HOSTS"),
        ("services.terrascope.be",),
    )
    layers = _parse_csv(
        os.getenv("ZENITH_WMS_ALLOWED_LAYERS"),
        ("WORLDCOVER_2020_MAP", "WORLDCOVER_2021_MAP"),
    )
    return Settings(
        cors_origins=cors,
        wms_allowed_hosts=frozenset(h.lower() for h in hosts),
        wms_allowed_layers=frozenset(layers),
        api_keys=keys,
        enforce_wms_allowlist=os.getenv("ZENITH_ENFORCE_WMS_ALLOWLIST", "true").lower()
        not in {"0", "false", "no"},
    )
