"""Unit tests for deploy/egress-allowlist sample proxy helpers."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROXY_PATH = Path(__file__).resolve().parents[1] / "deploy" / "egress-allowlist" / "proxy.py"


def _load_proxy():
    spec = importlib.util.spec_from_file_location("egress_allowlist_proxy", PROXY_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


proxy = _load_proxy()


def test_resolve_allowlisted_public_ip() -> None:
    infos = [
        (2, 1, 6, "", ("93.184.216.34", 443)),
    ]
    with patch.object(proxy.socket, "getaddrinfo", return_value=infos):
        ip, port = proxy.resolve_and_check(
            "hooks.example.com", 443, frozenset({"hooks.example.com"})
        )
    assert ip == "93.184.216.34"
    assert port == 443


def test_resolve_rejects_non_allowlisted() -> None:
    with pytest.raises(ValueError, match="host_not_allowlisted"):
        proxy.resolve_and_check("evil.example", 443, frozenset({"hooks.example.com"}))


def test_resolve_rejects_empty_allowlist() -> None:
    with pytest.raises(ValueError, match="host_not_allowlisted"):
        proxy.resolve_and_check("hooks.example.com", 443, frozenset())


def test_resolve_rejects_private_after_dns() -> None:
    infos = [(2, 1, 6, "", ("10.0.0.5", 443))]
    with patch.object(proxy.socket, "getaddrinfo", return_value=infos):
        with pytest.raises(ValueError, match="blocked_resolved_ip"):
            proxy.resolve_and_check(
                "hooks.example.com", 443, frozenset({"hooks.example.com"})
            )


def test_resolve_rejects_metadata_host() -> None:
    with pytest.raises(ValueError, match="blocked_metadata"):
        proxy.resolve_and_check(
            "metadata.google.internal", 80, frozenset({"metadata.google.internal"})
        )
