"""Runtime API-key store (create / list / revoke).

Keys are seeded from ``Settings.api_keys`` (env ``ZENITH_API_KEYS`` or demo
stubs). Admin endpoints mutate this in-process store. Persistence across
restarts still requires writing secrets back to the env/secret store — this
module is the management API surface, not a production vault.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, replace
from typing import Iterable

from api.config import ApiKeyRecord, get_settings


@dataclass
class StoredKey:
    """Mutable view of an issued key (secret retained server-side only)."""

    key_id: str
    secret: str
    scopes: frozenset[str]
    label: str = ""
    created_at: float = 0.0
    revoked: bool = False
    revoked_at: float | None = None

    def to_record(self) -> ApiKeyRecord:
        return ApiKeyRecord(
            key_id=self.key_id,
            secret=self.secret,
            scopes=self.scopes,
            label=self.label,
        )


class KeyStore:
    """Thread-safe in-memory key registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._keys: dict[str, StoredKey] = {}
        self._seeded = False

    def reset_and_seed(self, records: Iterable[ApiKeyRecord] | None = None) -> None:
        """Replace contents with ``records`` (or current settings). Used by tests."""
        source = list(records) if records is not None else list(get_settings().api_keys)
        with self._lock:
            self._keys = {}
            now = time.time()
            for record in source:
                self._keys[record.key_id] = StoredKey(
                    key_id=record.key_id,
                    secret=record.secret,
                    scopes=frozenset(record.scopes),
                    label=record.label,
                    created_at=now,
                    revoked=False,
                )
            self._seeded = True

    def ensure_seeded(self) -> None:
        with self._lock:
            if self._seeded:
                return
        self.reset_and_seed()

    def list_keys(self, *, include_revoked: bool = False) -> list[StoredKey]:
        self.ensure_seeded()
        with self._lock:
            items = list(self._keys.values())
        if not include_revoked:
            items = [k for k in items if not k.revoked]
        return sorted(items, key=lambda k: k.key_id)

    def get(self, key_id: str) -> StoredKey | None:
        self.ensure_seeded()
        with self._lock:
            return self._keys.get(key_id)

    def lookup_by_secret(self, secret: str) -> StoredKey | None:
        self.ensure_seeded()
        with self._lock:
            for stored in self._keys.values():
                if (
                    not stored.revoked
                    and len(stored.secret) == len(secret)
                    and secrets.compare_digest(stored.secret, secret)
                ):
                    return stored
        return None

    def create(
        self,
        *,
        key_id: str | None = None,
        scopes: Iterable[str],
        label: str = "",
        secret: str | None = None,
    ) -> StoredKey:
        self.ensure_seeded()
        scope_set = frozenset(scopes)
        if not scope_set:
            raise ValueError("At least one scope is required")
        new_id = key_id or f"key_{secrets.token_hex(4)}"
        new_secret = secret or f"zenith_{secrets.token_urlsafe(24)}"
        stored = StoredKey(
            key_id=new_id,
            secret=new_secret,
            scopes=scope_set,
            label=label,
            created_at=time.time(),
            revoked=False,
        )
        with self._lock:
            if new_id in self._keys and not self._keys[new_id].revoked:
                raise KeyError(f"key_id '{new_id}' already exists")
            self._keys[new_id] = stored
        return stored

    def revoke(self, key_id: str) -> StoredKey | None:
        self.ensure_seeded()
        with self._lock:
            stored = self._keys.get(key_id)
            if stored is None:
                return None
            if stored.revoked:
                return stored
            updated = replace(stored, revoked=True, revoked_at=time.time())
            self._keys[key_id] = updated
            return updated


_KEYSTORE = KeyStore()


def get_keystore() -> KeyStore:
    return _KEYSTORE
