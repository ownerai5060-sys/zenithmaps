"""API-key store with optional durable SQLite vault.

Keys are seeded from ``Settings.api_keys`` (env ``ZENITH_API_KEYS`` or demo
stubs). When ``ZENITH_KEY_VAULT_PATH`` points at a SQLite file, create/revoke
mutations persist across process restarts. Admin HTTP CRUD is unchanged.

Unset / empty vault path → in-process memory only (tests / ephemeral demos).
"""

from __future__ import annotations

import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
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
    """Thread-safe key registry with optional SQLite durability."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._keys: dict[str, StoredKey] = {}
        self._seeded = False
        self._vault_path: str = ""

    @property
    def vault_path(self) -> str:
        return self._vault_path

    @property
    def durable(self) -> bool:
        return bool(self._vault_path)

    def _connect(self) -> sqlite3.Connection:
        path = Path(self._vault_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                secret TEXT NOT NULL,
                scopes TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                revoked_at REAL
            )
            """
        )
        conn.commit()
        return conn

    def _persist_unlocked(self, stored: StoredKey) -> None:
        if not self._vault_path:
            return
        scopes = " ".join(sorted(stored.scopes))
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO api_keys
                    (key_id, secret, scopes, label, created_at, revoked, revoked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(key_id) DO UPDATE SET
                    secret=excluded.secret,
                    scopes=excluded.scopes,
                    label=excluded.label,
                    created_at=excluded.created_at,
                    revoked=excluded.revoked,
                    revoked_at=excluded.revoked_at
                """,
                (
                    stored.key_id,
                    stored.secret,
                    scopes,
                    stored.label,
                    stored.created_at,
                    1 if stored.revoked else 0,
                    stored.revoked_at,
                ),
            )
            conn.commit()

    def _load_from_vault(self) -> dict[str, StoredKey]:
        loaded: dict[str, StoredKey] = {}
        if not self._vault_path:
            return loaded
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM api_keys").fetchall()
        for row in rows:
            scopes = frozenset(s for s in str(row["scopes"]).split() if s)
            loaded[row["key_id"]] = StoredKey(
                key_id=row["key_id"],
                secret=row["secret"],
                scopes=scopes,
                label=row["label"] or "",
                created_at=float(row["created_at"] or 0.0),
                revoked=bool(row["revoked"]),
                revoked_at=float(row["revoked_at"]) if row["revoked_at"] else None,
            )
        return loaded

    def configure_vault(self, path: str | None) -> None:
        """Set durable path (call before seed). Empty disables durability."""
        with self._lock:
            self._vault_path = (path or "").strip()

    def reset_and_seed(self, records: Iterable[ApiKeyRecord] | None = None) -> None:
        """Replace contents from vault (if any) merged with ``records``/settings.

        Vault rows win for existing ``key_id`` values so runtime creates survive
        restart. Seed records fill gaps (fresh vault / memory mode).
        """
        settings = get_settings()
        vault = (settings.key_vault_path or "").strip()
        source = list(records) if records is not None else list(settings.api_keys)
        with self._lock:
            self._vault_path = vault
            self._keys = {}
            now = time.time()
            persisted = self._load_from_vault() if vault else {}
            for record in source:
                if record.key_id in persisted:
                    continue
                stored = StoredKey(
                    key_id=record.key_id,
                    secret=record.secret,
                    scopes=frozenset(record.scopes),
                    label=record.label,
                    created_at=now,
                    revoked=False,
                )
                self._keys[record.key_id] = stored
                if vault:
                    self._persist_unlocked(stored)
            for key_id, stored in persisted.items():
                self._keys[key_id] = stored
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
            self._persist_unlocked(stored)
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
            self._persist_unlocked(updated)
            return updated


_KEYSTORE = KeyStore()


def get_keystore() -> KeyStore:
    return _KEYSTORE
