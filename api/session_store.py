"""Shared SSO session + IdP refresh persistence.

Backends (``ZENITH_SESSION_STORE_BACKEND``):

* ``memory`` — process-local (default when no path/Redis)
* ``sqlite`` / file — ``ZENITH_SESSION_STORE_PATH`` (cluster-friendly single-node
  durable fallback; also used when ``auto`` + path set)
* ``redis`` — ``ZENITH_REDIS_URL`` when the ``redis`` package is installed
* ``auto`` — Redis if URL works, else SQLite if path set, else memory

Portal cookies hold an opaque ``session_id`` (not the raw access / IdP refresh).
IdP refresh tokens are stored server-side only and mapped to opaque refresh
handles returned to clients.
"""

from __future__ import annotations

import json
import logging
import secrets
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from api.config import Settings, get_settings

logger = logging.getLogger("zenith.api.session_store")

SessionBackendName = Literal["memory", "sqlite", "redis", "auto"]


@dataclass(frozen=True)
class SessionRecord:
    """Browser SSO session (cookie value = session_id)."""

    session_id: str
    key_id: str
    scopes: frozenset[str]
    label: str
    expires_at: float
    access_token: str = ""
    idp_access_token: str = ""
    idp_refresh_token: str = ""
    created_at: float = 0.0

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at

    def to_public_dict(self) -> dict[str, Any]:
        """JSON-safe view without IdP refresh material."""
        return {
            "session_id": self.session_id,
            "key_id": self.key_id,
            "scopes": sorted(self.scopes),
            "label": self.label,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
            "has_idp_refresh": bool(self.idp_refresh_token),
        }


@dataclass(frozen=True)
class RefreshRecord:
    """Opaque refresh handle → local stub or server-held IdP refresh."""

    handle: str
    key_id: str
    scopes: frozenset[str]
    label: str
    expires_at: float
    is_idp: bool = False
    idp_refresh_token: str = ""
    created_at: float = 0.0

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


def _serialize_session(rec: SessionRecord) -> str:
    payload = {
        **asdict(rec),
        "scopes": sorted(rec.scopes),
    }
    return json.dumps(payload, separators=(",", ":"))


def _deserialize_session(raw: str) -> SessionRecord:
    data = json.loads(raw)
    return SessionRecord(
        session_id=str(data["session_id"]),
        key_id=str(data["key_id"]),
        scopes=frozenset(data.get("scopes") or []),
        label=str(data.get("label") or ""),
        expires_at=float(data["expires_at"]),
        access_token=str(data.get("access_token") or ""),
        idp_access_token=str(data.get("idp_access_token") or ""),
        idp_refresh_token=str(data.get("idp_refresh_token") or ""),
        created_at=float(data.get("created_at") or 0.0),
    )


def _serialize_refresh(rec: RefreshRecord) -> str:
    payload = {
        **asdict(rec),
        "scopes": sorted(rec.scopes),
    }
    return json.dumps(payload, separators=(",", ":"))


def _deserialize_refresh(raw: str) -> RefreshRecord:
    data = json.loads(raw)
    return RefreshRecord(
        handle=str(data["handle"]),
        key_id=str(data["key_id"]),
        scopes=frozenset(data.get("scopes") or []),
        label=str(data.get("label") or ""),
        expires_at=float(data["expires_at"]),
        is_idp=bool(data.get("is_idp")),
        idp_refresh_token=str(data.get("idp_refresh_token") or ""),
        created_at=float(data.get("created_at") or 0.0),
    )


class SessionStoreBackend(ABC):
    """Pluggable session + refresh persistence."""

    name: str = "abstract"

    @abstractmethod
    def reset(self) -> None: ...

    @abstractmethod
    def put_session(self, record: SessionRecord) -> None: ...

    @abstractmethod
    def get_session(self, session_id: str) -> SessionRecord | None: ...

    @abstractmethod
    def delete_session(self, session_id: str) -> bool: ...

    @abstractmethod
    def put_refresh(self, record: RefreshRecord) -> None: ...

    @abstractmethod
    def get_refresh(self, handle: str) -> RefreshRecord | None: ...

    @abstractmethod
    def delete_refresh(self, handle: str) -> bool: ...


class InMemorySessionStore(SessionStoreBackend):
    name = "memory"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, SessionRecord] = {}
        self._refresh: dict[str, RefreshRecord] = {}

    def reset(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._refresh.clear()

    def put_session(self, record: SessionRecord) -> None:
        with self._lock:
            self._sessions[record.session_id] = record

    def get_session(self, session_id: str) -> SessionRecord | None:
        with self._lock:
            rec = self._sessions.get(session_id)
            if rec is None:
                return None
            if rec.expired:
                del self._sessions[session_id]
                return None
            return rec

    def delete_session(self, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def put_refresh(self, record: RefreshRecord) -> None:
        with self._lock:
            self._refresh[record.handle] = record

    def get_refresh(self, handle: str) -> RefreshRecord | None:
        with self._lock:
            rec = self._refresh.get(handle)
            if rec is None:
                return None
            if rec.expired:
                del self._refresh[handle]
                return None
            return rec

    def delete_refresh(self, handle: str) -> bool:
        with self._lock:
            return self._refresh.pop(handle, None) is not None


class SqliteSessionStore(SessionStoreBackend):
    """SQLite / file-backed session + IdP refresh store."""

    name = "sqlite"

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        db = Path(self._path)
        db.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sso_sessions (
                    session_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sso_refresh (
                    handle TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    expires_at REAL NOT NULL
                );
                """
            )

    def reset(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM sso_sessions")
            conn.execute("DELETE FROM sso_refresh")

    def put_session(self, record: SessionRecord) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sso_sessions (session_id, payload, expires_at)
                VALUES (?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    payload=excluded.payload,
                    expires_at=excluded.expires_at
                """,
                (record.session_id, _serialize_session(record), record.expires_at),
            )

    def get_session(self, session_id: str) -> SessionRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT payload, expires_at FROM sso_sessions WHERE session_id=?",
                (session_id,),
            ).fetchone()
            if row is None:
                return None
            if float(row["expires_at"]) <= time.time():
                conn.execute(
                    "DELETE FROM sso_sessions WHERE session_id=?", (session_id,)
                )
                return None
            return _deserialize_session(str(row["payload"]))

    def delete_session(self, session_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM sso_sessions WHERE session_id=?", (session_id,)
            )
            return cur.rowcount > 0

    def put_refresh(self, record: RefreshRecord) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sso_refresh (handle, payload, expires_at)
                VALUES (?, ?, ?)
                ON CONFLICT(handle) DO UPDATE SET
                    payload=excluded.payload,
                    expires_at=excluded.expires_at
                """,
                (record.handle, _serialize_refresh(record), record.expires_at),
            )

    def get_refresh(self, handle: str) -> RefreshRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT payload, expires_at FROM sso_refresh WHERE handle=?",
                (handle,),
            ).fetchone()
            if row is None:
                return None
            if float(row["expires_at"]) <= time.time():
                conn.execute("DELETE FROM sso_refresh WHERE handle=?", (handle,))
                return None
            return _deserialize_refresh(str(row["payload"]))

    def delete_refresh(self, handle: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM sso_refresh WHERE handle=?", (handle,))
            return cur.rowcount > 0


class RedisSessionStore(SessionStoreBackend):
    """Redis-backed session + refresh (shared across replicas)."""

    name = "redis"
    _SESSION_PREFIX = "zenith:sso:session:"
    _REFRESH_PREFIX = "zenith:sso:refresh:"

    def __init__(self, redis_url: str) -> None:
        try:
            import redis  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "redis package is not installed; pip install redis"
            ) from exc
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._client.ping()

    def reset(self) -> None:
        for key in self._client.scan_iter(match="zenith:sso:*", count=100):
            self._client.delete(key)

    def put_session(self, record: SessionRecord) -> None:
        ttl = max(1, int(record.expires_at - time.time()))
        self._client.setex(
            f"{self._SESSION_PREFIX}{record.session_id}",
            ttl,
            _serialize_session(record),
        )

    def get_session(self, session_id: str) -> SessionRecord | None:
        raw = self._client.get(f"{self._SESSION_PREFIX}{session_id}")
        if not raw:
            return None
        rec = _deserialize_session(str(raw))
        if rec.expired:
            self.delete_session(session_id)
            return None
        return rec

    def delete_session(self, session_id: str) -> bool:
        return bool(self._client.delete(f"{self._SESSION_PREFIX}{session_id}"))

    def put_refresh(self, record: RefreshRecord) -> None:
        ttl = max(1, int(record.expires_at - time.time()))
        self._client.setex(
            f"{self._REFRESH_PREFIX}{record.handle}",
            ttl,
            _serialize_refresh(record),
        )

    def get_refresh(self, handle: str) -> RefreshRecord | None:
        raw = self._client.get(f"{self._REFRESH_PREFIX}{handle}")
        if not raw:
            return None
        rec = _deserialize_refresh(str(raw))
        if rec.expired:
            self.delete_refresh(handle)
            return None
        return rec

    def delete_refresh(self, handle: str) -> bool:
        return bool(self._client.delete(f"{self._REFRESH_PREFIX}{handle}"))


class SessionStore:
    """Facade used by auth / oauth routers."""

    def __init__(self, backend: SessionStoreBackend | None = None) -> None:
        self._backend = backend or InMemorySessionStore()

    @property
    def backend_name(self) -> str:
        return self._backend.name

    def configure(self, backend: SessionStoreBackend) -> None:
        self._backend = backend

    def reset(self) -> None:
        self._backend.reset()

    def create_session(
        self,
        *,
        key_id: str,
        scopes: frozenset[str],
        label: str,
        ttl_s: int,
        access_token: str = "",
        idp_access_token: str = "",
        idp_refresh_token: str = "",
    ) -> SessionRecord:
        now = time.time()
        record = SessionRecord(
            session_id=secrets.token_urlsafe(32),
            key_id=key_id,
            scopes=scopes,
            label=label,
            expires_at=now + max(60, ttl_s),
            access_token=access_token,
            idp_access_token=idp_access_token,
            idp_refresh_token=idp_refresh_token,
            created_at=now,
        )
        self._backend.put_session(record)
        return record

    def get_session(self, session_id: str) -> SessionRecord | None:
        if not session_id:
            return None
        return self._backend.get_session(session_id)

    def delete_session(self, session_id: str) -> bool:
        if not session_id:
            return False
        return self._backend.delete_session(session_id)

    def store_idp_refresh(
        self,
        *,
        idp_refresh_token: str,
        key_id: str,
        scopes: frozenset[str],
        label: str,
        ttl_s: int,
    ) -> RefreshRecord:
        """Persist IdP refresh server-side; return opaque client handle."""
        now = time.time()
        record = RefreshRecord(
            handle=secrets.token_urlsafe(32),
            key_id=key_id,
            scopes=scopes,
            label=label,
            expires_at=now + max(300, ttl_s),
            is_idp=True,
            idp_refresh_token=idp_refresh_token,
            created_at=now,
        )
        self._backend.put_refresh(record)
        return record

    def consume_idp_refresh(self, handle: str) -> RefreshRecord | None:
        """Pop an IdP refresh handle (rotation: caller re-stores if needed)."""
        rec = self._backend.get_refresh(handle)
        if rec is None or not rec.is_idp:
            return None
        self._backend.delete_refresh(handle)
        return rec

    def get_idp_refresh(self, handle: str) -> RefreshRecord | None:
        rec = self._backend.get_refresh(handle)
        if rec is None or not rec.is_idp:
            return None
        return rec


_STORE = SessionStore()
_STORE_LOCK = threading.Lock()


def _build_backend(settings: Settings | None = None) -> SessionStoreBackend:
    settings = settings or get_settings()
    choice = (settings.session_store_backend or "auto").strip().lower()
    path = (settings.session_store_path or "").strip()
    redis_url = (settings.redis_url or "").strip()

    def try_redis() -> SessionStoreBackend | None:
        if not redis_url:
            return None
        try:
            backend = RedisSessionStore(redis_url)
            logger.info("SSO session store backend: redis")
            return backend
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Redis session store unavailable (%s); trying fallback", exc
            )
            return None

    def try_sqlite() -> SessionStoreBackend | None:
        if not path:
            return None
        logger.info("SSO session store backend: sqlite path=%s", path)
        return SqliteSessionStore(path)

    if choice == "memory":
        logger.info("SSO session store backend: memory")
        return InMemorySessionStore()
    if choice == "redis":
        return try_redis() or try_sqlite() or InMemorySessionStore()
    if choice == "sqlite":
        return try_sqlite() or InMemorySessionStore()
    # auto
    return try_redis() or try_sqlite() or InMemorySessionStore()


def get_session_store() -> SessionStore:
    return _STORE


def reset_session_store(settings: Settings | None = None) -> SessionStore:
    """Rebuild backend from settings (startup / tests)."""
    with _STORE_LOCK:
        _STORE.configure(_build_backend(settings))
        _STORE.reset()
        return _STORE


def configure_session_store(settings: Settings | None = None) -> SessionStore:
    """Configure without wiping (startup when longevity matters)."""
    with _STORE_LOCK:
        _STORE.configure(_build_backend(settings))
        return _STORE
