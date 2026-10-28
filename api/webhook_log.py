"""Durable webhook delivery log (SQLite / file).

When ``ZENITH_WEBHOOK_LOG_PATH`` is set, each delivery attempt is appended to a
SQLite table so operators can audit pings across restarts. Empty path keeps an
in-memory ring buffer (tests / ephemeral demos).
"""

from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from api.config import get_settings


@dataclass
class DeliveryRecord:
    id: str
    webhook_id: str
    event: str
    url: str
    status: str
    http_status: int | None
    error: str | None
    occurred_at: float
    signature_header: str | None = None


class DeliveryLog:
    """Thread-safe delivery history with optional SQLite durability."""

    def __init__(self, *, memory_limit: int = 500) -> None:
        self._lock = threading.Lock()
        self._memory: list[DeliveryRecord] = []
        self._memory_limit = memory_limit
        self._path: str = ""

    @property
    def path(self) -> str:
        return self._path

    @property
    def durable(self) -> bool:
        return bool(self._path)

    def configure(self, path: str | None) -> None:
        with self._lock:
            self._path = (path or "").strip()
            if self._path:
                self._ensure_schema()

    def reset(self) -> None:
        with self._lock:
            self._memory.clear()
            if self._path:
                path = Path(self._path)
                if path.is_file():
                    path.unlink(missing_ok=True)
                self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        path = Path(self._path)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        if not self._path:
            return
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS webhook_deliveries (
                    id TEXT PRIMARY KEY,
                    webhook_id TEXT NOT NULL,
                    event TEXT NOT NULL,
                    url TEXT NOT NULL,
                    status TEXT NOT NULL,
                    http_status INTEGER,
                    error TEXT,
                    occurred_at REAL NOT NULL,
                    signature_header TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_wh_del_time "
                "ON webhook_deliveries(occurred_at DESC)"
            )
            conn.commit()

    def append(
        self,
        *,
        webhook_id: str,
        event: str,
        url: str,
        status: str,
        http_status: int | None = None,
        error: str | None = None,
        signature_header: str | None = None,
    ) -> DeliveryRecord:
        settings = get_settings()
        path = (settings.webhook_log_path or "").strip()
        record = DeliveryRecord(
            id=f"del_{uuid.uuid4().hex[:12]}",
            webhook_id=webhook_id,
            event=event,
            url=url,
            status=status,
            http_status=http_status,
            error=error,
            occurred_at=time.time(),
            signature_header=signature_header,
        )
        with self._lock:
            self._path = path
            self._memory.append(record)
            if len(self._memory) > self._memory_limit:
                self._memory = self._memory[-self._memory_limit :]
            if path:
                self._ensure_schema()
                with self._connect() as conn:
                    conn.execute(
                        """
                        INSERT INTO webhook_deliveries
                            (id, webhook_id, event, url, status, http_status,
                             error, occurred_at, signature_header)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record.id,
                            record.webhook_id,
                            record.event,
                            record.url,
                            record.status,
                            record.http_status,
                            record.error,
                            record.occurred_at,
                            record.signature_header,
                        ),
                    )
                    conn.commit()
        return record

    def list_recent(
        self,
        *,
        limit: int = 50,
        webhook_id: str | None = None,
    ) -> list[DeliveryRecord]:
        settings = get_settings()
        path = (settings.webhook_log_path or "").strip()
        with self._lock:
            self._path = path
            if path:
                self._ensure_schema()
                sql = (
                    "SELECT * FROM webhook_deliveries"
                    + (" WHERE webhook_id = ?" if webhook_id else "")
                    + " ORDER BY occurred_at DESC LIMIT ?"
                )
                params: tuple[Any, ...] = (
                    (webhook_id, limit) if webhook_id else (limit,)
                )
                with self._connect() as conn:
                    rows = conn.execute(sql, params).fetchall()
                return [
                    DeliveryRecord(
                        id=row["id"],
                        webhook_id=row["webhook_id"],
                        event=row["event"],
                        url=row["url"],
                        status=row["status"],
                        http_status=row["http_status"],
                        error=row["error"],
                        occurred_at=float(row["occurred_at"]),
                        signature_header=row["signature_header"],
                    )
                    for row in rows
                ]
            items = list(self._memory)
        if webhook_id:
            items = [r for r in items if r.webhook_id == webhook_id]
        items.sort(key=lambda r: r.occurred_at, reverse=True)
        return items[:limit]


_LOG = DeliveryLog()


def get_delivery_log() -> DeliveryLog:
    return _LOG
