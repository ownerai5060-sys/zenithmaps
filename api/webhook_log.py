"""Durable webhook delivery log (SQLite / file).

When ``ZENITH_WEBHOOK_LOG_PATH`` is set, each delivery attempt is appended to a
SQLite table so operators can audit pings across restarts. Empty path keeps an
in-memory ring buffer (tests / ephemeral demos).

Shares the SQLite file with the subscription registry and retry queue
(see ``api.webhook_store``).
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

from api.config import get_settings
from api.webhook_store import connect, ensure_schema


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
                with connect(self._path) as conn:
                    ensure_schema(conn)

    def reset(self) -> None:
        with self._lock:
            self._memory.clear()
            if self._path:
                with connect(self._path) as conn:
                    ensure_schema(conn)
                    conn.execute("DELETE FROM webhook_deliveries")
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
                with connect(path) as conn:
                    ensure_schema(conn)
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
                with connect(path) as conn:
                    ensure_schema(conn)
                    sql = (
                        "SELECT * FROM webhook_deliveries"
                        + (" WHERE webhook_id = ?" if webhook_id else "")
                        + " ORDER BY occurred_at DESC LIMIT ?"
                    )
                    params: tuple[Any, ...] = (
                        (webhook_id, limit) if webhook_id else (limit,)
                    )
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
