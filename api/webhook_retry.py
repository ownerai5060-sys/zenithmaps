"""Retry queue + exponential backoff for failed webhook deliveries.

Failed POSTs are enqueued into the same SQLite file as the delivery log
(``ZENITH_WEBHOOK_LOG_PATH``). Process due items with::

    python -m api.webhook_worker
    # or
    from api.webhook_retry import process_due_retries
    process_due_retries()

Backoff: ``base * 2**(attempt-1)`` seconds, capped (defaults: 2s base, 300s cap,
5 max attempts). In-memory queue is used when no durable path is configured.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

import httpx

from api.config import get_settings
from api.webhook_store import connect, ensure_schema

logger = logging.getLogger("zenith.webhook_retry")

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BASE_DELAY_S = 2.0
DEFAULT_MAX_DELAY_S = 300.0


@dataclass
class RetryJob:
    id: str
    webhook_id: str
    event: str
    url: str
    payload: dict[str, Any]
    attempt_count: int
    max_attempts: int
    next_retry_at: float
    last_error: str | None
    status: str
    created_at: float
    updated_at: float


def compute_backoff_s(
    attempt_count: int,
    *,
    base_delay_s: float = DEFAULT_BASE_DELAY_S,
    max_delay_s: float = DEFAULT_MAX_DELAY_S,
) -> float:
    """Seconds to wait after ``attempt_count`` failures (1-based next delay)."""
    if attempt_count < 1:
        attempt_count = 1
    delay = base_delay_s * (2 ** (attempt_count - 1))
    return float(min(delay, max_delay_s))


class RetryQueue:
    """Thread-safe retry queue with optional SQLite durability."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._memory: dict[str, RetryJob] = {}
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
                    conn.execute("DELETE FROM webhook_retry_queue")
                    conn.commit()

    def _resolve_path(self) -> str:
        settings = get_settings()
        path = (settings.webhook_log_path or "").strip()
        self._path = path
        return path

    def enqueue(
        self,
        *,
        webhook_id: str,
        event: str,
        url: str,
        payload: dict[str, Any],
        error: str | None = None,
        max_attempts: int | None = None,
        base_delay_s: float | None = None,
    ) -> RetryJob:
        settings = get_settings()
        path = self._resolve_path()
        now = time.time()
        attempts = 1
        max_a = max_attempts or getattr(
            settings, "webhook_retry_max_attempts", DEFAULT_MAX_ATTEMPTS
        )
        base = base_delay_s or getattr(
            settings, "webhook_retry_base_delay_s", DEFAULT_BASE_DELAY_S
        )
        cap = getattr(settings, "webhook_retry_max_delay_s", DEFAULT_MAX_DELAY_S)
        job = RetryJob(
            id=f"rq_{uuid.uuid4().hex[:12]}",
            webhook_id=webhook_id,
            event=event,
            url=url,
            payload=payload,
            attempt_count=attempts,
            max_attempts=int(max_a),
            next_retry_at=now + compute_backoff_s(attempts, base_delay_s=base, max_delay_s=cap),
            last_error=error,
            status="pending",
            created_at=now,
            updated_at=now,
        )
        with self._lock:
            if path:
                with connect(path) as conn:
                    ensure_schema(conn)
                    conn.execute(
                        """
                        INSERT INTO webhook_retry_queue
                            (id, webhook_id, event, url, payload_json, attempt_count,
                             max_attempts, next_retry_at, last_error, status,
                             created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            job.id,
                            job.webhook_id,
                            job.event,
                            job.url,
                            json.dumps(job.payload, separators=(",", ":")),
                            job.attempt_count,
                            job.max_attempts,
                            job.next_retry_at,
                            job.last_error,
                            job.status,
                            job.created_at,
                            job.updated_at,
                        ),
                    )
                    conn.commit()
            else:
                self._memory[job.id] = job
        return job

    def list_due(self, *, now: float | None = None, limit: int = 50) -> list[RetryJob]:
        path = self._resolve_path()
        when = now if now is not None else time.time()
        with self._lock:
            if path:
                with connect(path) as conn:
                    ensure_schema(conn)
                    rows = conn.execute(
                        """
                        SELECT * FROM webhook_retry_queue
                        WHERE status = 'pending' AND next_retry_at <= ?
                        ORDER BY next_retry_at ASC
                        LIMIT ?
                        """,
                        (when, limit),
                    ).fetchall()
                return [_row_to_job(row) for row in rows]
            items = [
                j
                for j in self._memory.values()
                if j.status == "pending" and j.next_retry_at <= when
            ]
            items.sort(key=lambda j: j.next_retry_at)
            return items[:limit]

    def list_pending(self, *, limit: int = 100) -> list[RetryJob]:
        path = self._resolve_path()
        with self._lock:
            if path:
                with connect(path) as conn:
                    ensure_schema(conn)
                    rows = conn.execute(
                        """
                        SELECT * FROM webhook_retry_queue
                        WHERE status = 'pending'
                        ORDER BY next_retry_at ASC
                        LIMIT ?
                        """,
                        (limit,),
                    ).fetchall()
                return [_row_to_job(row) for row in rows]
            items = [j for j in self._memory.values() if j.status == "pending"]
            items.sort(key=lambda j: j.next_retry_at)
            return items[:limit]

    def mark_done(self, job_id: str) -> None:
        self._set_status(job_id, "done")

    def mark_dead(self, job_id: str, *, error: str | None = None) -> None:
        self._set_status(job_id, "dead", error=error)

    def reschedule(
        self,
        job: RetryJob,
        *,
        error: str | None,
        base_delay_s: float | None = None,
    ) -> RetryJob:
        settings = get_settings()
        path = self._resolve_path()
        now = time.time()
        next_attempt = job.attempt_count + 1
        base = base_delay_s or getattr(
            settings, "webhook_retry_base_delay_s", DEFAULT_BASE_DELAY_S
        )
        cap = getattr(settings, "webhook_retry_max_delay_s", DEFAULT_MAX_DELAY_S)
        updated = RetryJob(
            id=job.id,
            webhook_id=job.webhook_id,
            event=job.event,
            url=job.url,
            payload=job.payload,
            attempt_count=next_attempt,
            max_attempts=job.max_attempts,
            next_retry_at=now
            + compute_backoff_s(next_attempt, base_delay_s=base, max_delay_s=cap),
            last_error=error,
            status="pending",
            created_at=job.created_at,
            updated_at=now,
        )
        with self._lock:
            if path:
                with connect(path) as conn:
                    conn.execute(
                        """
                        UPDATE webhook_retry_queue
                        SET attempt_count = ?, next_retry_at = ?, last_error = ?,
                            status = 'pending', updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            updated.attempt_count,
                            updated.next_retry_at,
                            updated.last_error,
                            updated.updated_at,
                            updated.id,
                        ),
                    )
                    conn.commit()
            else:
                self._memory[updated.id] = updated
        return updated

    def _set_status(
        self, job_id: str, status: str, *, error: str | None = None
    ) -> None:
        path = self._resolve_path()
        now = time.time()
        with self._lock:
            if path:
                with connect(path) as conn:
                    conn.execute(
                        """
                        UPDATE webhook_retry_queue
                        SET status = ?, last_error = COALESCE(?, last_error),
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (status, error, now, job_id),
                    )
                    conn.commit()
            else:
                job = self._memory.get(job_id)
                if job is not None:
                    job.status = status
                    if error is not None:
                        job.last_error = error
                    job.updated_at = now


def _row_to_job(row: Any) -> RetryJob:
    payload = json.loads(row["payload_json"])
    return RetryJob(
        id=row["id"],
        webhook_id=row["webhook_id"],
        event=row["event"],
        url=row["url"],
        payload=payload if isinstance(payload, dict) else {},
        attempt_count=int(row["attempt_count"]),
        max_attempts=int(row["max_attempts"]),
        next_retry_at=float(row["next_retry_at"]),
        last_error=row["last_error"],
        status=row["status"],
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
    )


_QUEUE = RetryQueue()


def get_retry_queue() -> RetryQueue:
    return _QUEUE


def process_due_retries(
    *,
    now: float | None = None,
    limit: int = 50,
    timeout_s: float = 3.0,
    client: httpx.Client | None = None,
) -> dict[str, int]:
    """Process due retry jobs once. Returns counts: attempted/succeeded/failed/dead."""
    from api.webhooks import (
        SIGNATURE_HEADER,
        _delivery_headers,
        get_webhook_registry,
    )
    from api.webhook_log import get_delivery_log

    queue = get_retry_queue()
    due = queue.list_due(now=now, limit=limit)
    stats = {"attempted": 0, "succeeded": 0, "failed": 0, "dead": 0}
    if not due:
        return stats

    owns = client is None
    http = client or httpx.Client(timeout=timeout_s)
    try:
        for job in due:
            stats["attempted"] += 1
            body = json.dumps(
                job.payload, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            headers = _delivery_headers(job.event, body)
            signature = headers.get(SIGNATURE_HEADER)
            try:
                response = http.post(job.url, content=body, headers=headers)
                if response.status_code >= 400:
                    raise RuntimeError(f"HTTP {response.status_code}")
                get_webhook_registry().record_ping(job.webhook_id, status="ok", error=None)
                get_delivery_log().append(
                    webhook_id=job.webhook_id,
                    event=job.event,
                    url=job.url,
                    status="ok",
                    http_status=response.status_code,
                    error=None,
                    signature_header=signature,
                )
                queue.mark_done(job.id)
                stats["succeeded"] += 1
            except Exception as exc:  # noqa: BLE001
                err = str(exc)
                logger.warning(
                    "webhook retry failed id=%s job=%s: %s",
                    job.webhook_id,
                    job.id,
                    err,
                )
                get_webhook_registry().record_ping(
                    job.webhook_id, status="error", error=err
                )
                get_delivery_log().append(
                    webhook_id=job.webhook_id,
                    event=job.event,
                    url=job.url,
                    status="error",
                    http_status=None,
                    error=err,
                    signature_header=signature,
                )
                if job.attempt_count >= job.max_attempts:
                    queue.mark_dead(job.id, error=err)
                    stats["dead"] += 1
                else:
                    queue.reschedule(job, error=err)
                    stats["failed"] += 1
    finally:
        if owns:
            http.close()
    return stats
