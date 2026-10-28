"""Shared SQLite helpers for webhook subscriptions + delivery/retry tables.

When ``ZENITH_WEBHOOK_LOG_PATH`` is set, subscriptions, delivery attempts, and
the retry queue live in the same SQLite file so ops state survives restarts.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


def connect(path: str) -> sqlite3.Connection:
    """Open (and create parent dirs for) a webhook SQLite database."""
    db = Path(path)
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create webhook ops tables if missing (idempotent)."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS webhook_subscriptions (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            events TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            last_ping_at REAL,
            last_status TEXT,
            last_error TEXT,
            active INTEGER NOT NULL DEFAULT 1
        );

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
        );

        CREATE INDEX IF NOT EXISTS idx_wh_del_time
            ON webhook_deliveries(occurred_at DESC);

        CREATE TABLE IF NOT EXISTS webhook_retry_queue (
            id TEXT PRIMARY KEY,
            webhook_id TEXT NOT NULL,
            event TEXT NOT NULL,
            url TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 5,
            next_retry_at REAL NOT NULL,
            last_error TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_wh_retry_due
            ON webhook_retry_queue(status, next_retry_at);
        """
    )
    conn.commit()
