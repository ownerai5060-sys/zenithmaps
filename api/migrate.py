"""Lightweight SQL migration runner for optional PostGIS fixtures.

Applies numbered ``sql/*.sql`` files in lexical order against
``ZENITH_DATABASE_URL``, tracking applied versions in
``zenith_schema_migrations``. This is **not** Alembic — no autogenerate,
no downgrade graph — just a deterministic apply path for staging/ops.

Usage::

    python -m api.migrate              # apply pending
    python -m api.migrate --dry-run    # list pending only
    python -m api.migrate --sql-dir sql

Without ``ZENITH_DATABASE_URL`` the CLI exits non-zero with a clear message
(fixtures/stubs still work without PostGIS).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

_VERSION_RE = re.compile(r"^(\d+)_")
_DEFAULT_SQL_DIR = Path(__file__).resolve().parent.parent / "sql"
_MIGRATIONS_DDL = """
CREATE TABLE IF NOT EXISTS zenith_schema_migrations (
    version     TEXT PRIMARY KEY,
    filename    TEXT NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


def list_migration_files(sql_dir: Path | None = None) -> list[tuple[str, Path]]:
    """Return ``(version, path)`` sorted by version for ``NNN_name.sql`` files."""
    root = sql_dir or _DEFAULT_SQL_DIR
    found: list[tuple[str, Path]] = []
    if not root.is_dir():
        return found
    for path in sorted(root.glob("*.sql")):
        match = _VERSION_RE.match(path.name)
        if not match:
            continue
        found.append((match.group(1), path))
    return found


def _connect(dsn: str):
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - env dependent
        raise SystemExit(
            "psycopg is required for migrations; "
            "pip install 'psycopg[binary]==3.2.9'"
        ) from exc
    return psycopg.connect(dsn)


def applied_versions(conn) -> set[str]:
    with conn.cursor() as cur:
        cur.execute(_MIGRATIONS_DDL)
        cur.execute("SELECT version FROM zenith_schema_migrations")
        rows = cur.fetchall()
    conn.commit()
    return {str(r[0]) for r in rows}


def apply_pending(
    dsn: str,
    *,
    sql_dir: Path | None = None,
    dry_run: bool = False,
) -> list[str]:
    """Apply pending migrations; return list of applied (or would-apply) filenames."""
    migrations = list_migration_files(sql_dir)
    if not migrations:
        return []

    conn = _connect(dsn)
    try:
        done = applied_versions(conn)
        pending = [(ver, path) for ver, path in migrations if ver not in done]
        if dry_run:
            return [p.name for _, p in pending]

        applied: list[str] = []
        for ver, path in pending:
            sql = path.read_text(encoding="utf-8")
            with conn.cursor() as cur:
                cur.execute(sql)
                cur.execute(
                    """
                    INSERT INTO zenith_schema_migrations (version, filename)
                    VALUES (%s, %s)
                    ON CONFLICT (version) DO NOTHING
                    """,
                    (ver, path.name),
                )
            conn.commit()
            applied.append(path.name)
        return applied
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Apply Zenith sql/*.sql migrations to PostGIS (lightweight)."
    )
    parser.add_argument(
        "--sql-dir",
        type=Path,
        default=_DEFAULT_SQL_DIR,
        help="Directory of NNN_*.sql files (default: repo sql/)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List pending migrations without applying",
    )
    parser.add_argument(
        "--database-url",
        default="",
        help="Override ZENITH_DATABASE_URL",
    )
    args = parser.parse_args(argv)

    dsn = (args.database_url or os.getenv("ZENITH_DATABASE_URL", "")).strip()
    if not dsn:
        print(
            "ZENITH_DATABASE_URL is not set — nothing to migrate. "
            "WFS-lite will use fixtures/stubs until PostGIS is configured.",
            file=sys.stderr,
        )
        return 2

    try:
        result = apply_pending(dsn, sql_dir=args.sql_dir, dry_run=args.dry_run)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"migration failed: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        if not result:
            print("No pending migrations.")
        else:
            print("Pending:")
            for name in result:
                print(f"  - {name}")
        return 0

    if not result:
        print("Schema already up to date.")
    else:
        print("Applied:")
        for name in result:
            print(f"  - {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
