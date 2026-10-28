"""Policy-driven API-key rotation (age-based).

Policy is stored next to the durable key vault when ``ZENITH_KEY_VAULT_PATH``
is set (SQLite table ``rotation_policy``); otherwise in-process memory.

Apply due rotations via:

* Admin: ``GET/PUT /api/v1/admin/keys/rotation-policy`` and
  ``POST /api/v1/admin/keys/rotation-policy/run``
* Cron CLI: ``python -m api.rotation_worker``
* Optional in-process lite scheduler (``ZENITH_ROTATION_SCHEDULER_ENABLED``)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from api.config import get_settings
from api.keystore import StoredKey, get_keystore
from api.oauth import get_token_store

logger = logging.getLogger("zenith.api.rotation_policy")

# Demo/sandbox seed key ids — excluded by default so local stubs are not churned.
_DEFAULT_EXCLUDE = ("demo", "readonly", "operator", "admin")


@dataclass
class RotationPolicy:
    """When enabled, rotate active keys whose secret age exceeds ``max_age_days``."""

    enabled: bool = False
    max_age_days: float = 90.0
    # Empty include list = all non-revoked keys (minus exclude).
    include_key_ids: tuple[str, ...] = ()
    exclude_key_ids: tuple[str, ...] = field(
        default_factory=lambda: tuple(_DEFAULT_EXCLUDE)
    )
    updated_at: float = 0.0

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "max_age_days": self.max_age_days,
            "include_key_ids": list(self.include_key_ids),
            "exclude_key_ids": list(self.exclude_key_ids),
            "updated_at": self.updated_at or None,
        }


@dataclass
class RotationResult:
    key_id: str
    status: str  # rotated | skipped | dry_run | error
    detail: str = ""
    secret: str | None = None
    previous_tokens_revoked: int = 0


@dataclass
class RotationRunReport:
    dry_run: bool
    considered: int
    rotated: int
    skipped: int
    results: list[RotationResult]
    policy: dict[str, Any]

    def to_public_dict(self, *, include_secrets: bool = False) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        for r in self.results:
            row: dict[str, Any] = {
                "key_id": r.key_id,
                "status": r.status,
                "detail": r.detail,
                "previous_tokens_revoked": r.previous_tokens_revoked,
            }
            if include_secrets and r.secret:
                row["secret"] = r.secret
            items.append(row)
        return {
            "dry_run": self.dry_run,
            "considered": self.considered,
            "rotated": self.rotated,
            "skipped": self.skipped,
            "results": items,
            "policy": self.policy,
        }


class RotationPolicyStore:
    """Thread-safe policy registry with optional SQLite durability."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._policy = RotationPolicy()
        self._path: str = ""

    def configure(self, path: str | None = None) -> None:
        settings = get_settings()
        resolved = (path if path is not None else settings.key_vault_path or "").strip()
        with self._lock:
            self._path = resolved
            if resolved:
                self._policy = self._load(resolved)
            # else keep current in-memory policy

    def reset(self, policy: RotationPolicy | None = None) -> None:
        with self._lock:
            self._policy = policy or RotationPolicy()
            if self._path:
                self._persist(self._policy)

    def get(self) -> RotationPolicy:
        with self._lock:
            return replace(
                self._policy,
                include_key_ids=tuple(self._policy.include_key_ids),
                exclude_key_ids=tuple(self._policy.exclude_key_ids),
            )

    def update(
        self,
        *,
        enabled: bool | None = None,
        max_age_days: float | None = None,
        include_key_ids: list[str] | None = None,
        exclude_key_ids: list[str] | None = None,
    ) -> RotationPolicy:
        with self._lock:
            current = self._policy
            new_include = (
                tuple(k.strip() for k in include_key_ids if k and k.strip())
                if include_key_ids is not None
                else current.include_key_ids
            )
            new_exclude = (
                tuple(k.strip() for k in exclude_key_ids if k and k.strip())
                if exclude_key_ids is not None
                else current.exclude_key_ids
            )
            age = (
                float(max_age_days)
                if max_age_days is not None
                else current.max_age_days
            )
            if age <= 0:
                raise ValueError("max_age_days must be > 0")
            updated = RotationPolicy(
                enabled=current.enabled if enabled is None else bool(enabled),
                max_age_days=age,
                include_key_ids=new_include,
                exclude_key_ids=new_exclude,
                updated_at=time.time(),
            )
            self._policy = updated
            if self._path:
                self._persist(updated)
            return replace(
                updated,
                include_key_ids=tuple(updated.include_key_ids),
                exclude_key_ids=tuple(updated.exclude_key_ids),
            )

    def _connect(self, path: str) -> sqlite3.Connection:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(p), check_same_thread=False)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rotation_policy (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                payload TEXT NOT NULL
            )
            """
        )
        conn.commit()
        return conn

    def _persist(self, policy: RotationPolicy) -> None:
        if not self._path:
            return
        payload = json.dumps(
            {
                "enabled": policy.enabled,
                "max_age_days": policy.max_age_days,
                "include_key_ids": list(policy.include_key_ids),
                "exclude_key_ids": list(policy.exclude_key_ids),
                "updated_at": policy.updated_at,
            }
        )
        with self._connect(self._path) as conn:
            conn.execute(
                """
                INSERT INTO rotation_policy (id, payload) VALUES (1, ?)
                ON CONFLICT(id) DO UPDATE SET payload=excluded.payload
                """,
                (payload,),
            )
            conn.commit()

    def _load(self, path: str) -> RotationPolicy:
        try:
            with self._connect(path) as conn:
                row = conn.execute(
                    "SELECT payload FROM rotation_policy WHERE id = 1"
                ).fetchone()
        except sqlite3.Error as exc:
            logger.warning("rotation policy load failed (%s); using defaults", exc)
            return RotationPolicy()
        if not row:
            return RotationPolicy()
        try:
            data = json.loads(row[0])
            return RotationPolicy(
                enabled=bool(data.get("enabled", False)),
                max_age_days=float(data.get("max_age_days", 90.0)),
                include_key_ids=tuple(data.get("include_key_ids") or ()),
                exclude_key_ids=tuple(
                    data.get("exclude_key_ids")
                    if "exclude_key_ids" in data
                    else _DEFAULT_EXCLUDE
                ),
                updated_at=float(data.get("updated_at") or 0.0),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("rotation policy corrupt (%s); using defaults", exc)
            return RotationPolicy()


_STORE = RotationPolicyStore()


def get_rotation_policy_store() -> RotationPolicyStore:
    return _STORE


def _secret_age_s(stored: StoredKey) -> float:
    anchor = stored.rotated_at or stored.created_at or 0.0
    if anchor <= 0:
        return 0.0
    return max(0.0, time.time() - anchor)


def _eligible(stored: StoredKey, policy: RotationPolicy) -> tuple[bool, str]:
    if stored.revoked:
        return False, "revoked"
    if policy.include_key_ids and stored.key_id not in policy.include_key_ids:
        return False, "not_in_include_list"
    if stored.key_id in policy.exclude_key_ids:
        return False, "excluded"
    max_age_s = float(policy.max_age_days) * 86400.0
    age = _secret_age_s(stored)
    if age < max_age_s:
        return False, f"age_ok ({age:.0f}s < {max_age_s:.0f}s)"
    return True, f"due (age {age:.0f}s >= {max_age_s:.0f}s)"


def apply_due_rotations(
    *,
    dry_run: bool = False,
    force_enabled: bool = False,
    include_secrets: bool = False,
) -> RotationRunReport:
    """Rotate keys that exceed policy max age.

    ``force_enabled`` runs even when policy.enabled is False (admin/CLI override).
    Secrets are only populated when ``include_secrets`` and not dry_run.
    """
    store = get_rotation_policy_store()
    # Ensure configured from current vault path.
    store.configure()
    policy = store.get()
    results: list[RotationResult] = []
    rotated = 0
    skipped = 0
    considered = 0

    if not policy.enabled and not force_enabled:
        return RotationRunReport(
            dry_run=dry_run,
            considered=0,
            rotated=0,
            skipped=0,
            results=[
                RotationResult(
                    key_id="*",
                    status="skipped",
                    detail="policy disabled (enable via admin or --force)",
                )
            ],
            policy=policy.to_public_dict(),
        )

    keys = get_keystore().list_keys(include_revoked=False)
    for stored in keys:
        considered += 1
        ok, detail = _eligible(stored, policy)
        if not ok:
            skipped += 1
            results.append(
                RotationResult(key_id=stored.key_id, status="skipped", detail=detail)
            )
            continue
        if dry_run:
            results.append(
                RotationResult(key_id=stored.key_id, status="dry_run", detail=detail)
            )
            continue
        updated = get_keystore().rotate(stored.key_id)
        if updated is None:
            results.append(
                RotationResult(
                    key_id=stored.key_id,
                    status="error",
                    detail="rotate returned None",
                )
            )
            continue
        revoked_n = get_token_store().revoke_for_key(stored.key_id)
        rotated += 1
        results.append(
            RotationResult(
                key_id=updated.key_id,
                status="rotated",
                detail=detail,
                secret=updated.secret if include_secrets else None,
                previous_tokens_revoked=revoked_n,
            )
        )
        logger.info(
            "policy-rotated key_id=%s tokens_revoked=%s",
            updated.key_id,
            revoked_n,
        )

    return RotationRunReport(
        dry_run=dry_run,
        considered=considered,
        rotated=rotated,
        skipped=skipped,
        results=results,
        policy=policy.to_public_dict(),
    )


def policy_asdict_for_debug(policy: RotationPolicy) -> dict[str, Any]:
    return asdict(policy)
