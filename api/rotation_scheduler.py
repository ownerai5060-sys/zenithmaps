"""APScheduler-lite in-process rotation ticker (optional).

Enable with ``ZENITH_ROTATION_SCHEDULER_ENABLED=true``. Interval from
``ZENITH_ROTATION_SCHEDULER_INTERVAL_S`` (default 3600). Prefer the cron CLI
(``python -m api.rotation_worker``) in multi-replica production so only one
job fires — this ticker is for single-process staging demos.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

from api.config import Settings
from api.rotation_policy import apply_due_rotations

logger = logging.getLogger("zenith.api.rotation_scheduler")

_stop = threading.Event()
_thread: Optional[threading.Thread] = None


def start_rotation_scheduler(settings: Settings) -> bool:
    """Start background ticker when enabled. Idempotent."""
    global _thread
    if not getattr(settings, "rotation_scheduler_enabled", False):
        return False
    if _thread is not None and _thread.is_alive():
        return True
    interval = max(30.0, float(getattr(settings, "rotation_scheduler_interval_s", 3600.0)))
    _stop.clear()

    def _loop() -> None:
        logger.info(
            "rotation scheduler started (interval=%.0fs); prefer cron in multi-replica",
            interval,
        )
        # Initial delay so startup seed finishes.
        if _stop.wait(min(5.0, interval)):
            return
        while not _stop.is_set():
            try:
                report = apply_due_rotations(dry_run=False, force_enabled=False)
                if report.rotated:
                    logger.info(
                        "scheduler rotated %s key(s) (considered=%s)",
                        report.rotated,
                        report.considered,
                    )
            except Exception:  # noqa: BLE001
                logger.exception("rotation scheduler pass failed")
            if _stop.wait(interval):
                break
        logger.info("rotation scheduler stopped")

    _thread = threading.Thread(
        target=_loop, name="zenith-rotation-scheduler", daemon=True
    )
    _thread.start()
    return True


def stop_rotation_scheduler() -> None:
    global _thread
    _stop.set()
    t = _thread
    if t is not None and t.is_alive():
        t.join(timeout=2.0)
    _thread = None
