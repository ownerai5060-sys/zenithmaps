"""CLI entrypoint: process due webhook retry jobs once or in a loop.

Usage::

    python -m api.webhook_worker
    python -m api.webhook_worker --loop --interval 5
    python -m api.webhook_worker --once --limit 20

Reads ``ZENITH_WEBHOOK_LOG_PATH`` for the durable retry queue. Exits 0 when
idle / after one pass; non-zero on unexpected errors.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time

from api.config import get_settings
from api.webhook_log import get_delivery_log
from api.webhook_retry import get_retry_queue, process_due_retries
from api.webhooks import get_webhook_registry


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def run_once(*, limit: int, timeout_s: float) -> dict[str, int]:
    settings = get_settings()
    path = settings.webhook_log_path
    get_delivery_log().configure(path)
    get_webhook_registry().configure(path)
    get_retry_queue().configure(path)
    return process_due_retries(limit=limit, timeout_s=timeout_s)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Zenith webhook retry worker (exponential backoff)."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        default=True,
        help="Process due jobs once and exit (default).",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Keep polling for due jobs until interrupted.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Seconds between polls when --loop is set (default: 5).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Max jobs per pass (default: 50).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="HTTP timeout seconds per delivery (default: 3).",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)

    settings = get_settings()
    if not settings.webhook_log_path:
        logging.getLogger("zenith.webhook_worker").warning(
            "ZENITH_WEBHOOK_LOG_PATH is empty; using in-memory retry queue "
            "(nothing durable to drain across processes)."
        )

    if args.loop:
        logging.getLogger("zenith.webhook_worker").info(
            "webhook retry loop started interval=%ss", args.interval
        )
        try:
            while True:
                stats = run_once(limit=args.limit, timeout_s=args.timeout)
                if stats["attempted"]:
                    logging.getLogger("zenith.webhook_worker").info(
                        "retry pass: %s", stats
                    )
                time.sleep(max(args.interval, 0.1))
        except KeyboardInterrupt:
            return 0
    stats = run_once(limit=args.limit, timeout_s=args.timeout)
    logging.getLogger("zenith.webhook_worker").info("retry once: %s", stats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
