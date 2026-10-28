"""CLI entrypoint: apply policy-driven API-key rotations once or in a loop.

Cron-friendly (exit after one pass)::

    python -m api.rotation_worker
    python -m api.rotation_worker --once --dry-run
    python -m api.rotation_worker --once --force
    python -m api.rotation_worker --loop --interval 3600

Requires a durable vault (``ZENITH_KEY_VAULT_PATH``) in real deployments so
rotated secrets persist. Prints a JSON summary on stdout.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time

from api.config import get_settings
from api.keystore import get_keystore
from api.rotation_policy import apply_due_rotations, get_rotation_policy_store


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def run_once(
    *,
    dry_run: bool,
    force: bool,
    include_secrets: bool,
) -> dict:
    settings = get_settings()
    get_keystore().configure_vault(settings.key_vault_path)
    get_keystore().ensure_seeded()
    get_rotation_policy_store().configure(settings.key_vault_path)
    report = apply_due_rotations(
        dry_run=dry_run,
        force_enabled=force,
        include_secrets=include_secrets,
    )
    return report.to_public_dict(include_secrets=include_secrets)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Zenith policy key-rotation worker (cron-friendly)."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        default=True,
        help="Apply due rotations once and exit (default).",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Keep applying on an interval until interrupted.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=3600.0,
        help="Seconds between passes when --loop (default: 3600).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List due keys without rotating.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Run even when policy.enabled is false.",
    )
    parser.add_argument(
        "--include-secrets",
        action="store_true",
        help="Print new secrets in the JSON summary (ops only; avoid in logs).",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)

    settings = get_settings()
    if not settings.key_vault_path:
        logging.getLogger("zenith.api.rotation_worker").warning(
            "ZENITH_KEY_VAULT_PATH unset — rotations will not survive restart"
        )

    if args.loop:
        while True:
            summary = run_once(
                dry_run=args.dry_run,
                force=args.force,
                include_secrets=args.include_secrets,
            )
            print(json.dumps(summary, indent=2), flush=True)
            time.sleep(max(1.0, float(args.interval)))
    else:
        summary = run_once(
            dry_run=args.dry_run,
            force=args.force,
            include_secrets=args.include_secrets,
        )
        print(json.dumps(summary, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
