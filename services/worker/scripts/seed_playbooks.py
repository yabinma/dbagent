#!/usr/bin/env python3
"""Idempotent install job that upserts the 5 MVP playbooks into ``playbooks``.

Same pattern as ``bootstrap_signing_key.py`` (design.md Section 9.5.3 /
FP-M5-11). Safe to re-run: updates steps/verification/params_schema/risk_level
without resetting maturity counters.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

logger = logging.getLogger("seed_playbooks")


def seed_playbooks(session, catalog: list[dict] | None = None) -> dict[str, int]:
    """Upsert playbook catalog rows. Returns counts {inserted, updated}."""
    from sqlalchemy import select

    from rca_common.db.models import Playbook
    from worker.playbooks import PLAYBOOK_CATALOG

    rows = catalog if catalog is not None else PLAYBOOK_CATALOG
    inserted = 0
    updated = 0
    for entry in rows:
        existing = session.get(Playbook, entry["playbook_id"])
        if existing is None:
            session.add(
                Playbook(
                    playbook_id=entry["playbook_id"],
                    platform_type=entry.get("platform_type") or "presto",
                    risk_level=entry["risk_level"],
                    params_schema=entry.get("params_schema") or {},
                    steps=entry.get("steps") or {},
                    verification=entry.get("verification") or {},
                    auto_eligible=False,
                    maturity={"approved_runs": 0, "success": 0, "rollbacks": 0},
                )
            )
            inserted += 1
        else:
            existing.platform_type = entry.get("platform_type") or existing.platform_type
            existing.risk_level = entry["risk_level"]
            existing.params_schema = entry.get("params_schema") or existing.params_schema
            existing.steps = entry.get("steps") or existing.steps
            existing.verification = entry.get("verification") or existing.verification
            # Do not reset maturity or auto_eligible.
            session.add(existing)
            updated += 1
    session.commit()
    return {"inserted": inserted, "updated": updated}


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--postgres-dsn",
        default=os.environ.get("RCA_POSTGRES_DSN")
        or os.environ.get("POSTGRES_DSN")
        or "",
        help="Postgres DSN (or set RCA_POSTGRES_DSN).",
    )
    parser.add_argument(
        "--config",
        default=os.environ.get("RCA_WORKER_CONFIG", ""),
        help="Optional AppConfig YAML to read storage.postgres_dsn from.",
    )
    args = parser.parse_args(argv)

    dsn = args.postgres_dsn
    if not dsn and args.config:
        from rca_common.config import load_config

        dsn = load_config(args.config).storage.postgres_dsn
    if not dsn:
        logger.error("postgres DSN required (--postgres-dsn or --config or env)")
        return 1

    from rca_common.db.session import make_engine, make_session_factory

    engine = make_engine(dsn)
    factory = make_session_factory(engine)
    with factory() as session:
        counts = seed_playbooks(session)
    logger.info(
        "seed_playbooks: inserted=%d updated=%d",
        counts["inserted"],
        counts["updated"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
