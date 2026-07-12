"""Sanity checks for the benchmark/functional checkpoint manifests
(design.md Section 14.3/14.4). This is a lightweight stand-in for the full
CI manifest-check script (Section 14.5's "CI runs a manifest check ...
that fails if any checkpoint has no linked test"), which is part of the M6
delivery/CI packaging work; this test at least keeps the two YAML files
internally consistent as milestones are added.
"""
from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]

EXPECTED_BENCHMARK_IDS = {f"B{i}" for i in range(1, 15)}
EXPECTED_CHECKPOINT_IDS = {f"F{i}" for i in range(1, 17)}
VALID_STATUSES = {"covered", "partial", "deferred"}


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_thresholds_yaml_lists_every_benchmark_exactly_once():
    data = _load(REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml")
    ids = [b["id"] for b in data["benchmarks"]]
    assert set(ids) == EXPECTED_BENCHMARK_IDS
    assert len(ids) == len(set(ids)), "duplicate benchmark id"


def test_checkpoints_yaml_lists_every_checkpoint_exactly_once():
    data = _load(REPO_ROOT / "tests" / "functional" / "checkpoints.yaml")
    ids = [c["id"] for c in data["checkpoints"]]
    assert set(ids) == EXPECTED_CHECKPOINT_IDS
    assert len(ids) == len(set(ids)), "duplicate checkpoint id"


def test_every_benchmark_has_a_valid_status_and_owning_milestone():
    data = _load(REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml")
    for b in data["benchmarks"]:
        assert b["status"] in VALID_STATUSES, b["id"]
        assert b["owning_milestone"].startswith("M"), b["id"]
        if b["status"] != "deferred":
            assert b["tests"], f"{b['id']} is not deferred but has no linked test"


def test_every_checkpoint_has_a_valid_status_and_owning_milestone():
    data = _load(REPO_ROOT / "tests" / "functional" / "checkpoints.yaml")
    for c in data["checkpoints"]:
        assert c["status"] in VALID_STATUSES, c["id"]
        assert c["owning_milestone"].startswith("M"), c["id"]
        if c["status"] != "deferred":
            assert c["tests"] or c.get("notes"), (
                f"{c['id']} is not deferred but has no linked test or explanatory notes"
            )


def test_m1_checkpoint_f14_links_to_the_real_m1_functional_test():
    data = _load(REPO_ROOT / "tests" / "functional" / "checkpoints.yaml")
    f14 = next(c for c in data["checkpoints"] if c["id"] == "F14")
    assert f14["owning_milestone"] == "M1"
    assert any("test_m1_foundation.py" in t for t in f14["tests"])
