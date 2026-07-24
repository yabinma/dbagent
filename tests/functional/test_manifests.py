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


def _resolve_test_file(link: str) -> Path | None:
    """Map a thresholds.yaml test link to a source file on disk.

    Links look like ``path/to/file.py::test_name`` or ``path/to/file.go::TestName``.
    """
    path_part = link.split("::", 1)[0].strip()
    if not path_part:
        return None
    candidate = REPO_ROOT / path_part
    if candidate.is_file():
        return candidate
    return None


def _link_names_benchmark(link: str, bench_id: str) -> bool:
    """True if the linked test identity includes the benchmark id (B6/test_b6/TestB6)."""
    lower = link.lower()
    bid = bench_id.lower()  # e.g. "b6"
    # Require the id in the test name portion (after ::) or as TestB6 / test_b6 in path.
    if "::" in link:
        name = link.split("::", 1)[1].lower()
        if bid in name or f"test_{bid}" in name or f"test{bid}" in name:
            return True
    # Go-style whole-file links sometimes encode the id in the filename.
    return f"test_{bid}" in lower or f"bench_{bid}" in lower or f"/{bid.lower()}_" in lower


def _file_asserts_threshold(src: str) -> bool:
    """Heuristic: the test source contains a numeric threshold assertion.

    Genuine B6/B13/B14 (and Go B3/B4/B5/B9) tests compare measured latency/rate
    against a concrete number. Ordinary correctness tests do not.
    """
    import re

    # Common patterns: assert x < 1.0 / assert rate >= 200 / t.Fatalf with budget
    patterns = [
        r"assert\s+.+\s*[<>=]{1,2}\s*\d",
        r"if\s+.+\s*[<>]=?\s*\d",
        r"(FAILED|budget|threshold|p99|req/s|ms\b).{0,40}\d",
        r"\d+\s*(ms|s)\b",
        r"require\.(True|Less|Greater|InDelta)",
    ]
    return any(re.search(p, src, re.IGNORECASE) for p in patterns)


def test_covered_benchmarks_link_to_threshold_asserting_tests():
    """Manifest honesty (Section 14.4 / review.md W2): a `covered` benchmark
    must link to a test that (a) names the benchmark id and (b) actually
    asserts a numeric threshold — not a plain correctness test.
    """
    data = _load(REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml")
    failures: list[str] = []
    for b in data["benchmarks"]:
        if b["status"] != "covered":
            continue
        bid = b["id"]
        links = b.get("tests") or []
        if not links:
            failures.append(f"{bid}: covered but tests list empty")
            continue
        named = [lnk for lnk in links if _link_names_benchmark(lnk, bid)]
        if not named:
            failures.append(
                f"{bid}: covered but no linked test names the benchmark id "
                f"(expected e.g. test_{bid.lower()}_... or Test{bid}_...); links={links}"
            )
            continue
        asserted = False
        for lnk in named:
            path = _resolve_test_file(lnk)
            if path is None:
                failures.append(f"{bid}: linked test file not found for {lnk!r}")
                continue
            src = path.read_text(encoding="utf-8")
            # If a specific test name is given, prefer checking that function's body.
            if "::" in lnk:
                tname = lnk.split("::", 1)[1]
                # Slice from the def/func of that test to the next top-level def/func.
                import re

                m = re.search(
                    rf"(?:^|\n)(?:async\s+)?def\s+{re.escape(tname)}\s*\(|"
                    rf"(?:^|\n)func\s+{re.escape(tname)}\s*\(",
                    src,
                )
                if m:
                    start = m.start()
                    rest = src[start + 1 :]
                    m2 = re.search(r"\n(?:async\s+)?def\s+\w+|\nfunc\s+\w+", rest)
                    body = rest[: m2.start()] if m2 else rest
                    if _file_asserts_threshold(body):
                        asserted = True
                        break
            if _file_asserts_threshold(src):
                asserted = True
                break
        if not asserted:
            failures.append(
                f"{bid}: covered and named, but linked test(s) do not assert a "
                f"numeric threshold (got {named})"
            )
    assert not failures, "manifest honesty failures:\n  - " + "\n  - ".join(failures)
