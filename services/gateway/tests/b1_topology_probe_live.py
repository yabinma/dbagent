"""GC-3 FP-GC3-2: the one live node of the B1 topology discovery route.

**This file is deliberately not named ``test_*.py``.** Neither the root
``pytest.ini`` nor ``services/gateway/pyproject.toml`` overrides
``python_files``, so no directory collection -- not ``unit-gateway``, not
``functional``, not the local ``py`` tier -- discovers it. Only
``scripts/integration-test.sh b1_topology_probe`` collects it, by naming this
file as an explicit operand. That is what keeps FP-IG-26 true: the frozen
sizing-ledger producer ``test_b1_ingest_burst.py`` is still collected by
exactly one CI job, while this module reuses its harness.

It contains no container-free logic on purpose. Everything that builds,
validates or scores a record lives in ``b1_topology_probe.py`` and
``test_b1_ingest_burst.py``, under the ordinary traced coverage phase; what is
here is one module-scoped live fixture and one assertion body, which no
tracer ever runs.

GC-5 (FP-GC5-10) adds its transaction/WAL fields to the same fingerprint and
nothing else: this route neither asserts the commit ratio nor lets an
unavailable reading void an arm, because only GC-3's own separately audited
requalification may change a model's outcome.

The node's gate is *measurement integrity*, not candidate performance. It
fails on any placement, topology, lifecycle, platform, worker, record-integrity
or accounting defect, and it deliberately does not assert that the five
performance comparisons are ``met``: a truthful ``missed`` is the datum this
whole route exists to collect, and asserting it would stop the sweep at the
first expected miss.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_HARNESS_PATH = Path(__file__).resolve().parent / "test_b1_ingest_burst.py"
_spec = importlib.util.spec_from_file_location("test_b1_ingest_burst", _HARNESS_PATH)
assert _spec and _spec.loader
harness = importlib.util.module_from_spec(_spec)
sys.modules["test_b1_ingest_burst"] = harness
_spec.loader.exec_module(harness)

probe = harness.probe


@pytest.fixture(scope="module")
def b1_topology_probe_run(tmp_path_factory):
    """FP-GC3-2: one discovery arm, under the schema-3 contract the shell wrote."""
    yield from harness._run_b1_reference(harness.CI_SCALE_PROBE_PROFILE, tmp_path_factory)


@pytest.mark.b1_live
@pytest.mark.b1_topology_probe
def test_b1_ci_scale_topology_probe_record(b1_topology_probe_run):
    """FP-GC3-2: prove the arm, then record the unchanged bar without gating it."""
    run = b1_topology_probe_run
    declaration = run["declaration"]
    context = harness.read_probe_context()

    # (0) Placement and physical topology are preconditions. The fixture
    # already refuses to yield without them; re-asserted here so a refactor
    # cannot quietly remove the gate.
    assert run["placement_ok"] is True, run["fingerprint"]
    assert declaration.profile == harness.CI_SCALE_PROBE_PROFILE_NAME
    assert declaration.schema == harness.B1_TOPOLOGY_PLACEMENT_SCHEMA
    assert declaration.topology in probe.TOPOLOGY_IDS, declaration.topology
    for role in harness.B1_ROLES:
        assert run["placement"][role].allowed_cpus == declaration.allowed(role), role
        assert run["placement_open"][role].allowed_cpus == declaration.allowed(role), role

    # (1) The record itself: closed keys, exact mapping, sibling maps that
    # agree with the reference reading, and verdicts that agree with their own
    # operands. `build_probe_arm_record` raises on every one of those.
    record = harness.build_probe_arm_record(run, context)
    assert record["index"] == context["index"]
    assert record["topology"] == declaration.topology

    # (2) The five integrity statuses are asserted directly: a miss there means
    # the measurement is undefined, not that the candidate is slow.
    verdicts = record["verdicts"]
    for field in probe.INTEGRITY_VERDICT_FIELDS:
        assert verdicts[field] == probe.VERDICT_MET, (
            f"{field}={verdicts[field]}; {run['fingerprint']}"
        )

    # (3) The five performance statuses are DATA. Each is checked only for
    # being one of the two admitted words and for agreeing with its own live
    # operand -- never for being `met`.
    live = probe.evaluate_verdicts(harness.probe_operands(run))
    for field in probe.PERFORMANCE_VERDICT_FIELDS:
        token = verdicts[field]
        assert token in (probe.VERDICT_MET, probe.VERDICT_MISSED), (field, token)
        assert token == live[field], (field, token, live[field])

    # (4) Exactly the closed ordered vocabulary, once each.
    assert tuple(verdicts) == probe.VERDICT_FIELDS
    print(f"B1 probe verdicts={probe.serialize_verdicts(verdicts)}", flush=True)

    # (5) GC-4 (FP-GC4-5): the shared HARNESS-OPERAND validator -- a positive
    # served count, a positive PostgreSQL CPU reading and both finite lateness
    # legs. Nothing else. It judges no comparison, gates no candidate and, in
    # particular, does not inspect the test-only wait sampler: a sampler that
    # failed, stalled or saw nothing serializes `unavailable` in all five wait
    # fields plus a note, and this arm is still written. A GC-4 diagnostic must
    # never be able to destroy a 28-arm GC-3 sweep's evidence.
    harness.assert_complete_postgres_cost_record(run)

    harness.write_probe_arm_record(record)

    # (6) ...and that is verified on the arm that was actually written: the
    # record exists, its fingerprint carries the wait fields in one of their
    # two admitted representations, and an unavailable sampler is accompanied
    # by its note rather than by a fabricated zero.
    written = json.loads(harness.B1_PROBE_RECORD.read_text(encoding="utf-8"))
    assert written["index"] == record["index"]
    wait_fields = {
        field: harness._parse_b1_env_field(written["fingerprint"], field)
        for field in harness.B1_POSTGRES_COST_FIELDS[1:]
    }
    if harness.postgres_wait_sample_failure(run["postgres_wait_sample"]) is None:
        assert harness.DIAGNOSTIC_UNAVAILABLE not in set(wait_fields.values()), wait_fields
    else:
        assert set(wait_fields.values()) == {harness.DIAGNOSTIC_UNAVAILABLE}, wait_fields
        assert any("postgres wait sampler" in note for note in written["notes"]), written["notes"]

    # (7) GC-5 (FP-GC5-7/8/10): the transaction and WAL fields travel inside
    # this arm's existing fingerprint, in one of the same two admitted
    # representations. Their absence is NOT a verdict and their ratio is NOT
    # compared here: the mechanism gate lives on the product-local route, and
    # a GC-5 diagnostic must never be able to void a GC-3 discovery arm.
    commit_fields = {
        field: harness._parse_b1_env_field(written["fingerprint"], field)
        for field in harness.B1_POSTGRES_COMMIT_FIELDS
    }
    commit_reason = harness.postgres_commit_snapshot_failure(
        run["postgres_commit_before"],
        run["postgres_commit_after"],
        run["result"].served,
    )
    if commit_reason is None:
        assert harness.DIAGNOSTIC_UNAVAILABLE not in set(commit_fields.values()), (
            commit_fields
        )
        assert int(commit_fields["postgres_xact_commit_delta"]) > 0, commit_fields
    else:
        assert set(commit_fields.values()) == {harness.DIAGNOSTIC_UNAVAILABLE}, (
            commit_fields
        )
        assert any(
            "postgres transaction snapshot" in note for note in written["notes"]
        ), written["notes"]
