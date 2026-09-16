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

The node's gate is *measurement integrity*, not candidate performance. It
fails on any placement, topology, lifecycle, platform, worker, record-integrity
or accounting defect, and it deliberately does not assert that the five
performance comparisons are ``met``: a truthful ``missed`` is the datum this
whole route exists to collect, and asserting it would stop the sweep at the
first expected miss.
"""
from __future__ import annotations

import importlib.util
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

    harness.write_probe_arm_record(record)
