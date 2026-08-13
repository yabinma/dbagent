"""FP-IG-23 sizing-ledger surface, collected only by the benchmark job.

Re-sited from test_delivery_charts.py by §11.3.3 AC so the gate's
red-until-recorded state cannot skip the job that produces its
observations. This file is collectable without helm: the named
provenance test calls validate_sizing_ledger(..., check_rendered_cpu=False).
The rendered-resource identity remains FP-IG-4's assertion in functional.

Qualifying-run definition (§11.3.3 AC; review-time, not this test):
a recorded run qualifies iff it is this repository's workflow at the
collection head H_c, the B1 step executed and FP-IG-7's named test
reports PASSED, the B1 env= line satisfies Z's validity conditions,
and the job shows no failing step or test other than the two named
red-by-construction verdicts (this file's gate on got 0, and
contingently FP-IG-18). The H_c-to-final-head diff may touch only
the recording carriers: deploy/charts/dbagent/values.yaml,
tests/benchmark/thresholds.yaml, this file, and
tests/delivery/test_delivery_charts.py.
"""
from __future__ import annotations

import re

import yaml

from delivery_helpers import CHARTS, helm_template, parse_manifests


DBAGENT = CHARTS / "dbagent"

VOID_SIZING_BASIS = 2.427
_RUN_ID_RE = re.compile(r"^[0-9]+/[0-9]+$")
_LEDGER_ENTRY_KEYS = (
    "runId",
    "cpuMsPerRequest",
    "cpus",
    "cpuModel",
    "image",
    "workers",
    "served",
    "errors",
    "committed",
    "p99Ms",
    "servedRate",
    "maxInFlight",
    "platformOnline",
    "workerPidsPre",
    "workerPidsPost",
)


def validate_sizing_ledger(ig: dict, *, check_rendered_cpu: bool = True) -> None:
    """FP-IG-23 validity + recompute. Factored so mutation fixtures can
    drive the same checks against a weakened ledger.

    Exactly five observations are required unconditionally. An empty
    ledger — including the shipped void 2.427 / observations: [] state —
    is red until five valid CI benchmark-job runs are recorded. A void
    2.427 basis with any observations is also red unless those five
    entries independently recompute to 2.427 (they will not: the void
    figure came from invalid cpus=16 runs).
    """
    assert "sizingBasis" in ig, "ingestGateway.sizingBasis missing (unfixed tree)"
    sb = ig["sizingBasis"]
    assert "signature" in sb, "sizingBasis.signature missing (unfixed tree)"
    assert "observations" in sb, "sizingBasis.observations missing (unfixed tree)"
    sig = sb["signature"]
    for key in ("cpus", "cpuModel", "image", "workers"):
        assert key in sig, key
    assert isinstance(sb["observations"], list)
    assert sig["cpus"] == 4
    assert sig["workers"] == ig["workers"]

    obs = sb["observations"]
    assert len(obs) == 5, f"want exactly five observations, got {len(obs)}"
    run_ids = []
    cpu_vals = []
    for entry in obs:
        for key in _LEDGER_ENTRY_KEYS:
            assert key in entry, key
        assert entry["cpus"] == sig["cpus"] == 4
        assert entry["cpuModel"] == sig["cpuModel"]
        assert entry["image"] == sig["image"]
        assert entry["workers"] == sig["workers"] == ig["workers"]
        assert entry["errors"] == 0
        assert entry["served"] == 30000
        assert entry["committed"] == entry["served"]
        assert entry["p99Ms"] < 150
        assert entry["servedRate"] >= 200
        assert entry["maxInFlight"] < 1000
        assert entry["platformOnline"] is True
        pre = list(entry["workerPidsPre"])
        post = list(entry["workerPidsPost"])
        assert pre == sorted(set(pre)), pre
        assert post == sorted(set(post)), post
        assert len(pre) == sig["workers"]
        assert pre == post
        rid = entry["runId"]
        assert isinstance(rid, str) and _RUN_ID_RE.fullmatch(rid), rid
        run_ids.append(rid)
        cpu_vals.append(float(entry["cpuMsPerRequest"]))
    assert len(set(run_ids)) == 5, run_ids
    recomputed = max(cpu_vals) + (max(cpu_vals) - min(cpu_vals))
    assert abs(float(sb["cpuMsPerRequest"]) - recomputed) < 1e-9
    if not check_rendered_cpu:
        return
    import math

    expected_req = math.ceil(recomputed * 200)
    out = helm_template(DBAGENT)
    docs = parse_manifests(out)
    dep = next(
        d
        for d in docs
        if d.get("kind") == "Deployment" and "ingest-gateway" in d["metadata"]["name"]
    )
    req = dep["spec"]["template"]["spec"]["containers"][0]["resources"]["requests"]["cpu"]
    s = str(req)
    millicores = int(s[:-1]) if s.endswith("m") else int(float(s) * 1000)
    assert millicores == expected_req


def test_sizing_basis_provenance_is_on_reference_and_from_a_serving_run():
    """FP-IG-23: ledger schema + five valid observations + recompute.

    Sited in benchmark step 20, after B1's producing step at 17 (§11.3.3 AC).
    helm is not installed in that job; rendered CPU is FP-IG-4's assertion.

    Against the unfixed tree: red — no signature block and no observations.
    Against the current tree: still red — observations is empty. Valid
    runIds cannot be fabricated here. Collection is five consecutive CI
    benchmark-job runs at the collection head H_c (AC: FP-IG-7 PASSED in
    the B1 step log, no failing verdict other than this gate on got 0 and
    contingently FP-IG-18). The void 2.427 figure stays in values.yaml as a
    historical label only; it does not satisfy this test. The batch is not
    complete until five real observations, a re-derived basis, and
    recomputed CPU resources are recorded.
    """
    values = yaml.safe_load((DBAGENT / "values.yaml").read_text(encoding="utf-8"))
    validate_sizing_ledger(values["ingestGateway"], check_rendered_cpu=False)


def _valid_observation(run_id: str, cpu: float, workers: int = 4) -> dict:
    pids = [1000 + i for i in range(workers)]
    return {
        "runId": run_id,
        "cpuMsPerRequest": cpu,
        "cpus": 4,
        "cpuModel": "ref",
        "image": "ref-image",
        "workers": workers,
        "served": 30000,
        "errors": 0,
        "committed": 30000,
        "p99Ms": 40.0,
        "servedRate": 990.0,
        "maxInFlight": 200,
        "platformOnline": True,
        "workerPidsPre": pids,
        "workerPidsPost": list(pids),
    }


def _filled_ledger(*, cpu_vals=None, mutate=None) -> dict:
    cpus = list(cpu_vals or [1.0, 1.1, 1.2, 1.05, 1.08])
    ig = {
        "workers": 4,
        "sizingBasis": {
            "cpuMsPerRequest": max(cpus) + (max(cpus) - min(cpus)),
            "signature": {
                "cpus": 4,
                "cpuModel": "ref",
                "image": "ref-image",
                "workers": 4,
            },
            "observations": [
                _valid_observation(f"{1000 + i}/1", cpus[i]) for i in range(5)
            ],
        },
    }
    if mutate:
        mutate(ig)
    return ig


def test_sizing_ledger_mutations_are_red_only_with_validity_rules():
    """Standing test for FP-IG-23: each named weakening fails the helper.

    Against the unfixed tree every case is independently red (no
    signature, no observations, void 2.427 cannot be re-encoded).
    Cases are red only while the corresponding rule is present.
    """
    validate_sizing_ledger(_filled_ledger(), check_rendered_cpu=False)

    def _expect_red(name, mutate):
        try:
            validate_sizing_ledger(_filled_ledger(mutate=mutate), check_rendered_cpu=False)
        except AssertionError:
            return
        raise AssertionError(f"{name} stayed green; the validity rule is absent")

    _expect_red("missing_signature", lambda ig: ig["sizingBasis"].pop("signature"))
    _expect_red("missing_observations", lambda ig: ig["sizingBasis"].pop("observations"))
    _expect_red(
        "void_basis_with_fabricated_obs",
        lambda ig: ig["sizingBasis"].__setitem__("cpuMsPerRequest", VOID_SIZING_BASIS),
    )
    _expect_red(
        "duplicate_run_ids",
        lambda ig: ig["sizingBasis"]["observations"].__setitem__(
            1, _valid_observation("1000/1", 1.1)
        ),
    )
    _expect_red(
        "duplicate_pids",
        lambda ig: ig["sizingBasis"]["observations"][0].__setitem__(
            "workerPidsPre", [1, 1, 1, 1]
        ),
    )
    _expect_red(
        "committed_ne_served",
        lambda ig: ig["sizingBasis"]["observations"][0].__setitem__("committed", 29999),
    )
    _expect_red(
        "platform_not_online",
        lambda ig: ig["sizingBasis"]["observations"][0].__setitem__(
            "platformOnline", False
        ),
    )
    _expect_red(
        "worker_set_changed",
        lambda ig: ig["sizingBasis"]["observations"][0].__setitem__(
            "workerPidsPost", [9, 10, 11, 12]
        ),
    )
    _expect_red(
        "cpus_not_reference_4",
        lambda ig: (
            ig["sizingBasis"]["signature"].__setitem__("cpus", 16),
            [
                e.__setitem__("cpus", 16)
                for e in ig["sizingBasis"]["observations"]
            ],
        ),
    )
    _expect_red(
        "recompute_mismatch",
        lambda ig: ig["sizingBasis"].__setitem__("cpuMsPerRequest", 9.999),
    )
    _expect_red(
        "empty_observations",
        lambda ig: ig["sizingBasis"].__setitem__("observations", []),
    )
    _expect_red(
        "malformed_run_id_extra_segment",
        lambda ig: ig["sizingBasis"]["observations"][0].__setitem__(
            "runId", "1000/bogus/extra"
        ),
    )
    _expect_red(
        "malformed_run_id_non_numeric_attempt",
        lambda ig: ig["sizingBasis"]["observations"][0].__setitem__(
            "runId", "1000/bogus"
        ),
    )

    # Unfixed-tree shape: no ledger at all.
    try:
        validate_sizing_ledger({"workers": 4}, check_rendered_cpu=False)
    except AssertionError:
        pass
    else:
        raise AssertionError("unfixed (no sizingBasis) stayed green")
