"""FP-IG-23 sizing-ledger surface, collected only by the benchmark job.

Re-sited from test_delivery_charts.py by §11.3.3 AC so the gate's
red-until-recorded state cannot skip the job that produces its
observations. This file is collectable without helm: the named
provenance test calls validate_sizing_ledger(..., check_rendered_cpu=False).
The rendered-resource identity remains FP-IG-4's assertion in functional.

B1-LATENCY-BASIS-1 restates the qualifying-run definition (FP-B1LB-1) and
closes the ledger schema (FP-B1LB-2/3/4). A recorded run qualifies iff it is
this repository's ordinary ``benchmark`` workflow at the collection head
``H_c``, routed by GC-3 onto the single current ``selected`` CPU model, and
its canonical ``B1 env=`` line satisfies the restated CI-scale operating
point in §3.1: profile ``ci-scale``, authority ``ci-scale-reference``, 15000
offered, 15000 served and committed, zero errors, served rate >= 450/s,
due-time p99 < 150 ms, max in flight < 500, platform online, a valid
placement witness and a stable four-worker identity. The product-local
1000 req/s tier and the GC-3 topology-probe arms are INELIGIBLE: that is a
deliberate frozen-clause-Z deviation (design/frozen-deviations.md), not an
editorial correction, and it neither weakens the CI-scale bar nor claims
product-scale capacity.

Collection is coordinator-owned and post-review (FP-B1LB-4): at most 20
ordinary ``benchmark`` dispatches at exactly ``H_c``, every one of them
recorded in ``collection.attempts`` as either the linked observation or a
discarded attempt carrying its exact route/clause reason. No run id,
observation, discard or number in this file's synthetic fixtures may ever
enter values.yaml, the threshold notes or acceptance evidence. The
``H_c``-to-recording diff may touch only deploy/charts/dbagent/values.yaml
and tests/benchmark/thresholds.yaml.

This module is also the fixed, fail-closed entry point for the isolated
``b1_latency_basis`` target (FP-B1LB-6). ``scripts/integration-test.sh``
invokes it as a script:

    <venv python> tests/delivery/test_delivery_sizing_ledger.py \
        basis-oracle-preflight --values <values.yaml> --decision <carrier>
    <venv python> tests/delivery/test_delivery_sizing_ledger.py \
        basis-oracle-route --values <values.yaml> --decision <carrier> \
        --route <route record>

Both print exactly ``basis_oracle_unobserved:<reason>`` on stderr and exit 3
when the oracle cannot be observed on this runner; ordinary CLI misuse keeps
an ordinary nonzero status so the two can never be confused.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import re
import sys
from pathlib import Path

import yaml

# Importable both as a pytest module (conftest puts this directory on the
# path) and as the launcher's CLI (`python tests/delivery/<this file>`),
# where sys.path[0] is already this directory.
if str(Path(__file__).resolve().parent) not in sys.path:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from delivery_helpers import CHARTS, REPO_ROOT, helm_template, parse_manifests


DBAGENT = CHARTS / "dbagent"
VALUES_YAML = DBAGENT / "values.yaml"
GC3_DECISION = REPO_ROOT / "tests" / "benchmark" / "b1_topology_decision.json"
GC3_PROBE_HELPER = REPO_ROOT / "services" / "gateway" / "tests" / "b1_topology_probe.py"

#: The historical, VOID basis label. It is a string in values.yaml's prose and
#: a mutation operand here; it is never a qualification.
VOID_SIZING_BASIS = 2.427


def _load_module(path: Path, name: str):
    """Load a tracked helper by file path, as the delivery profile already does."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - unreachable
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


#: GC-3's own carrier reader/validator. Selection is never reimplemented here.
gc3 = _load_module(GC3_PROBE_HELPER, "b1lb_topology_probe")


class SizingLedgerError(AssertionError):
    """A named failure of the closed ledger contract (FP-IG-23 / FP-B1LB-1..5)."""


class BasisOracleUnobserved(Exception):
    """The latency-basis oracle cannot be observed here; never a pass."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class BasisOracleRouteError(Exception):
    """An unusable route record: ordinary failure, never an unobserved route."""


def _fail(message: str) -> "None":
    raise SizingLedgerError(message)


# ---------------------------------------------------------------------------
# FP-B1LB-1 — the restated, unchanged CI-scale operating point
# ---------------------------------------------------------------------------
REQUIRED_PROFILE = "ci-scale"
REQUIRED_MEASUREMENT_AUTHORITY = "ci-scale-reference"
REQUIRED_OFFERED = 15000
REQUIRED_SERVED = 15000
SERVED_RATE_FLOOR = 450
P99_MS_CEILING = 150
MAX_IN_FLIGHT_CEILING = 500
REQUIRED_OBSERVATIONS = 5
REFERENCE_CPUS = 4

# ---------------------------------------------------------------------------
# FP-B1LB-2/3 — the closed schema
# ---------------------------------------------------------------------------
SIZING_BASIS_KEYS = frozenset({"cpuMsPerRequest", "signature", "collection", "observations"})
COLLECTION_KEYS = frozenset({"attempts"})
SIGNATURE_KEYS = (
    "headSha",
    "cpus",
    "cpuModel",
    "image",
    "workers",
    "referenceTopology",
    "placementSchema",
    "topologyDecisionHeadSha",
)
#: The signature fields every observation repeats verbatim. ``headSha`` is
#: checked separately: a row carries it as provenance, not as a copy slot.
SIGNATURE_COPY_KEYS = (
    "cpus",
    "cpuModel",
    "image",
    "workers",
    "referenceTopology",
    "placementSchema",
    "topologyDecisionHeadSha",
)
OBSERVATION_KEYS = frozenset(
    {
        # provenance
        "runId", "headSha", "profile", "measurementAuthority",
        # cost
        "cpuMsPerRequest",
        # signature copy
        "cpus", "cpuModel", "image", "workers", "referenceTopology",
        "placementSchema", "topologyDecisionHeadSha",
        # serving validity
        "offered", "served", "errors", "committed", "p99Ms", "servedRate",
        "maxInFlight", "platformOnline", "placementOk",
        # worker identity
        "workerPidsPre", "workerPidsPost",
    }
)
ATTEMPT_KEYS = frozenset({"runId", "headSha", "cpuModel", "decisionState", "outcome", "reason"})

OUTCOME_OBSERVATION = "observation"
OUTCOME_DISCARDED = "discarded"
OUTCOMES = (OUTCOME_OBSERVATION, OUTCOME_DISCARDED)

STATE_SELECTED = gc3.ROUTE_STATE_SELECTED
STATE_UNHOSTABLE = gc3.ROUTE_STATE_UNHOSTABLE
STATE_ABSENT = gc3.ROUTE_STATE_ABSENT
STATE_UNAVAILABLE = gc3.ROUTE_STATE_UNAVAILABLE
STATE_INVALID = gc3.ROUTE_STATE_INVALID
STATE_NOT_REACHED = "not_reached"
DECISION_STATES = (
    STATE_SELECTED, STATE_UNHOSTABLE, STATE_ABSENT,
    STATE_UNAVAILABLE, STATE_INVALID, STATE_NOT_REACHED,
)
#: The two states whose route could not name a model at all.
NULL_MODEL_STATES = (STATE_UNAVAILABLE, STATE_NOT_REACHED)

#: This slice's own discard reasons. The GC-3 route reasons are imported
#: above rather than restated, so a route-vocabulary change cannot drift.
CLAUSE_FAILED_PREFIX = "b1_clause_failed:"
SIGNATURE_MISMATCH_PREFIX = "signature_mismatch:"
BENCHMARK_INCOMPLETE_PREFIX = "benchmark_incomplete:"
#: The closed set of §3.1 predicate names a `selected` route may have failed.
B1_PREDICATE_NAMES = (
    "committed", "errors", "maxInFlight", "offered", "p99Ms", "placementOk",
    "platformOnline", "served", "servedRate", "workerSet",
)

_RUN_ID_RE = re.compile(r"^[0-9]+/[0-9]+$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_RE = re.compile(r"^(?:imagedata|os-release):[0-9a-f]{16}$")

# ---------------------------------------------------------------------------
# FP-B1LB-6 — the isolated oracle's fail-closed reasons
# ---------------------------------------------------------------------------
UNOBSERVED_PREFIX = "basis_oracle_unobserved:"
UNOBSERVED_EXIT = 3
LEDGER_UNRECORDED = "ledger_unrecorded"
LEDGER_INVALID = "ledger_invalid"


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _finite_positive(value, where: str) -> float:
    if not _is_number(value):
        _fail(f"{where} is not a number: {value!r}")
    number = float(value)
    if not math.isfinite(number):
        _fail(f"{where} is not finite: {value!r}")
    if number <= 0:
        _fail(f"{where} is not positive: {value!r}")
    return number


# ---------------------------------------------------------------------------
# FP-B1LB-2 — the GC-3 binding
# ---------------------------------------------------------------------------
_DECISION_CACHE: "dict[tuple[str, int, float], dict]" = {}


def load_gc3_decision(decision_path=GC3_DECISION) -> dict:
    """The tracked carrier, validated by GC-3's own closed-schema helper."""
    path = Path(decision_path)
    if not path.is_file():
        _fail(f"{gc3.DECISION_MISSING_REASON}: {path}")
    stat = path.stat()
    key = (str(path), stat.st_size, stat.st_mtime)
    cached = _DECISION_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        validated = gc3.validate_decision(payload)
    except (gc3.TopologyProbeError, ValueError, OSError) as exc:
        raise SizingLedgerError(f"{gc3.DECISION_INVALID_REASON}: {exc}") from exc
    _DECISION_CACHE[key] = validated
    return validated


def gc3_selected_identity(decision: dict) -> dict:
    """The one current `selected` model's identity, or fail closed.

    Zero selected models and two selected models are both failures: one chart
    resource tuple cannot consume several model-specific costs, and this
    contract deliberately does not choose by map order, score or vendor.
    """
    models = (decision or {}).get("models")
    if not isinstance(models, dict) or not models:
        _fail("the GC-3 carrier has no models map")
    selected = {
        model: entry for model, entry in models.items()
        if isinstance(entry, dict) and entry.get("status") == "selected"
    }
    if len(selected) != 1:
        _fail(
            "one chart ledger binds exactly one current GC-3 selected model; the "
            f"carrier currently selects {len(selected)}: {sorted(selected)}"
        )
    model, entry = next(iter(selected.items()))
    return {
        "cpuModel": model,
        "referenceTopology": entry["selected"],
        "placementSchema": entry["placementSchema"],
        "topologyDecisionHeadSha": entry["evidenceHeadSha"],
    }


# ---------------------------------------------------------------------------
# FP-B1LB-5 — the derivation
# ---------------------------------------------------------------------------
def derive_basis(costs) -> float:
    """max + (max - min) over the accepted costs."""
    lo = min(costs)
    hi = max(costs)
    return hi + (hi - lo)


def derive_chart_millicores(basis: float) -> "tuple[int, int]":
    """requests.cpu = ceil(basis x 200) m; limits.cpu = exactly 5 x requests."""
    request = math.ceil(basis * 200)
    return request, 5 * request


# ---------------------------------------------------------------------------
# The validator
# ---------------------------------------------------------------------------
def require_ledger_shape(ig: dict) -> dict:
    """The closed container shape, before any value is judged.

    Deliberately separate from validate_sizing_ledger: the chart test's Phase
    A pending branch needs the two empty carriers, and the actual-state gate
    needs its observation-count diagnostic to be the FIRST thing a void ledger
    reports.
    """
    if not isinstance(ig, dict) or "sizingBasis" not in ig:
        _fail("ingestGateway.sizingBasis missing (unfixed tree)")
    sb = ig["sizingBasis"]
    if not isinstance(sb, dict):
        _fail(f"sizingBasis is not an object: {type(sb).__name__}")
    if set(sb) != SIZING_BASIS_KEYS:
        _fail(f"closed sizingBasis keys {sorted(SIZING_BASIS_KEYS)}; got {sorted(sb)}")
    if not isinstance(sb["signature"], dict):
        _fail("sizingBasis.signature is not an object")
    collection = sb["collection"]
    if not isinstance(collection, dict) or set(collection) != COLLECTION_KEYS:
        _fail(
            f"closed sizingBasis.collection keys {sorted(COLLECTION_KEYS)}; "
            f"got {sorted(collection) if isinstance(collection, dict) else collection!r}"
        )
    if not isinstance(collection["attempts"], list):
        _fail("sizingBasis.collection.attempts is not a list")
    if not isinstance(sb["observations"], list):
        _fail("sizingBasis.observations is not a list")
    return sb


def _validate_signature(sig: dict, ig: dict, decision: dict) -> None:
    if set(sig) != set(SIGNATURE_KEYS):
        _fail(f"closed signature keys {sorted(SIGNATURE_KEYS)}; got {sorted(sig)}")
    if not isinstance(sig["headSha"], str) or not _SHA_RE.match(sig["headSha"]):
        _fail(f"signature.headSha is not a 40-hex collection head: {sig['headSha']!r}")
    if sig["cpus"] != REFERENCE_CPUS or not _is_int(sig["cpus"]):
        _fail(f"signature.cpus is the reference {REFERENCE_CPUS}; got {sig['cpus']!r}")
    if not _is_int(sig["workers"]) or sig["workers"] != ig.get("workers"):
        _fail(
            f"signature.workers {sig['workers']!r} is not the chart's worker count "
            f"{ig.get('workers')!r}"
        )
    if not isinstance(sig["image"], str) or not _IMAGE_RE.match(sig["image"]):
        _fail(f"signature.image is not a canonical B1 image fingerprint: {sig['image']!r}")
    identity = gc3_selected_identity(decision)
    for field in ("cpuModel", "referenceTopology", "placementSchema", "topologyDecisionHeadSha"):
        if sig[field] != identity[field]:
            _fail(
                f"signature.{field} {sig[field]!r} is not the current GC-3 selected "
                f"decision's {identity[field]!r}"
            )


def _run_id_order(run_id: str) -> "tuple[int, int]":
    left, right = run_id.split("/", 1)
    return int(left), int(right)


def _validate_run_id(value, where: str) -> str:
    if not isinstance(value, str) or not _RUN_ID_RE.match(value):
        _fail(f"{where} is not a <run_id>/<attempt> identity: {value!r}")
    return value


def _validate_observation(index: int, entry, sig: dict) -> "tuple[str, float]":
    where = f"observations[{index}]"
    if not isinstance(entry, dict):
        _fail(f"{where} is not an object")
    if set(entry) != OBSERVATION_KEYS:
        missing = sorted(OBSERVATION_KEYS - set(entry))
        unknown = sorted(set(entry) - OBSERVATION_KEYS)
        _fail(f"{where} closed keys: missing {missing}, unknown {unknown}")
    for field in SIGNATURE_COPY_KEYS:
        if entry[field] != sig[field]:
            _fail(f"{where}.{field} {entry[field]!r} != signature {sig[field]!r}")
    if entry["headSha"] != sig["headSha"]:
        _fail(f"{where}.headSha {entry['headSha']!r} is not the collection head")
    # FP-B1LB-1: the restated operating point, clause by clause.
    if entry["profile"] != REQUIRED_PROFILE:
        _fail(f"{where}.profile {entry['profile']!r} is not {REQUIRED_PROFILE!r}")
    if entry["measurementAuthority"] != REQUIRED_MEASUREMENT_AUTHORITY:
        _fail(
            f"{where}.measurementAuthority {entry['measurementAuthority']!r} is not "
            f"{REQUIRED_MEASUREMENT_AUTHORITY!r}"
        )
    if not _is_int(entry["offered"]) or entry["offered"] != REQUIRED_OFFERED:
        _fail(f"{where}.offered {entry['offered']!r} is not {REQUIRED_OFFERED}")
    if not _is_int(entry["served"]) or entry["served"] != REQUIRED_SERVED:
        _fail(f"{where}.served {entry['served']!r} is not {REQUIRED_SERVED}")
    if not _is_int(entry["errors"]) or entry["errors"] != 0:
        _fail(f"{where}.errors {entry['errors']!r} is not 0")
    if not _is_int(entry["committed"]) or entry["committed"] != entry["served"]:
        _fail(f"{where}.committed {entry['committed']!r} != served {entry['served']!r}")
    if not _is_number(entry["servedRate"]) or float(entry["servedRate"]) < SERVED_RATE_FLOOR:
        _fail(f"{where}.servedRate {entry['servedRate']!r} is below {SERVED_RATE_FLOOR}")
    if not _is_number(entry["p99Ms"]) or not float(entry["p99Ms"]) < P99_MS_CEILING:
        _fail(f"{where}.p99Ms {entry['p99Ms']!r} is not below {P99_MS_CEILING}")
    if not _is_int(entry["maxInFlight"]) or entry["maxInFlight"] >= MAX_IN_FLIGHT_CEILING:
        _fail(f"{where}.maxInFlight {entry['maxInFlight']!r} is not below {MAX_IN_FLIGHT_CEILING}")
    if entry["platformOnline"] is not True:
        _fail(f"{where}.platformOnline is not True: {entry['platformOnline']!r}")
    if entry["placementOk"] is not True:
        _fail(f"{where}.placementOk is not True: {entry['placementOk']!r}")
    # Worker identity: one stable, sorted, distinct set of exactly W pids.
    pre, post = entry["workerPidsPre"], entry["workerPidsPost"]
    for name, pids in (("workerPidsPre", pre), ("workerPidsPost", post)):
        if not isinstance(pids, list) or not all(_is_int(p) for p in pids):
            _fail(f"{where}.{name} is not a list of integers: {pids!r}")
        if list(pids) != sorted(set(pids)):
            _fail(f"{where}.{name} is not sorted and distinct: {pids!r}")
        if len(pids) != sig["workers"]:
            _fail(f"{where}.{name} holds {len(pids)} pids, not {sig['workers']}")
    if list(pre) != list(post):
        _fail(f"{where} worker set changed: pre={pre!r} post={post!r}")
    cost = _finite_positive(entry["cpuMsPerRequest"], f"{where}.cpuMsPerRequest")
    return _validate_run_id(entry["runId"], f"{where}.runId"), cost


def _validate_discard_reason(where: str, state: str, model, reason) -> None:
    if state in (STATE_UNHOSTABLE, STATE_ABSENT):
        expected = f"{gc3.ROUTE_UNRATIFIED_REASON_PREFIX}{model}"
        if reason != expected:
            _fail(f"{where}.reason {reason!r} is not the GC-3 route reason {expected!r}")
        return
    if state == STATE_UNAVAILABLE:
        if reason != gc3.ROUTE_MODEL_UNAVAILABLE_REASON:
            _fail(
                f"{where}.reason {reason!r} is not "
                f"{gc3.ROUTE_MODEL_UNAVAILABLE_REASON!r}"
            )
        return
    if state == STATE_INVALID:
        if reason not in (gc3.DECISION_MISSING_REASON, gc3.DECISION_INVALID_REASON):
            _fail(f"{where}.reason {reason!r} is not a GC-3 carrier failure reason")
        return
    if state == STATE_NOT_REACHED:
        if not isinstance(reason, str) or not reason.startswith(BENCHMARK_INCOMPLETE_PREFIX):
            _fail(f"{where}.reason {reason!r} does not name an incomplete benchmark step")
        step = reason[len(BENCHMARK_INCOMPLETE_PREFIX):]
        if not step or step != step.strip():
            _fail(f"{where}.reason names no exact failed step: {reason!r}")
        return
    # STATE_SELECTED: the route served, and the run itself was rejected.
    if not isinstance(reason, str):
        _fail(f"{where}.reason is not a string: {reason!r}")
    if reason.startswith(CLAUSE_FAILED_PREFIX):
        names = reason[len(CLAUSE_FAILED_PREFIX):].split(",")
        allowed = B1_PREDICATE_NAMES
        label = "B1 predicate"
    elif reason.startswith(SIGNATURE_MISMATCH_PREFIX):
        names = reason[len(SIGNATURE_MISMATCH_PREFIX):].split(",")
        allowed = SIGNATURE_KEYS
        label = "signature field"
    else:
        _fail(
            f"{where}.reason {reason!r} is neither {CLAUSE_FAILED_PREFIX!r} nor "
            f"{SIGNATURE_MISMATCH_PREFIX!r}"
        )
        return
    if names == [""]:
        _fail(f"{where}.reason names no {label}: {reason!r}")
    unknown = sorted(set(names) - set(allowed))
    if unknown:
        _fail(f"{where}.reason names unknown {label}s {unknown}")
    if names != sorted(set(names)):
        _fail(f"{where}.reason {label} list is not sorted and distinct: {reason!r}")


def _validate_attempts(attempts: list, sig: dict, observation_ids: list) -> None:
    seen: list = []
    for index, row in enumerate(attempts):
        where = f"collection.attempts[{index}]"
        if not isinstance(row, dict):
            _fail(f"{where} is not an object")
        if set(row) != ATTEMPT_KEYS:
            _fail(f"{where} closed keys {sorted(ATTEMPT_KEYS)}; got {sorted(row)}")
        run_id = _validate_run_id(row["runId"], f"{where}.runId")
        if row["headSha"] != sig["headSha"]:
            _fail(f"{where}.headSha {row['headSha']!r} is not the collection head")
        state = row["decisionState"]
        if state not in DECISION_STATES:
            _fail(f"{where}.decisionState {state!r} is not one of {list(DECISION_STATES)}")
        outcome = row["outcome"]
        if outcome not in OUTCOMES:
            _fail(f"{where}.outcome {outcome!r} is not one of {list(OUTCOMES)}")
        model = row["cpuModel"]
        if state in NULL_MODEL_STATES:
            if model is not None:
                _fail(f"{where}.cpuModel is null for a {state} route; got {model!r}")
        elif not isinstance(model, str) or not model:
            _fail(f"{where}.cpuModel is the exact route model string; got {model!r}")
        if outcome == OUTCOME_OBSERVATION:
            if state != STATE_SELECTED:
                _fail(f"{where} is an observation but its route was {state!r}")
            if model != sig["cpuModel"]:
                _fail(f"{where}.cpuModel {model!r} is not the signature model")
            if row["reason"] is not None:
                _fail(f"{where} is an observation and carries a reason: {row['reason']!r}")
            if run_id not in observation_ids:
                _fail(f"{where} links to no observation with runId {run_id!r}")
        else:
            if run_id in observation_ids:
                _fail(f"{where} is discarded but runId {run_id!r} is also an observation")
            _validate_discard_reason(where, state, model, row["reason"])
        seen.append(run_id)
    if len(set(seen)) != len(seen):
        duplicated = sorted({r for r in seen if seen.count(r) > 1})
        _fail(f"collection.attempts repeats run ids {duplicated}")
    order = [_run_id_order(r) for r in seen]
    if order != sorted(order):
        _fail(f"collection.attempts is not ordered by numeric run id then attempt: {seen}")
    linked = [
        row["runId"] for row in attempts if row["outcome"] == OUTCOME_OBSERVATION
    ]
    if sorted(linked) != sorted(observation_ids):
        _fail(
            "every observation is exactly one `observation` attempt; "
            f"attempts link {sorted(linked)} against observations {sorted(observation_ids)}"
        )
    # §3.4(3): the retained interval STOPS at the fifth qualifying run. A
    # trailing discard would mean either a sixth dispatch that the ledger had
    # no business recording, or a qualifying run relabelled out of the five.
    if attempts and attempts[-1]["outcome"] != OUTCOME_OBSERVATION:
        _fail(
            "the attempt interval does not end at the fifth qualifying run; "
            f"the last attempt {attempts[-1]['runId']!r} is discarded"
        )


def validate_sizing_ledger(
    ig: dict, *, check_rendered_cpu: bool = True, decision: "dict | None" = None
) -> None:
    """FP-IG-23 validity + FP-B1LB-2/3/4/5 identity, linkage and recompute.

    Factored so the mutation fixtures can drive the same checks against a
    weakened ledger, and so the chart test never re-implements them.

    Exactly five observations are required unconditionally. An empty ledger --
    including the shipped void 2.427 / observations: [] state -- is red until
    five qualifying CI-scale benchmark-job runs at one collection head are
    recorded. The count is checked FIRST so that the shipped void carrier
    always reports the same `got 0` diagnostic.
    """
    sb = require_ledger_shape(ig)
    obs = sb["observations"]
    if len(obs) != REQUIRED_OBSERVATIONS:
        _fail(f"want exactly five observations, got {len(obs)}")

    sig = sb["signature"]
    _validate_signature(sig, ig, load_gc3_decision() if decision is None else decision)

    run_ids: list = []
    cpu_vals: list = []
    for index, entry in enumerate(obs):
        run_id, cost = _validate_observation(index, entry, sig)
        run_ids.append(run_id)
        cpu_vals.append(cost)
    if len(set(run_ids)) != REQUIRED_OBSERVATIONS:
        _fail(f"the five observations are not pairwise distinct: {run_ids}")
    order = [_run_id_order(r) for r in run_ids]
    if order != sorted(order):
        _fail(f"observations are not ordered by numeric run id then attempt: {run_ids}")

    _validate_attempts(sb["collection"]["attempts"], sig, run_ids)

    recomputed = derive_basis(cpu_vals)
    recorded = sb["cpuMsPerRequest"]
    if not _is_number(recorded) or not math.isfinite(float(recorded)):
        _fail(f"sizingBasis.cpuMsPerRequest is not a finite number: {recorded!r}")
    if abs(float(recorded) - recomputed) >= 1e-9:
        _fail(
            f"sizingBasis.cpuMsPerRequest {recorded!r} is not max+(max-min) "
            f"= {recomputed!r} over the five rows"
        )
    if not check_rendered_cpu:
        return
    expected_request, expected_limit = derive_chart_millicores(recomputed)
    request, limit = rendered_ingest_gateway_cpu()
    if request != expected_request:
        _fail(f"rendered requests.cpu {request}m != ceil(basis x 200) = {expected_request}m")
    if limit != expected_limit:
        _fail(f"rendered limits.cpu {limit}m != 5 x requests = {expected_limit}m")


def _millicores(value) -> int:
    text = str(value)
    return int(text[:-1]) if text.endswith("m") else int(float(text) * 1000)


def rendered_ingest_gateway_cpu() -> "tuple[int, int]":
    """(requests.cpu, limits.cpu) in millicores, from the rendered chart."""
    docs = parse_manifests(helm_template(DBAGENT))
    dep = next(
        d for d in docs
        if d.get("kind") == "Deployment" and "ingest-gateway" in d["metadata"]["name"]
    )
    resources = dep["spec"]["template"]["spec"]["containers"][0]["resources"]
    return _millicores(resources["requests"]["cpu"]), _millicores(resources["limits"]["cpu"])


def chart_resource_expectations(
    ig: dict, *, decision: "dict | None" = None
) -> "tuple[int, int] | None":
    """The derived (request, limit) millicores, or None while collection pends.

    The Phase A pending branch condition is EXACTLY
    ``observations == [] and collection.attempts == []``. Any other ledger
    state -- including a non-empty invalid one -- goes through the validator
    and fails there, so a broken carrier can never be read as "not collected
    yet" (FP-B1LB-5, §3.7 Phase A).
    """
    sb = require_ledger_shape(ig)
    if sb["observations"] == [] and sb["collection"]["attempts"] == []:
        return None
    validate_sizing_ledger(ig, check_rendered_cpu=False, decision=decision)
    return derive_chart_millicores(float(sb["cpuMsPerRequest"]))


def test_sizing_basis_provenance_is_on_reference_and_from_a_serving_run():
    """FP-IG-23: ledger schema + five valid observations + recompute.

    Sited in benchmark step 20, after B1's producing step at 17 (§11.3.3 AC).
    helm is not installed in that job; rendered CPU is FP-IG-4's assertion.

    Against the unfixed tree: red -- no signature block and no observations.
    Against the collection-ready tree: still red, with the `got 0` count
    diagnostic -- the ledger is empty and valid runIds cannot be fabricated
    here. Collection is the coordinator's bounded post-review operation
    (FP-B1LB-4): at most 20 ordinary `benchmark` dispatches at one collection
    head, every one of them recorded in `collection.attempts`, and the five
    observations are the first five qualifying selected-signature runs in that
    sequence. The void 2.427 figure stays in values.yaml as a historical label
    only; it does not satisfy this test. This node is the shared final owner of
    the four synthetic per-FP tests below: they are green on fixtures, and only
    this one is green on the real carrier once five real rows exist.
    """
    values = yaml.safe_load(VALUES_YAML.read_text(encoding="utf-8"))
    validate_sizing_ledger(values["ingestGateway"], check_rendered_cpu=False)


# ---------------------------------------------------------------------------
# Synthetic fixtures. Unmistakably non-production identities and values, used
# ONLY to mutation-test each rule. They never enter values.yaml, the threshold
# notes or any acceptance evidence (§3.3, out of scope).
# ---------------------------------------------------------------------------
FIXTURE_HEAD_SHA = "0" * 40
FIXTURE_IMAGE = "os-release:0000000000000000"
#: Exactly representable in binary, so ceil(basis x 200) has no float artefact.
FIXTURE_COSTS = (1.0, 1.25, 1.5, 1.125, 1.375)
FIXTURE_RUN_IDS = ("11/1", "22/1", "33/1", "44/1", "55/1")
FIXTURE_OTHER_MODEL = "Synthetic Fixture CPU @ 0.00GHz"
FIXTURE_OTHER_TOPOLOGY = "postgres-isolated"


def _fixture_signature(**overrides) -> dict:
    identity = gc3_selected_identity(load_gc3_decision())
    signature = {
        "headSha": FIXTURE_HEAD_SHA,
        "cpus": REFERENCE_CPUS,
        "cpuModel": identity["cpuModel"],
        "image": FIXTURE_IMAGE,
        "workers": 4,
        "referenceTopology": identity["referenceTopology"],
        "placementSchema": identity["placementSchema"],
        "topologyDecisionHeadSha": identity["topologyDecisionHeadSha"],
    }
    signature.update(overrides)
    return signature


def _valid_observation(run_id: str, cpu: float, sig: dict) -> dict:
    pids = [1000 + i for i in range(sig["workers"])]
    entry = {
        "runId": run_id,
        "headSha": sig["headSha"],
        "profile": REQUIRED_PROFILE,
        "measurementAuthority": REQUIRED_MEASUREMENT_AUTHORITY,
        "cpuMsPerRequest": cpu,
        "offered": REQUIRED_OFFERED,
        "served": REQUIRED_SERVED,
        "errors": 0,
        "committed": REQUIRED_SERVED,
        "p99Ms": 96.0,
        "servedRate": 499.0,
        "maxInFlight": 75,
        "platformOnline": True,
        "placementOk": True,
        "workerPidsPre": list(pids),
        "workerPidsPost": list(pids),
    }
    for field in SIGNATURE_COPY_KEYS:
        entry[field] = sig[field]
    return entry


def _observation_attempt(run_id: str, sig: dict) -> dict:
    return {
        "runId": run_id,
        "headSha": sig["headSha"],
        "cpuModel": sig["cpuModel"],
        "decisionState": STATE_SELECTED,
        "outcome": OUTCOME_OBSERVATION,
        "reason": None,
    }


def _filled_ledger(*, cpu_vals=None, mutate=None, signature=None) -> dict:
    sig = dict(signature or _fixture_signature())
    costs = list(cpu_vals or FIXTURE_COSTS)
    observations = [
        _valid_observation(FIXTURE_RUN_IDS[i], costs[i], sig)
        for i in range(REQUIRED_OBSERVATIONS)
    ]
    attempts = [_observation_attempt(run_id, sig) for run_id in FIXTURE_RUN_IDS]
    ig = {
        "workers": sig["workers"],
        "sizingBasis": {
            "cpuMsPerRequest": derive_basis(costs),
            "signature": sig,
            "collection": {"attempts": attempts},
            "observations": observations,
        },
    }
    if mutate:
        mutate(ig)
    return ig


def _expect_red(name: str, mutate) -> None:
    try:
        validate_sizing_ledger(_filled_ledger(mutate=mutate), check_rendered_cpu=False)
    except AssertionError:
        return
    raise AssertionError(f"{name} stayed green; the validity rule is absent")


# ---------------------------------------------------------------------------
# Function tests, one per FP owned by this file
# ---------------------------------------------------------------------------
def test_fp_b1lb_1_operating_point_rules():
    """FP-B1LB-1: the warrant is the unchanged, serving CI-scale operating point.

    The restated literals are asserted as themselves, the positive fixture is
    green, and each product-local/probe literal that the frozen clause used to
    require is independently red. This claims nothing about product capacity.
    """
    assert (REQUIRED_PROFILE, REQUIRED_MEASUREMENT_AUTHORITY) == (
        "ci-scale", "ci-scale-reference"
    )
    assert (REQUIRED_OFFERED, REQUIRED_SERVED) == (15000, 15000)
    assert (SERVED_RATE_FLOOR, P99_MS_CEILING, MAX_IN_FLIGHT_CEILING) == (450, 150, 500)
    validate_sizing_ledger(_filled_ledger(), check_rendered_cpu=False)

    def _row(index, **fields):
        def mutate(ig):
            ig["sizingBasis"]["observations"][index].update(fields)
        return mutate

    # The retired product-local literals: 30000 served, a 200/s floor and a
    # 1000 in-flight cap are exactly what this slice stops accepting.
    _expect_red("product_scale_served_30000", _row(0, served=30000, committed=30000))
    _expect_red("product_scale_offered_30000", _row(0, offered=30000))
    _expect_red("served_rate_at_the_retired_200_floor", _row(0, servedRate=200.0))
    _expect_red("max_in_flight_at_the_retired_1000_cap", _row(0, maxInFlight=999))
    _expect_red("max_in_flight_reached_the_ci_scale_cap", _row(0, maxInFlight=500))
    _expect_red("product_local_authority", _row(0, measurementAuthority="product-local-reference"))
    _expect_red("product_profile", _row(0, profile="product-exclusive"))
    _expect_red("probe_profile", _row(0, profile="ci-scale-probe"))
    _expect_red("local_replica_authority", _row(0, measurementAuthority="local-replica"))
    _expect_red("p99_at_the_ceiling", _row(0, p99Ms=150.0))
    _expect_red("served_rate_below_the_floor", _row(0, servedRate=449.9))
    _expect_red("errors_nonzero", _row(0, errors=1))
    _expect_red("committed_ne_served", _row(0, committed=14999))
    _expect_red("platform_not_online", _row(0, platformOnline=False))
    _expect_red("placement_not_ok", _row(0, placementOk=False))
    _expect_red("placement_ok_is_truthy_not_true", _row(0, placementOk=1))
    _expect_red("platform_online_is_truthy_not_true", _row(0, platformOnline=1))
    _expect_red("worker_set_changed", _row(0, workerPidsPost=[9, 10, 11, 12]))
    _expect_red("duplicate_pids", _row(0, workerPidsPre=[1, 1, 1, 1]))
    _expect_red("unsorted_pids", _row(0, workerPidsPre=[1003, 1002, 1001, 1000]))
    _expect_red("worker_count_drift", _row(0, workerPidsPre=[1, 2, 3], workerPidsPost=[1, 2, 3]))


def test_fp_b1lb_2_gc3_identity_binding():
    """FP-B1LB-2: one chart basis, one exact GC-3-selected identity.

    The carrier is read through GC-3's own validator; selection is not
    reimplemented. Zero and two current `selected` models both fail closed,
    and every identity field is independently discriminating.
    """
    decision = load_gc3_decision()
    identity = gc3_selected_identity(decision)
    selected = {
        model: entry for model, entry in decision["models"].items()
        if entry.get("status") == "selected"
    }
    assert list(selected) == [identity["cpuModel"]]
    entry = selected[identity["cpuModel"]]
    assert identity["referenceTopology"] == entry["selected"]
    assert identity["placementSchema"] == entry["placementSchema"]
    assert identity["topologyDecisionHeadSha"] == entry["evidenceHeadSha"]

    # Fail-closed cardinality: neither zero nor two selected models may route.
    for count, models in (
        (0, {"m": {"status": "unhostable"}}),
        (2, {"a": dict(entry), "b": dict(entry)}),
    ):
        try:
            gc3_selected_identity({"models": models})
        except AssertionError as exc:
            assert "exactly one current GC-3 selected model" in str(exc)
        else:
            raise AssertionError(f"{count} selected models stayed green")

    validate_sizing_ledger(_filled_ledger(), check_rendered_cpu=False)
    for field, replacement in (
        ("cpuModel", FIXTURE_OTHER_MODEL),
        ("referenceTopology", FIXTURE_OTHER_TOPOLOGY),
        ("placementSchema", 2),
        ("topologyDecisionHeadSha", "f" * 40),
    ):
        signature = _fixture_signature(**{field: replacement})
        try:
            validate_sizing_ledger(
                _filled_ledger(signature=signature), check_rendered_cpu=False
            )
        except AssertionError as exc:
            assert f"signature.{field}" in str(exc), str(exc)
        else:
            raise AssertionError(f"a {field} unlike the GC-3 decision stayed green")
    _expect_red("malformed_collection_head", lambda ig: ig["sizingBasis"]["signature"].__setitem__("headSha", "nope"))
    _expect_red("cpus_not_reference_4", lambda ig: (
        ig["sizingBasis"]["signature"].__setitem__("cpus", 16),
        [e.__setitem__("cpus", 16) for e in ig["sizingBasis"]["observations"]],
    ))
    _expect_red("workers_not_the_chart_count", lambda ig: ig.__setitem__("workers", 8))
    _expect_red("image_is_not_a_fingerprint", lambda ig: (
        ig["sizingBasis"]["signature"].__setitem__("image", "unknown"),
        [e.__setitem__("image", "unknown") for e in ig["sizingBasis"]["observations"]],
    ))
    _expect_red("signature_key_added", lambda ig: ig["sizingBasis"]["signature"].__setitem__("cpuQuota", 2))
    _expect_red("signature_key_removed", lambda ig: ig["sizingBasis"]["signature"].pop("image"))


def test_fp_b1lb_3_five_distinct_rows():
    """FP-B1LB-3: exactly five distinct, same-identity, fully valid rows."""
    validate_sizing_ledger(_filled_ledger(), check_rendered_cpu=False)

    def _resize(count):
        def mutate(ig):
            sb = ig["sizingBasis"]
            sb["observations"] = sb["observations"][:count]
            sb["collection"]["attempts"] = sb["collection"]["attempts"][:count]
            sb["cpuMsPerRequest"] = derive_basis(
                [e["cpuMsPerRequest"] for e in sb["observations"]] or [1.0]
            )
        return mutate

    for count in (0, 4, 3):
        _expect_red(f"observation_count_{count}", _resize(count))
    try:
        validate_sizing_ledger(_filled_ledger(mutate=_resize(0)), check_rendered_cpu=False)
    except AssertionError as exc:
        assert "got 0" in str(exc), str(exc)
    _expect_red("copied_row", lambda ig: ig["sizingBasis"]["observations"].__setitem__(
        1, _valid_observation(FIXTURE_RUN_IDS[0], FIXTURE_COSTS[1], ig["sizingBasis"]["signature"])
    ))
    _expect_red("unordered_rows", lambda ig: ig["sizingBasis"]["observations"].reverse())
    _expect_red("malformed_run_id_extra_segment", lambda ig: ig["sizingBasis"]["observations"][0]
                .__setitem__("runId", "1/1/1"))
    _expect_red("malformed_run_id_non_numeric_attempt", lambda ig: ig["sizingBasis"]["observations"][0]
                .__setitem__("runId", "1/bogus"))
    _expect_red("row_key_added", lambda ig: ig["sizingBasis"]["observations"][0]
                .__setitem__("cpuCores", 4))
    _expect_red("row_key_removed", lambda ig: ig["sizingBasis"]["observations"][0].pop("placementOk"))
    _expect_red("row_identity_drift", lambda ig: ig["sizingBasis"]["observations"][2]
                .__setitem__("cpuModel", FIXTURE_OTHER_MODEL))
    _expect_red("row_head_drift", lambda ig: ig["sizingBasis"]["observations"][2]
                .__setitem__("headSha", "b" * 40))
    # Numeric edges on the measured cost.
    for name, value in (
        ("cost_nan", float("nan")),
        ("cost_infinity", float("inf")),
        ("cost_zero", 0.0),
        ("cost_negative", -1.0),
        ("cost_bool", True),
        ("cost_string", "1.5"),
    ):
        _expect_red(name, lambda ig, v=value: ig["sizingBasis"]["observations"][0]
                    .__setitem__("cpuMsPerRequest", v))
    _expect_red("ledger_key_added", lambda ig: ig["sizingBasis"].__setitem__("note", "x"))
    _expect_red("ledger_key_removed", lambda ig: ig["sizingBasis"].pop("collection"))
    _expect_red("collection_key_added", lambda ig: ig["sizingBasis"]["collection"]
                .__setitem__("dispatches", 20))


def test_fp_b1lb_4_attempt_log_linkage_and_reason_form():
    """FP-B1LB-4: the bounded attempt interval's closed linkage and reasons.

    This decides schema, linkage, ordering and reason FORM only. Completeness
    against the retained GitHub workflow history is Phase B review's job: a
    green node here is not completeness proof, and nothing in this file can
    infer an unlisted remote run from YAML alone.
    """
    sig = _fixture_signature()
    discards = {
        STATE_UNHOSTABLE: f"{gc3.ROUTE_UNRATIFIED_REASON_PREFIX}{FIXTURE_OTHER_MODEL}",
        STATE_ABSENT: f"{gc3.ROUTE_UNRATIFIED_REASON_PREFIX}{FIXTURE_OTHER_MODEL}",
        STATE_UNAVAILABLE: gc3.ROUTE_MODEL_UNAVAILABLE_REASON,
        STATE_INVALID: gc3.DECISION_MISSING_REASON,
        STATE_NOT_REACHED: f"{BENCHMARK_INCOMPLETE_PREFIX}B1 -- resource-declared CI-scale ingest-gateway burst",
    }

    def _discard(run_id, state, reason=None, model="keep"):
        if model == "keep":
            model = None if state in NULL_MODEL_STATES else FIXTURE_OTHER_MODEL
        return {
            "runId": run_id,
            "headSha": sig["headSha"],
            "cpuModel": model,
            "decisionState": state,
            "outcome": OUTCOME_DISCARDED,
            "reason": discards[state] if reason is None else reason,
        }

    def _order_key(row):
        # Tolerant of the deliberately malformed-run-id case below: an
        # unparseable identity sorts last rather than breaking the fixture.
        try:
            return (0,) + _run_id_order(row["runId"])
        except (AttributeError, TypeError, ValueError):
            return (1, 0, 0)

    def _with(extra_attempts):
        def mutate(ig):
            attempts = ig["sizingBasis"]["collection"]["attempts"] + list(extra_attempts)
            attempts.sort(key=_order_key)
            ig["sizingBasis"]["collection"]["attempts"] = attempts
        return mutate

    # A complete interval: five linked observations plus every non-serving and
    # failed dispatch that happened between them.
    # Every intervening dispatch is interleaved BEFORE the fifth accepted row,
    # because the retained interval ends there.
    complete = [
        _discard("12/1", STATE_UNHOSTABLE),
        _discard("13/1", STATE_ABSENT),
        _discard("14/1", STATE_UNAVAILABLE),
        _discard("15/1", STATE_INVALID),
        _discard("16/1", STATE_NOT_REACHED),
        _discard("17/1", STATE_SELECTED, f"{CLAUSE_FAILED_PREFIX}errors,p99Ms",
                 model=sig["cpuModel"]),
        _discard("18/1", STATE_SELECTED, f"{SIGNATURE_MISMATCH_PREFIX}image,workers",
                 model=sig["cpuModel"]),
    ]
    validate_sizing_ledger(_filled_ledger(mutate=_with(complete)), check_rendered_cpu=False)

    _expect_red("missing_attempt_for_an_observation",
                lambda ig: ig["sizingBasis"]["collection"]["attempts"].pop(0))
    _expect_red("observation_without_a_linked_attempt", lambda ig: ig["sizingBasis"]["collection"]
                ["attempts"][0].__setitem__("runId", "99/1"))
    _expect_red("qualifying_run_marked_discarded", lambda ig: ig["sizingBasis"]["collection"]
                ["attempts"][0].update({"outcome": OUTCOME_DISCARDED,
                                        "reason": f"{CLAUSE_FAILED_PREFIX}errors"}))
    _expect_red("observation_attempt_carries_a_reason", lambda ig: ig["sizingBasis"]["collection"]
                ["attempts"][0].__setitem__("reason", f"{CLAUSE_FAILED_PREFIX}errors"))
    _expect_red("observation_attempt_on_a_recorded_route", lambda ig: ig["sizingBasis"]["collection"]
                ["attempts"][0].__setitem__("decisionState", STATE_UNHOSTABLE))
    _expect_red("attempt_key_added", lambda ig: ig["sizingBasis"]["collection"]["attempts"][0]
                .__setitem__("conclusion", "success"))
    _expect_red("attempt_key_removed", lambda ig: ig["sizingBasis"]["collection"]["attempts"][0]
                .pop("reason"))
    _expect_red("attempt_head_drift", lambda ig: ig["sizingBasis"]["collection"]["attempts"][0]
                .__setitem__("headSha", "c" * 40))
    _expect_red("duplicate_attempt_run_ids",
                _with([_discard(FIXTURE_RUN_IDS[0], STATE_UNHOSTABLE)]))
    _expect_red("unordered_attempts", lambda ig: ig["sizingBasis"]["collection"]["attempts"].reverse())
    _expect_red("fabricated_attempt_state",
                _with([_discard("6/1", STATE_UNHOSTABLE, "topology_probably_fine")]))
    _expect_red("unknown_decision_state", lambda ig: ig["sizingBasis"]["collection"]["attempts"][0]
                .__setitem__("decisionState", "probably_selected"))
    _expect_red("unknown_outcome", lambda ig: ig["sizingBasis"]["collection"]["attempts"][0]
                .__setitem__("outcome", "retained"))
    for name, attempt in (
        ("unratified_reason_names_another_model",
         _discard("6/1", STATE_UNHOSTABLE, f"{gc3.ROUTE_UNRATIFIED_REASON_PREFIX}other")),
        ("unavailable_reason_drift", _discard("6/1", STATE_UNAVAILABLE, "no_model")),
        ("invalid_reason_drift", _discard("6/1", STATE_INVALID, "gc3_decision_probably_ok")),
        ("not_reached_without_a_step", _discard("6/1", STATE_NOT_REACHED,
                                                BENCHMARK_INCOMPLETE_PREFIX)),
        ("clause_reason_unknown_predicate",
         _discard("6/1", STATE_SELECTED, f"{CLAUSE_FAILED_PREFIX}vibes", model=sig["cpuModel"])),
        ("clause_reason_unsorted",
         _discard("6/1", STATE_SELECTED, f"{CLAUSE_FAILED_PREFIX}p99Ms,errors",
                  model=sig["cpuModel"])),
        ("clause_reason_empty",
         _discard("6/1", STATE_SELECTED, CLAUSE_FAILED_PREFIX, model=sig["cpuModel"])),
        ("signature_mismatch_reason_unknown_field",
         _discard("6/1", STATE_SELECTED, f"{SIGNATURE_MISMATCH_PREFIX}colour",
                  model=sig["cpuModel"])),
        ("unavailable_route_names_a_model",
         _discard("6/1", STATE_UNAVAILABLE, model=FIXTURE_OTHER_MODEL)),
        ("unhostable_route_without_a_model",
         _discard("6/1", STATE_UNHOSTABLE, model=None)),
        ("malformed_attempt_run_id",
         _discard("6/1", STATE_UNHOSTABLE) | {"runId": "six"}),
        # The retained interval must END at the fifth qualifying run.
        ("interval_continues_past_the_fifth_observation",
         _discard("66/1", STATE_UNHOSTABLE)),
    ):
        _expect_red(name, _with([attempt]))


def test_sizing_ledger_mutations_are_red_only_with_validity_rules():
    """Standing test for FP-IG-23 and FP-B1LB-1..5: each named weakening fails.

    Against the unfixed tree every case is independently red (no closed
    signature, no collection carrier, no observations, void 2.427 cannot be
    re-encoded). Cases are red only while the corresponding rule is present.
    """
    validate_sizing_ledger(_filled_ledger(), check_rendered_cpu=False)

    _expect_red("missing_signature", lambda ig: ig["sizingBasis"].pop("signature"))
    _expect_red("missing_observations", lambda ig: ig["sizingBasis"].pop("observations"))
    _expect_red("missing_collection", lambda ig: ig["sizingBasis"].pop("collection"))
    _expect_red(
        "void_basis_with_fabricated_obs",
        lambda ig: ig["sizingBasis"].__setitem__("cpuMsPerRequest", VOID_SIZING_BASIS),
    )
    _expect_red("duplicate_run_ids", lambda ig: ig["sizingBasis"]["observations"][1]
                .__setitem__("runId", FIXTURE_RUN_IDS[0]))
    _expect_red("recompute_mismatch",
                lambda ig: ig["sizingBasis"].__setitem__("cpuMsPerRequest", 9.999))
    _expect_red("recompute_is_max_not_max_plus_spread", lambda ig: ig["sizingBasis"]
                .__setitem__("cpuMsPerRequest", max(FIXTURE_COSTS)))
    _expect_red("basis_not_finite",
                lambda ig: ig["sizingBasis"].__setitem__("cpuMsPerRequest", float("nan")))
    _expect_red("empty_observations", lambda ig: ig["sizingBasis"].__setitem__("observations", []))

    # §3.7 Phase A: a non-empty INVALID ledger may not take the chart test's
    # pending branch. The branch condition is exactly "both carriers empty".
    def _nonempty_invalid(ig):
        ig["sizingBasis"]["observations"] = [{"runId": "1/1"}]
        ig["sizingBasis"]["collection"]["attempts"] = []

    broken = _filled_ledger(mutate=_nonempty_invalid)
    assert broken["sizingBasis"]["observations"] != []
    assert broken["sizingBasis"]["collection"]["attempts"] == []
    try:
        chart_resource_expectations(broken)
    except AssertionError:
        pass
    else:
        raise AssertionError(
            "nonempty_invalid_ledger_cannot_take_pending_chart_branch stayed green; "
            "the pending branch is wider than `observations == [] and attempts == []`"
        )
    # ...and the exact empty condition still reads as pending, not as derived.
    pending = _filled_ledger(mutate=lambda ig: ig["sizingBasis"].update(
        {"observations": [], "collection": {"attempts": []}}
    ))
    assert chart_resource_expectations(pending) is None

    # Unfixed-tree shape: no ledger at all.
    try:
        validate_sizing_ledger({"workers": 4}, check_rendered_cpu=False)
    except AssertionError:
        pass
    else:
        raise AssertionError("unfixed (no sizingBasis) stayed green")


def test_derived_chart_resources_follow_the_ledger_formula():
    """UT: the two derived chart numbers, independent of any rendered chart."""
    assert derive_basis(FIXTURE_COSTS) == 2.0
    assert derive_chart_millicores(2.0) == (400, 2000)
    assert derive_chart_millicores(0.5) == (100, 500)
    # ceil, not round: any fraction of a millicore rounds up.
    assert derive_chart_millicores(1.0000001)[0] == 201
    request, limit = derive_chart_millicores(derive_basis(FIXTURE_COSTS))
    assert limit == 5 * request


# ---------------------------------------------------------------------------
# FP-B1LB-6 — the isolated latency-basis target's fixed entry points
# ---------------------------------------------------------------------------
def _load_ingest_gateway(values_path) -> dict:
    values = yaml.safe_load(Path(values_path).read_text(encoding="utf-8"))
    return values["ingestGateway"]


def validate_latency_basis_preflight(values_path, decision_path) -> dict:
    """Before b1_prepare: a nonempty, fully qualified ledger, or exit 3.

    An unrecorded ledger and an invalid one are DIFFERENT reasons: the first
    is the expected pre-collection state, the second is a broken carrier.
    Neither ever starts a live workload, and neither is a pass.
    """
    try:
        ig = _load_ingest_gateway(values_path)
        sb = require_ledger_shape(ig)
    except Exception as exc:  # noqa: BLE001 - every shape failure is fail-closed
        raise BasisOracleUnobserved(LEDGER_INVALID) from exc
    if sb["observations"] == [] and sb["collection"]["attempts"] == []:
        raise BasisOracleUnobserved(LEDGER_UNRECORDED)
    try:
        validate_sizing_ledger(
            ig, check_rendered_cpu=False, decision=load_gc3_decision(decision_path)
        )
    except Exception as exc:  # noqa: BLE001 - every validity failure is fail-closed
        raise BasisOracleUnobserved(LEDGER_INVALID) from exc
    return sb["signature"]


#: The signature fields a ROUTE record plus the current GC-3 decision can
#: disagree with. Sorted, comma separated, they are the
#: `signature_mismatch:<fields>` reason §3.6 fixes.
ROUTE_VISIBLE_SIGNATURE_FIELDS = (
    "cpuModel", "referenceTopology", "placementSchema", "topologyDecisionHeadSha",
)


def route_signature_mismatch(signature: dict, route: dict, identity: dict) -> list[str]:
    """Which route-visible identity fields differ from the recorded ledger.

    Pure, so every field is independently testable: two of the four cannot be
    produced by a VALID route record on the current carrier at all (the route
    schema pins `placementSchema`, and the decision head is read from the same
    carrier), and defence in depth is exactly what they are for.
    """
    observed = {
        "cpuModel": route["cpuModel"],
        "referenceTopology": route["topology"],
        "placementSchema": route["placementSchema"],
        "topologyDecisionHeadSha": identity["topologyDecisionHeadSha"],
    }
    assert set(observed) == set(ROUTE_VISIBLE_SIGNATURE_FIELDS)
    return sorted(
        field for field, value in observed.items() if value != signature.get(field)
    )


def validate_latency_basis_route(values_path, decision_path, route_path) -> dict:
    """After route/route-fields and before pair discovery: this exact identity.

    A GC-3 recorded route reports ITS OWN canonical reason rather than being
    counted as an oracle pass, and any route-visible signature mismatch is
    named field by field.
    """
    signature = validate_latency_basis_preflight(values_path, decision_path)
    try:
        route = gc3.validate_route(
            json.loads(Path(route_path).read_text(encoding="utf-8"))
        )
    except (gc3.TopologyProbeError, ValueError, OSError) as exc:
        raise BasisOracleRouteError(f"unusable route record {route_path}: {exc}") from exc
    if route["disposition"] != gc3.ROUTE_GATING:
        raise BasisOracleUnobserved(route["reason"])
    identity = gc3_selected_identity(load_gc3_decision(decision_path))
    mismatched = route_signature_mismatch(signature, route, identity)
    if mismatched:
        raise BasisOracleUnobserved(f"{SIGNATURE_MISMATCH_PREFIX}{','.join(mismatched)}")
    return signature


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="test_delivery_sizing_ledger.py",
        description="Fail-closed preconditions for the isolated b1_latency_basis target.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    preflight = sub.add_parser("basis-oracle-preflight")
    preflight.add_argument("--values", required=True)
    preflight.add_argument("--decision", required=True)
    route = sub.add_parser("basis-oracle-route")
    route.add_argument("--values", required=True)
    route.add_argument("--decision", required=True)
    route.add_argument("--route", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "basis-oracle-preflight":
            validate_latency_basis_preflight(args.values, args.decision)
        else:
            validate_latency_basis_route(args.values, args.decision, args.route)
    except BasisOracleUnobserved as exc:
        print(f"{UNOBSERVED_PREFIX}{exc.reason}", file=sys.stderr)
        return UNOBSERVED_EXIT
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
