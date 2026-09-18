"""GC-3 (FP-GC3-1/2/3): the closed B1 reference-topology candidate space.

Test-only and stdlib-only. Nothing here is product code, nothing here runs in
a product process, and nothing here reads a profile, threshold, affinity or
candidate value from the environment or from a caller argument. It is the one
authority for:

* which physical-topology placements the B1 CI-scale burst may be measured
  under (``TOPOLOGY_CLASSES``), and the 28 arms one discovery run measures;
* the closed schema-3 launch contract each arm is launched with;
* the closed ``met``/``missed`` vocabulary a discovery arm records;
* the closed discovery artifact, and what makes one ``invalid``;
* the immutable selector that turns two independent complete artifacts of ONE
  exact CPU model into exactly one ``selected`` or ``unhostable`` decision for
  that model, merged into the model-keyed schema-3 carrier -- additively for a
  new model, and for an already decided one only through an explicit
  ``--supersede`` naming its current head, proved a strict Git ancestor of the
  new pair's head, with the replaced decision retained in full; and
* the pre-placement ``route`` / ``route-fields`` / ``contract-selected``
  commands the ordinary ``b1`` launcher branches on, after its unconditional
  container-free coverage phase and before any live process exists.

It is deliberately importable with nothing but the standard library, because
the shell launcher runs the planner and the collector on the *host* -- outside
the review-runner image, before and after the driver container exists -- while
``test_b1_ingest_burst.py`` imports the same code inside the container so the
live record and the offline decision are produced by one implementation.

The separation the design rests on: a *candidate performance miss is data*,
and only integrity failures (a missing arm, a bad placement, an inconsistent
record) make the discovery route red. Nothing in this module compares a
measurement against a bar in order to decide whether a test passes; the
unchanged ``test_b1_ci_scale_reference_profile`` remains the only outcome
gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

#: The repository this module lives in: `services/gateway/tests/<this file>`.
#: It is the object database the strict-descendant proof reads, and it has no
#: caller or environment override -- a synthetic test monkeypatches this
#: constant to a temporary repository and nothing else may change it.
REPO_ROOT = Path(__file__).resolve().parents[3]


class TopologyProbeError(ValueError):
    """A closed-set rule of this module was violated. Never a performance miss."""


# ---------------------------------------------------------------------------
# Closed vocabulary
# ---------------------------------------------------------------------------

#: The schema of one arm's launch contract. Schema 2 is the GC-1 affinity
#: contract that carries no physical-topology claim; schema 3 adds the
#: topology identity, the reference CPU set and the intentionally unassigned
#: CPU. They are different documents, not versions of one: nothing migrates.
CONTRACT_SCHEMA = 3
#: The schema of the discovery artifact one probe run uploads.
ARTIFACT_SCHEMA = 1
#: Bumped only when the admitted candidate set below changes. Two artifacts
#: with different values are not comparable evidence.
TOPOLOGY_SET_VERSION = 1

PROBE_PROFILE_NAME = "ci-scale-probe"
#: The ordinary CI-scale gate's profile. Under GC-3 its launch contract is
#: schema 3 as well -- it carries the ratified topology of the exact host model
#: -- but it has no round or orientation: it is not a discovery arm.
SELECTED_PROFILE_NAME = "ci-scale"
PROBE_JOB = "b1-topology-probe"
PLACEMENT_MECHANISM = "sched-affinity"
REFERENCE_LOGICAL_CPUS = 4
#: There is deliberately NO reference-SKU literal here. The standard
#: `ubuntu-latest` four-vCPU pool rotates among exact CPU model strings, so
#: evidence, ratification and routing are keyed by the exact canonical model an
#: artifact or a host reports, and a pair is admitted only when the two
#: artifacts' own validated model strings are equal to each other. There is no
#: allowlist of manufacturer, family or SKU text, and no prefix, vendor or
#: case-fold fallback: an unknown spelling is an unratified model, never a
#: borrowed decision.
ROLES = ("gateway", "postgres", "driver")
ROUNDS = (0, 1)
ORIENTATIONS = (0, 1)

VERDICT_MET = "met"
VERDICT_MISSED = "missed"
VERDICTS = (VERDICT_MET, VERDICT_MISSED)

#: The closed, ordered comparison vocabulary of one discovery arm. Every field
#: is exactly ``met`` or ``missed`` and must agree with the arm's own raw
#: operands. The first block is *integrity*: the live node asserts those
#: directly, because a miss there means the measurement is undefined rather
#: than unsatisfied. The second block is *performance*: a truthful ``missed``
#: is the datum this whole route exists to collect.
INTEGRITY_VERDICT_FIELDS = (
    "offered_eq_15000",
    "served_plus_errors_eq_offered",
    "committed_eq_served",
    "platform_online",
    "worker_set_stable",
)
PERFORMANCE_VERDICT_FIELDS = (
    "errors_eq_zero",
    "served_eq_offered",
    "p99_lt_150_ms",
    "served_rate_gte_450",
    "max_in_flight_lt_500",
)
VERDICT_FIELDS = (
    "offered_eq_15000",
    "served_plus_errors_eq_offered",
    "errors_eq_zero",
    "served_eq_offered",
    "p99_lt_150_ms",
    "committed_eq_served",
    "served_rate_gte_450",
    "max_in_flight_lt_500",
    "platform_online",
    "worker_set_stable",
)

#: The unchanged CI-scale comparison operands, restated here as the literals
#: the probe evaluates against. They are copies of the bar, never a new bar:
#: `test_b1_ci_scale_reference_profile` keeps its own literals and remains the
#: only node that can fail on them.
CI_SCALE_OFFERED = 15000
CI_SCALE_P99_MS = 150.0
CI_SCALE_SUSTAINED_FLOOR = 450
CI_SCALE_MAX_IN_FLIGHT = 500

#: Closed artifact/record failure codes.
FAILURE_CODES = (
    "unsupported_topology",
    "cpu_model_unavailable",
    "arm_failed",
    "missing_arm",
    "duplicate_arm",
    "unknown_arm",
    "record_invalid",
    "identity_drift",
    "duplicate_run_id",
    "collector_failed",
)

ARTIFACT_COMPLETE = "complete"
ARTIFACT_INVALID = "invalid"

DECISION_SELECTED = "selected"
DECISION_UNHOSTABLE = "unhostable"
#: Schema 3 is the model-keyed carrier with provenance: one `models` map whose
#: keys are exact canonical CPU model strings, whose values carry that model's
#: CURRENT decision fields directly -- so routing has one unambiguous source --
#: and an oldest-to-newest `superseded` list of every decision it replaced,
#: each naming the head that replaced it. It is not a migration of schema 1
#: (one flat decision for one fixed SKU) and no compatibility reader for
#: schema 1 or schema 2 survives the one-time checked migration.
DECISION_SCHEMA = 3
#: The decision fields of ONE decision, current or superseded. A history
#: record carries exactly these under `decision` and never nests a history.
DECISION_DECISION_KEYS = frozenset(
    {
        "status", "evidenceHeadSha", "selected", "cardinality", "placementSchema",
        "ratifiable", "score", "artifacts",
    }
)
#: One current model entry: that decision, plus its append-only history.
DECISION_ENTRY_KEYS = DECISION_DECISION_KEYS | {"superseded"}
#: One history record: the whole decision that was replaced, and the head of
#: the decision that replaced it.
DECISION_HISTORY_KEYS = frozenset({"supersededByHeadSha", "decision"})
#: The named, fail-closed reason for an ancestry question local Git cannot
#: answer: a missing object, an unavailable executable, a checkout without the
#: history, or any exit that is neither a clean accept nor a clean reject. It
#: is never softened into an accept and never a network fetch.
DECISION_ANCESTRY_UNAVAILABLE_REASON = "gc3_ancestry_unavailable"
#: The named, fail-closed reason the two delivery carriers report while the
#: decision file does not exist. It never becomes a skip and never a default.
DECISION_MISSING_REASON = "gc3_decision_missing"
#: ...and the distinct reason for a carrier that exists but is corrupt.
#: Infrastructure corruption is never an unratified SKU.
DECISION_INVALID_REASON = "gc3_decision_invalid"
#: The tracked carrier, relative to the repository root, and the exact path the
#: driver container reads it at through its existing read-only source mount.
DECISION_CARRIER_REL = "tests/benchmark/b1_topology_decision.json"

#: A decision-eligible CPU model string. Nonempty, at most this many Unicode
#: code points, no control character, and never the `unknown` sentinel the
#: reader falls back to.
CPU_MODEL_MAX_CODE_POINTS = 256
CPU_MODEL_UNKNOWN = "unknown"

# --- FP-GC3-4: the pre-placement route -------------------------------------
#: The route record's own schema.
ROUTE_SCHEMA = 1
ROUTE_STATE_SELECTED = "selected"
ROUTE_STATE_UNHOSTABLE = "unhostable"
ROUTE_STATE_ABSENT = "absent"
ROUTE_STATE_UNAVAILABLE = "unavailable"
ROUTE_STATE_INVALID = "invalid"
ROUTE_STATES = (
    ROUTE_STATE_SELECTED,
    ROUTE_STATE_UNHOSTABLE,
    ROUTE_STATE_ABSENT,
    ROUTE_STATE_UNAVAILABLE,
    ROUTE_STATE_INVALID,
)
ROUTE_GATING = "gating"
ROUTE_RECORDED = "recorded"
ROUTE_FAILURE = "failure"
ROUTE_DISPOSITIONS = (ROUTE_GATING, ROUTE_RECORDED, ROUTE_FAILURE)
#: The recorded, non-gating reason for an exact model that has no ratified
#: topology -- because its entry says `unhostable`, or because it has no entry
#: at all. Another model's entry is never a fallback.
ROUTE_UNRATIFIED_REASON_PREFIX = "topology_unratified_sku:"
#: ...and the distinct recorded reason for a model that could not be read or
#: does not meet the model-string rules above.
ROUTE_MODEL_UNAVAILABLE_REASON = "topology_cpu_model_unavailable"
ROUTE_KEYS = (
    "schema", "profile", "cpuModel", "decisionState", "disposition", "reason",
    "topology", "cardinality", "placementSchema",
)
ROUTE_NONE = "none"
#: The one line `route` prints on stdout, retained in the benchmark step log.
ROUTE_STDOUT_PREFIX = "B1 topology_route="

_RUN_ID_RE = re.compile(r"\A[0-9a-f]{32}\Z")
_SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z")
_DECIMAL_RE = re.compile(r"\A[0-9]+\Z")
_HTTPS_RUN_URL_RE = re.compile(
    r"\Ahttps://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+\Z"
)


# ---------------------------------------------------------------------------
# Canonical Linux CPU lists
#
# Re-implemented rather than imported: this module is loaded by the host
# planner with nothing but the standard library available, and
# `b1_reference_profile.py` pulls in the driver's third-party stack. A unit
# test pins the two implementations to agree on every shape either accepts.
# ---------------------------------------------------------------------------


def parse_cpu_list(text: str) -> frozenset[int]:
    """Parse canonical Linux CPU-list syntax (``0-3,8``) into a CPU-id set."""
    if not isinstance(text, str):
        raise TopologyProbeError(f"CPU list is not a string: {text!r}")
    stripped = text.strip()
    if not stripped:
        raise TopologyProbeError("CPU list is empty")
    seen: set[int] = set()
    for part in stripped.split(","):
        if part != part.strip() or not part:
            raise TopologyProbeError(f"malformed CPU-list element {part!r} in {text!r}")
        bounds = part.split("-")
        if len(bounds) == 1:
            low_text = high_text = bounds[0]
        elif len(bounds) == 2:
            low_text, high_text = bounds
        else:
            raise TopologyProbeError(f"malformed CPU-list range {part!r} in {text!r}")
        if not (low_text.isdecimal() and high_text.isdecimal()):
            raise TopologyProbeError(f"non-decimal CPU id in {part!r} ({text!r})")
        low, high = int(low_text), int(high_text)
        if high < low:
            raise TopologyProbeError(f"inverted CPU-list range {part!r} in {text!r}")
        for cpu in range(low, high + 1):
            if cpu in seen:
                raise TopologyProbeError(f"duplicate CPU id {cpu} in {text!r}")
            seen.add(cpu)
    return frozenset(seen)


def format_cpu_list(cpus) -> str:
    """Render a CPU-id set in canonical Linux list syntax (``0-3,8``)."""
    ordered = sorted(set(cpus))
    if not ordered:
        raise TopologyProbeError("cannot render an empty CPU list")
    for cpu in ordered:
        if isinstance(cpu, bool) or not isinstance(cpu, int) or cpu < 0:
            raise TopologyProbeError(f"not a CPU id: {cpu!r}")
    parts: list[str] = []
    start = prev = ordered[0]
    for cpu in ordered[1:]:
        if cpu == prev + 1:
            prev = cpu
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = cpu
    parts.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(parts)


# ---------------------------------------------------------------------------
# FP-GC3-1 / FP-GC3-5 — physical topology discovery
# ---------------------------------------------------------------------------

CPU_ROOT = Path("/sys/devices/system/cpu")
THREAD_SIBLINGS_RELATIVE = "topology/thread_siblings_list"
CPU_DIRECTORY_PREFIX = "cpu"


def read_thread_siblings(cpu: int, *, cpu_root: Path = CPU_ROOT) -> frozenset[int]:
    """One CPU's canonical kernel sibling list, or raise.

    Deliberately not fail-soft: under GC-3 the sibling relationship is part of
    the placement gate, so an unreadable or non-canonical value must stop a
    verdict rather than reach a record as ``unavailable``.
    """
    path = Path(cpu_root) / f"{CPU_DIRECTORY_PREFIX}{cpu}" / THREAD_SIBLINGS_RELATIVE
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TopologyProbeError(f"cannot read {path}: {exc}") from exc
    siblings = parse_cpu_list(raw)
    if format_cpu_list(siblings) != raw.strip():
        raise TopologyProbeError(f"{path} carries a non-canonical CPU list {raw.strip()!r}")
    if cpu not in siblings:
        raise TopologyProbeError(
            f"{path} lists {format_cpu_list(siblings)}, which excludes cpu {cpu}"
        )
    return siblings


def sibling_groups(cpus, *, cpu_root: Path = CPU_ROOT) -> dict[int, frozenset[int]]:
    """``{cpu: siblings}`` for every requested CPU, each read independently."""
    return {cpu: read_thread_siblings(cpu, cpu_root=cpu_root) for cpu in sorted(set(cpus))}


def complete_sibling_pairs(allowed, *, cpu_root: Path = CPU_ROOT) -> tuple[tuple[int, int], ...]:
    """Every complete two-thread sibling pair inside ``allowed``, min-id ordered.

    A pair is admitted only when the kernel list holds exactly two CPUs, both
    are allowed, each member's own file names the identical two-member set, and
    the set was not already consumed. Anything else is simply not a pair --
    there is no repair and no partial admission.
    """
    ordered = sorted(set(allowed))
    groups = sibling_groups(ordered, cpu_root=cpu_root)
    consumed: set[frozenset[int]] = set()
    pairs: list[tuple[int, int]] = []
    for cpu in ordered:
        group = groups[cpu]
        if len(group) != 2:
            continue
        if not group <= set(ordered):
            continue
        if any(groups[member] != group for member in sorted(group)):
            continue
        if group in consumed:
            continue
        consumed.add(group)
        low, high = sorted(group)
        pairs.append((low, high))
    return tuple(pairs)


def reference_pairs(allowed, *, cpu_root: Path = CPU_ROOT) -> tuple[tuple[int, int], tuple[int, int]]:
    """The first two complete pairs, or an explicit prerequisite failure."""
    pairs = complete_sibling_pairs(allowed, cpu_root=cpu_root)
    if len(pairs) < 2:
        raise TopologyProbeError(
            "the allowed CPU set "
            f"{format_cpu_list(allowed) if allowed else '<empty>'} offers "
            f"{len(pairs)} complete two-thread sibling pair(s); the B1 reference "
            "topology needs two. This host cannot host the reference deployment; "
            "it is not substituted with four unrelated CPUs."
        )
    return pairs[0], pairs[1]


def serialize_sibling_map(cpu_ids, groups: dict[int, frozenset[int]]) -> str:
    """``<cpu>:<siblings>`` for each CPU of one role, CPU-id sorted, ``+``-joined."""
    ordered = sorted(set(cpu_ids))
    if not ordered:
        raise TopologyProbeError("no CPU to render a sibling map for")
    missing = [cpu for cpu in ordered if cpu not in groups]
    if missing:
        raise TopologyProbeError(f"no sibling reading for CPUs {missing}")
    return "+".join(f"{cpu}:{format_cpu_list(groups[cpu])}" for cpu in ordered)


def parse_sibling_map(rendered: str) -> dict[int, frozenset[int]]:
    """Inverse of :func:`serialize_sibling_map`; refuses any other shape."""
    if not isinstance(rendered, str) or not rendered:
        raise TopologyProbeError(f"sibling map is not a non-empty string: {rendered!r}")
    out: dict[int, frozenset[int]] = {}
    for entry in rendered.split("+"):
        head, _, tail = entry.partition(":")
        if not _DECIMAL_RE.match(head) or not tail:
            raise TopologyProbeError(f"malformed sibling-map entry {entry!r} in {rendered!r}")
        cpu = int(head)
        if cpu in out:
            raise TopologyProbeError(f"sibling map repeats cpu {cpu} in {rendered!r}")
        siblings = parse_cpu_list(tail)
        if format_cpu_list(siblings) != tail:
            raise TopologyProbeError(f"sibling map entry {entry!r} is not canonical")
        if cpu not in siblings:
            raise TopologyProbeError(f"sibling map entry {entry!r} excludes its own cpu")
        out[cpu] = siblings
    if serialize_sibling_map(out, out) != rendered:
        raise TopologyProbeError(f"sibling map {rendered!r} is not CPU-id sorted")
    return out


# ---------------------------------------------------------------------------
# FP-GC3-1 — the closed candidate space
#
# Positions are (a, b) = the first complete sibling pair and (c, d) = the
# second, so every class below is a *relationship*, not a CPU-id literal: the
# same seven classes mean the same thing on a hosted four-vCPU runner (pairs
# 0-1 and 2-3) and on an i7 replica (pairs 0,8 and 1,9).
# ---------------------------------------------------------------------------

POSITIONS = ("a", "b", "c", "d")

TOPOLOGY_CLASSES: dict[str, dict[str, tuple[str, ...]]] = {
    "gateway-core": {
        "gateway": ("a", "b"), "postgres": ("c",), "driver": ("d",), "unassigned": (),
    },
    "gateway-split": {
        "gateway": ("a", "c"), "postgres": ("b",), "driver": ("d",), "unassigned": (),
    },
    "postgres-core": {
        "gateway": ("a",), "postgres": ("c", "d"), "driver": ("b",), "unassigned": (),
    },
    "postgres-split": {
        "gateway": ("b",), "postgres": ("a", "c"), "driver": ("d",), "unassigned": (),
    },
    "postgres-isolated": {
        "gateway": ("a",), "postgres": ("c",), "driver": ("b",), "unassigned": ("d",),
    },
    "driver-isolated": {
        "gateway": ("a",), "postgres": ("b",), "driver": ("c",), "unassigned": ("d",),
    },
    "gateway-isolated": {
        "gateway": ("c",), "postgres": ("a",), "driver": ("b",), "unassigned": ("d",),
    },
}
TOPOLOGY_IDS = tuple(sorted(TOPOLOGY_CLASSES))
ARMS_PER_ARTIFACT = len(TOPOLOGY_IDS) * len(ORIENTATIONS) * len(ROUNDS)


def topology_cardinality(topology: str) -> dict[str, int]:
    """Exact per-role CPU cardinality of one class, derived from its map."""
    klass = _topology_class(topology)
    return {role: len(klass[role]) for role in ROLES}


def topology_unassigned_cardinality(topology: str) -> int:
    return len(_topology_class(topology)["unassigned"])


def _topology_class(topology: str) -> dict[str, tuple[str, ...]]:
    klass = TOPOLOGY_CLASSES.get(topology)
    if klass is None:
        raise TopologyProbeError(
            f"unknown topology {topology!r}; the closed set is {list(TOPOLOGY_IDS)}"
        )
    return klass


def orientation_positions(
    pair0: tuple[int, int], pair1: tuple[int, int], orientation: int
) -> dict[str, int]:
    """Bind ``a b c d`` to CPU ids under one of the two fixed orientations.

    Orientation 0 is ``(a, b, c, d)``; orientation 1 applies the renaming
    ``(a, b, c, d) -> (d, c, b, a)``, swapping both the physical-core order and
    the sibling-thread order, so a selection cannot depend on which core or
    which SMT thread the kernel enumerated first.
    """
    if orientation not in ORIENTATIONS:
        raise TopologyProbeError(f"orientation must be one of {list(ORIENTATIONS)}; got {orientation!r}")
    for pair in (pair0, pair1):
        if not (isinstance(pair, tuple) and len(pair) == 2):
            raise TopologyProbeError(f"sibling pair must be a 2-tuple; got {pair!r}")
        if pair[0] >= pair[1]:
            raise TopologyProbeError(f"sibling pair {pair!r} is not internally ordered")
    cpus = (pair0[0], pair0[1], pair1[0], pair1[1])
    if len(set(cpus)) != 4:
        raise TopologyProbeError(f"sibling pairs {pair0!r}/{pair1!r} are not disjoint")
    ordered = cpus if orientation == 0 else tuple(reversed(cpus))
    return dict(zip(POSITIONS, ordered))


def topology_mapping(
    topology: str, pair0: tuple[int, int], pair1: tuple[int, int], orientation: int
) -> dict[str, frozenset[int]]:
    """The role -> CPU-set mapping of one class under one orientation."""
    klass = _topology_class(topology)
    bound = orientation_positions(pair0, pair1, orientation)
    mapping = {role: frozenset(bound[p] for p in klass[role]) for role in ROLES}
    mapping["unassigned"] = frozenset(bound[p] for p in klass["unassigned"])
    _check_mapping(topology, mapping, frozenset(bound.values()))
    return mapping


def _check_mapping(topology: str, mapping: dict[str, frozenset[int]], reference: frozenset[int]) -> None:
    """The invariants every admitted class must satisfy, re-checked per arm."""
    cardinality = topology_cardinality(topology)
    # The driver first, and unconditionally: no admitted class gives it two
    # CPUs, because a second driver CPU cannot raise the saturated PostgreSQL
    # role's entitlement and necessarily takes capacity from a binding role.
    if len(mapping["driver"]) != 1:
        raise TopologyProbeError(f"{topology}: the driver must hold exactly one CPU")
    for role in ROLES:
        if len(mapping[role]) != cardinality[role]:
            raise TopologyProbeError(
                f"{topology}: role {role} has {len(mapping[role])} CPUs, class declares "
                f"{cardinality[role]}"
            )
    for left, right in (("gateway", "postgres"), ("gateway", "driver"), ("postgres", "driver")):
        overlap = mapping[left] & mapping[right]
        if overlap:
            raise TopologyProbeError(
                f"{topology}: measured roles {left}/{right} overlap on {sorted(overlap)}"
            )
    union = mapping["gateway"] | mapping["postgres"] | mapping["driver"]
    if union & mapping["unassigned"]:
        raise TopologyProbeError(
            f"{topology}: the unassigned CPU {sorted(union & mapping['unassigned'])} is also"
            " assigned to a measured role"
        )
    if union | mapping["unassigned"] != reference:
        raise TopologyProbeError(
            f"{topology}: the class covers {sorted(union | mapping['unassigned'])}, the "
            f"reference set is {sorted(reference)}"
        )
    if not 0 <= len(mapping["unassigned"]) <= 1:
        raise TopologyProbeError(
            f"{topology}: {len(mapping['unassigned'])} intentionally unassigned CPUs; at most one"
        )


def arm_order() -> tuple[tuple[str, int, int], ...]:
    """The 28 ``(topology, round, orientation)`` arms in execution order.

    Round 1 reverses both the class order and the orientation order, so no
    topology class owns only late arms and no orientation owns only early ones.
    """
    arms: list[tuple[str, int, int]] = []
    for topology in TOPOLOGY_IDS:
        for orientation in (0, 1):
            arms.append((topology, 0, orientation))
    for topology in reversed(TOPOLOGY_IDS):
        for orientation in (1, 0):
            arms.append((topology, 1, orientation))
    return tuple(arms)


def enumerate_arms(
    pair0: tuple[int, int], pair1: tuple[int, int]
) -> tuple[dict[str, object], ...]:
    """The complete, closed arm plan for one pair of sibling pairs."""
    reference = frozenset((*pair0, *pair1))
    arms: list[dict[str, object]] = []
    for index, (topology, round_, orientation) in enumerate(arm_order()):
        mapping = topology_mapping(topology, pair0, pair1, orientation)
        arms.append(
            {
                "index": index,
                "topology": topology,
                "round": round_,
                "orientation": orientation,
                "referenceCpus": format_cpu_list(reference),
                "roles": {role: format_cpu_list(mapping[role]) for role in ROLES},
                "unassignedCpus": (
                    format_cpu_list(mapping["unassigned"]) if mapping["unassigned"] else "none"
                ),
            }
        )
    seen = {(a["topology"], a["round"], a["orientation"]) for a in arms}
    if len(seen) != ARMS_PER_ARTIFACT or len(arms) != ARMS_PER_ARTIFACT:
        raise TopologyProbeError(
            f"the plan holds {len(arms)} arms ({len(seen)} unique); the closed set is "
            f"{ARMS_PER_ARTIFACT}"
        )
    return tuple(arms)


# ---------------------------------------------------------------------------
# FP-GC3-1 — the schema-3 launch contract
# ---------------------------------------------------------------------------

PROBE_CONTRACT_KEYS = frozenset(
    {
        "schema", "runId", "profile", "referenceLogicalCpus", "referenceCpus",
        "mechanism", "topology", "round", "orientation", "roles",
    }
)
#: The ordinary CI-scale gate's schema-3 contract: the same document without a
#: round or an orientation, because it is one ratified placement and not a
#: discovery arm. Orientation 0 is the only rendering `contract-selected` emits.
SELECTED_CONTRACT_KEYS = PROBE_CONTRACT_KEYS - {"round", "orientation"}
SELECTED_ORIENTATION = 0


def arm_contract(arm: dict, run_id: str) -> dict:
    """One arm's complete schema-3 launch contract."""
    if not isinstance(run_id, str) or not _RUN_ID_RE.match(run_id):
        raise TopologyProbeError(f"runId must be 32 lowercase hex characters; got {run_id!r}")
    return {
        "schema": CONTRACT_SCHEMA,
        "runId": run_id,
        "profile": PROBE_PROFILE_NAME,
        "referenceLogicalCpus": REFERENCE_LOGICAL_CPUS,
        "referenceCpus": arm["referenceCpus"],
        "mechanism": PLACEMENT_MECHANISM,
        "topology": arm["topology"],
        "round": arm["round"],
        "orientation": arm["orientation"],
        "roles": {role: {"allowedCpus": arm["roles"][role]} for role in ROLES},
    }


def selected_contract(topology: str, pairs, run_id: str) -> dict:
    """The ordinary CI-scale schema-3 contract for one ratified topology.

    ``pairs`` are the two complete sibling pairs the launcher observed; the
    class map is applied at the fixed orientation 0. The shell supplies the
    observed pairs and the route-selected class and nothing else -- it never
    becomes a second topology author, and no role mapping, cardinality,
    profile or model value can be passed in.
    """
    if not isinstance(run_id, str) or not _RUN_ID_RE.match(run_id):
        raise TopologyProbeError(f"runId must be 32 lowercase hex characters; got {run_id!r}")
    _topology_class(topology)
    normalized: list[tuple[int, int]] = []
    for pair in pairs:
        cpus = sorted(parse_cpu_list(pair) if isinstance(pair, str) else set(pair))
        if len(cpus) != 2:
            raise TopologyProbeError(f"sibling pair {pair!r} is not two CPUs")
        normalized.append((cpus[0], cpus[1]))
    if len(normalized) != 2:
        raise TopologyProbeError(f"expected exactly two sibling pairs; got {pairs!r}")
    normalized.sort()
    pair0, pair1 = normalized
    reference = frozenset((*pair0, *pair1))
    if len(reference) != REFERENCE_LOGICAL_CPUS:
        raise TopologyProbeError(
            f"sibling pairs {pairs!r} are not disjoint; they cover {sorted(reference)}"
        )
    mapping = topology_mapping(topology, pair0, pair1, SELECTED_ORIENTATION)
    return {
        "schema": CONTRACT_SCHEMA,
        "runId": run_id,
        "profile": SELECTED_PROFILE_NAME,
        "referenceLogicalCpus": REFERENCE_LOGICAL_CPUS,
        "referenceCpus": format_cpu_list(reference),
        "mechanism": PLACEMENT_MECHANISM,
        "topology": topology,
        "roles": {role: {"allowedCpus": format_cpu_list(mapping[role])} for role in ROLES},
    }


def parse_contract(payload: object, *, pairs=None) -> dict:
    """Validate either schema-3 contract -- one arm's, or the ratified gate's.

    The profile selects the shape: the discovery profile carries a round and an
    orientation, the ordinary CI-scale profile carries neither and is always
    rendered at orientation 0. Every other rule -- closed keys, canonical CPU
    lists, role cardinalities, disjointness, the zero-or-one unassigned CPU and
    the independently reconstructed mapping -- is the same code for both.
    """
    if not isinstance(payload, dict):
        raise TopologyProbeError(f"launch contract is not a JSON object: {type(payload).__name__}")
    profile = payload.get("profile")
    if profile == SELECTED_PROFILE_NAME:
        return parse_selected_contract(payload, pairs=pairs)
    return parse_arm_contract(payload, pairs=pairs)


def parse_selected_contract(payload: object, *, pairs=None) -> dict:
    """Validate the ordinary CI-scale schema-3 contract."""
    return _parse_topology_contract(
        payload,
        pairs=pairs,
        profile=SELECTED_PROFILE_NAME,
        keys=SELECTED_CONTRACT_KEYS,
        carries_arm_position=False,
    )


def parse_arm_contract(payload: object, *, pairs=None) -> dict:
    """Validate a schema-3 probe contract and reconstruct its mapping.

    The shell is not a second topology author: it copies the planner's
    contract, and this parser independently re-derives the mapping from the
    closed enumerator and refuses anything that differs.

    ``pairs`` is the observed physical sibling structure of the reference set.
    When it is supplied -- which every live launch and every recorded arm does
    -- the reconstruction is exact: the declared sets must be what the closed
    enumerator derives *for those pairs*, so a mapping that happens to have the
    right cardinalities but the wrong physical relationship is refused. Without
    it the check falls back to "some pairing of the reference set derives this",
    which is all a bare contract can support.
    """
    return _parse_topology_contract(
        payload,
        pairs=pairs,
        profile=PROBE_PROFILE_NAME,
        keys=PROBE_CONTRACT_KEYS,
        carries_arm_position=True,
    )


def _parse_topology_contract(
    payload: object, *, pairs, profile: str, keys: frozenset, carries_arm_position: bool
) -> dict:
    if not isinstance(payload, dict):
        raise TopologyProbeError(f"launch contract is not a JSON object: {type(payload).__name__}")
    got_keys = set(payload)
    if got_keys != set(keys):
        raise TopologyProbeError(
            f"closed schema-{CONTRACT_SCHEMA} probe contract keys "
            f"{sorted(keys)}; got {sorted(got_keys)}"
        )
    if payload["schema"] != CONTRACT_SCHEMA:
        raise TopologyProbeError(f"unsupported contract schema {payload['schema']!r}")
    if payload["profile"] != profile:
        raise TopologyProbeError(f"unsupported probe profile {payload['profile']!r}")
    if payload["mechanism"] != PLACEMENT_MECHANISM:
        raise TopologyProbeError(f"unsupported mechanism {payload['mechanism']!r}")
    if payload["referenceLogicalCpus"] != REFERENCE_LOGICAL_CPUS:
        raise TopologyProbeError(
            f"referenceLogicalCpus is pinned at {REFERENCE_LOGICAL_CPUS}; "
            f"got {payload['referenceLogicalCpus']!r}"
        )
    run_id = payload["runId"]
    if not isinstance(run_id, str) or not _RUN_ID_RE.match(run_id):
        raise TopologyProbeError(f"runId must be 32 lowercase hex characters; got {run_id!r}")
    topology = payload["topology"]
    _topology_class(topology)
    if carries_arm_position:
        round_ = payload["round"]
        orientation = payload["orientation"]
        if isinstance(round_, bool) or round_ not in ROUNDS:
            raise TopologyProbeError(f"round must be one of {list(ROUNDS)}; got {round_!r}")
        if isinstance(orientation, bool) or orientation not in ORIENTATIONS:
            raise TopologyProbeError(
                f"orientation must be one of {list(ORIENTATIONS)}; got {orientation!r}"
            )
    else:
        # The ratified gate is one placement, not an arm: it is rendered at the
        # fixed orientation 0 and carries no round.
        round_ = None
        orientation = SELECTED_ORIENTATION
    reference_raw = payload["referenceCpus"]
    reference = parse_cpu_list(reference_raw)
    if format_cpu_list(reference) != reference_raw:
        raise TopologyProbeError(f"referenceCpus {reference_raw!r} is not canonical")
    if len(reference) != REFERENCE_LOGICAL_CPUS:
        raise TopologyProbeError(
            f"referenceCpus {reference_raw!r} holds {len(reference)} CPUs, not "
            f"{REFERENCE_LOGICAL_CPUS}"
        )
    roles = payload["roles"]
    if not isinstance(roles, dict) or set(roles) != set(ROLES):
        raise TopologyProbeError(f"contract roles must be exactly {sorted(ROLES)}; got {roles!r}")
    declared: dict[str, frozenset[int]] = {}
    for role in ROLES:
        entry = roles[role]
        if not isinstance(entry, dict) or set(entry) != {"allowedCpus"}:
            raise TopologyProbeError(f"role {role!r} must carry exactly ['allowedCpus']; got {entry!r}")
        raw = entry["allowedCpus"]
        cpus = parse_cpu_list(raw)
        if format_cpu_list(cpus) != raw:
            raise TopologyProbeError(f"role {role!r} CPU list {raw!r} is not canonical")
        if not cpus <= reference:
            raise TopologyProbeError(
                f"role {role!r} CPUs {raw} are not inside referenceCpus {reference_raw}"
            )
        declared[role] = cpus
    unassigned = reference - (declared["gateway"] | declared["postgres"] | declared["driver"])
    declared["unassigned"] = unassigned
    _check_mapping(topology, declared, reference)
    # Independent reconstruction: the declared sets must be exactly what the
    # closed enumerator produces for this topology/orientation over the two
    # sibling pairs the reference set implies.
    expected = _reconstruct_mapping(topology, reference, orientation, declared, pairs)
    for role in (*ROLES, "unassigned"):
        if declared[role] != expected[role]:
            raise TopologyProbeError(
                f"{topology}/orientation {orientation}: role {role} declares "
                f"{sorted(declared[role])}, the closed enumerator derives {sorted(expected[role])}"
            )
    return {
        "schema": CONTRACT_SCHEMA,
        "run_id": run_id,
        "profile": profile,
        "mechanism": PLACEMENT_MECHANISM,
        "topology": topology,
        "round": round_,
        "orientation": orientation if carries_arm_position else None,
        "reference_cpus": reference,
        "roles": {role: declared[role] for role in ROLES},
        "unassigned": unassigned,
    }


def normalize_pairs(pairs, reference: frozenset[int]) -> tuple[tuple[int, int], tuple[int, int]]:
    """Two internally ordered, min-id ordered pairs covering exactly ``reference``."""
    normalized = []
    for pair in pairs:
        cpus = sorted(pair if not isinstance(pair, str) else parse_cpu_list(pair))
        if len(cpus) != 2:
            raise TopologyProbeError(f"sibling pair {pair!r} is not two CPUs")
        normalized.append((cpus[0], cpus[1]))
    if len(normalized) != 2:
        raise TopologyProbeError(f"expected exactly two sibling pairs; got {pairs!r}")
    normalized.sort()
    covered = frozenset(cpu for pair in normalized for cpu in pair)
    if len(covered) != 4 or covered != reference:
        raise TopologyProbeError(
            f"sibling pairs cover {sorted(covered)}; the reference set is {sorted(reference)}"
        )
    return normalized[0], normalized[1]


def _reconstruct_mapping(
    topology: str, reference: frozenset[int], orientation: int, declared: dict, pairs
) -> dict[str, frozenset[int]]:
    """Re-derive the mapping the closed enumerator would produce.

    With the observed pairs this is a single exact derivation. Without them --
    a bare contract carries no sibling reading -- it admits any pairing of the
    reference set that derives the declared sets, which is the strongest claim
    available from the contract alone. The live witness in
    ``test_b1_ingest_burst.py`` is what proves the CPUs really are siblings.
    """
    if pairs is not None:
        pair0, pair1 = normalize_pairs(pairs, reference)
        return topology_mapping(topology, pair0, pair1, orientation)
    ordered = sorted(reference)
    canonical = ((ordered[0], ordered[1]), (ordered[2], ordered[3]))
    for candidate in (
        canonical,
        ((ordered[0], ordered[2]), (ordered[1], ordered[3])),
        ((ordered[0], ordered[3]), (ordered[1], ordered[2])),
    ):
        mapping = topology_mapping(topology, candidate[0], candidate[1], orientation)
        if all(mapping[role] == declared[role] for role in ROLES):
            return mapping
    # Nothing matched: report against the canonical pairing so the message
    # names a concrete expectation.
    return topology_mapping(topology, canonical[0], canonical[1], orientation)


# ---------------------------------------------------------------------------
# FP-GC3-2 — verdicts
# ---------------------------------------------------------------------------

OPERAND_KEYS = (
    "offered", "served", "errors", "committed", "p99Ms", "servedRate",
    "maxInFlight", "platformOnline", "workerSetStable",
)


def evaluate_verdicts(operands: dict) -> dict[str, str]:
    """The ten unchanged comparisons, evaluated once, as ``met``/``missed``.

    Every value here is a *datum*. Nothing in this function can fail a test:
    the live node asserts the five integrity statuses separately and
    deliberately does not assert the five performance statuses.
    """
    missing = [key for key in OPERAND_KEYS if key not in operands]
    if missing:
        raise TopologyProbeError(f"verdict operands are incomplete: missing {missing}")
    unknown = sorted(set(operands) - set(OPERAND_KEYS))
    if unknown:
        raise TopologyProbeError(f"unknown verdict operands {unknown}")

    def token(value: bool) -> str:
        return VERDICT_MET if value else VERDICT_MISSED

    verdicts = {
        "offered_eq_15000": token(operands["offered"] == CI_SCALE_OFFERED),
        "served_plus_errors_eq_offered": token(
            operands["served"] + operands["errors"] == operands["offered"]
        ),
        "errors_eq_zero": token(operands["errors"] == 0),
        "served_eq_offered": token(operands["served"] == operands["offered"]),
        "p99_lt_150_ms": token(operands["p99Ms"] < CI_SCALE_P99_MS),
        "committed_eq_served": token(operands["committed"] == operands["served"]),
        "served_rate_gte_450": token(operands["servedRate"] >= CI_SCALE_SUSTAINED_FLOOR),
        "max_in_flight_lt_500": token(operands["maxInFlight"] < CI_SCALE_MAX_IN_FLIGHT),
        "platform_online": token(bool(operands["platformOnline"])),
        "worker_set_stable": token(bool(operands["workerSetStable"])),
    }
    return {field: verdicts[field] for field in VERDICT_FIELDS}


def serialize_verdicts(verdicts: dict) -> str:
    """``field=token,``-joined in the closed order; refuses any other shape."""
    if tuple(verdicts) != VERDICT_FIELDS:
        raise TopologyProbeError(
            f"verdict fields {tuple(verdicts)} are not the closed ordered set {VERDICT_FIELDS}"
        )
    for field, token in verdicts.items():
        if token not in VERDICTS:
            raise TopologyProbeError(f"{field}={token!r} is neither {VERDICT_MET!r} nor {VERDICT_MISSED!r}")
    return ",".join(f"{field}={verdicts[field]}" for field in VERDICT_FIELDS)


# ---------------------------------------------------------------------------
# FP-GC3-2 — the arm record and the discovery artifact
# ---------------------------------------------------------------------------

RECORD_KEYS = frozenset(
    {
        "index", "runId", "topology", "round", "orientation", "profile",
        "referenceCpus", "declaredRoles", "effectiveRoles", "unassignedCpus",
        "siblingMap", "referenceSiblingMap", "fingerprint", "operands", "verdicts",
        "verdictLine",
        "spanSeconds", "postgresUsageUsec", "gatewayCpuCoresUsed",
        "measurementAuthority", "cpuModel", "logicalCpuCount", "siblingPairs",
        "headSha", "githubRunId", "githubRunAttempt", "githubJob", "notes",
    }
)

#: Record fields that must be identical across all 28 records of one artifact.
IDENTITY_KEYS = (
    "cpuModel", "logicalCpuCount", "siblingPairs", "referenceCpus",
    "headSha", "githubRunId", "githubRunAttempt", "githubJob",
    "referenceSiblingMap",
)

ARTIFACT_KEYS = frozenset(
    {
        "schema", "status", "headSha", "githubRunId", "githubJob", "githubRunAttempt",
        "cpuModel", "logicalCpuCount", "referenceCpus", "siblingPairs",
        "topologySetVersion", "arms",
    }
)
INVALID_ARTIFACT_EXTRA_KEYS = frozenset({"failureCode", "missingArms", "failureDetail"})


def validate_record(record: object) -> dict:
    """One arm record: closed keys, legal verdicts, self-consistent operands."""
    if not isinstance(record, dict):
        raise TopologyProbeError(f"arm record is not an object: {type(record).__name__}")
    keys = set(record)
    if keys != RECORD_KEYS:
        raise TopologyProbeError(
            f"arm record keys drift: missing {sorted(RECORD_KEYS - keys)}, "
            f"unknown {sorted(keys - RECORD_KEYS)}"
        )
    reference = parse_cpu_list(record["referenceCpus"])
    pairs = normalize_pairs(record["siblingPairs"], reference)
    contract = parse_arm_contract(
        {
            "schema": CONTRACT_SCHEMA,
            "runId": record["runId"],
            "profile": record["profile"],
            "referenceLogicalCpus": REFERENCE_LOGICAL_CPUS,
            "referenceCpus": record["referenceCpus"],
            "mechanism": PLACEMENT_MECHANISM,
            "topology": record["topology"],
            "round": record["round"],
            "orientation": record["orientation"],
            "roles": {
                role: {"allowedCpus": record["declaredRoles"][role]} for role in ROLES
            },
        },
        pairs=pairs,
    )
    # The recorded sibling reading must be the pairs the record claims, and
    # every role's map must be a slice of it. A record cannot assert a physical
    # relationship its own sysfs reading does not carry.
    observed = parse_sibling_map(record["referenceSiblingMap"])
    if set(observed) != set(reference):
        raise TopologyProbeError(
            f"arm {record['runId']}: referenceSiblingMap covers {sorted(observed)}, the reference "
            f"set is {sorted(reference)}"
        )
    for cpu, siblings in observed.items():
        group = next((pair for pair in pairs if cpu in pair), None)
        if group is None or siblings != frozenset(group):
            raise TopologyProbeError(
                f"arm {record['runId']}: cpu {cpu} siblings {sorted(siblings)} disagree with the "
                f"recorded pairs {[list(p) for p in pairs]}"
            )
    if record["effectiveRoles"] != record["declaredRoles"]:
        raise TopologyProbeError(
            f"arm {record['runId']}: effective roles {record['effectiveRoles']} differ from "
            f"declared {record['declaredRoles']}"
        )
    expected_unassigned = (
        format_cpu_list(contract["unassigned"]) if contract["unassigned"] else "none"
    )
    if record["unassignedCpus"] != expected_unassigned:
        raise TopologyProbeError(
            f"arm {record['runId']}: unassignedCpus {record['unassignedCpus']!r}, class "
            f"derives {expected_unassigned!r}"
        )
    sibling_map = record["siblingMap"]
    if not isinstance(sibling_map, dict) or set(sibling_map) != set(ROLES):
        raise TopologyProbeError(f"arm {record['runId']}: siblingMap must cover exactly {sorted(ROLES)}")
    for role in ROLES:
        role_map = parse_sibling_map(sibling_map[role])
        if set(role_map) != set(contract["roles"][role]):
            raise TopologyProbeError(
                f"arm {record['runId']}: {role} sibling map covers {sorted(role_map)}, the role "
                f"holds {sorted(contract['roles'][role])}"
            )
        for cpu, siblings in role_map.items():
            if siblings != observed[cpu]:
                raise TopologyProbeError(
                    f"arm {record['runId']}: {role} cpu {cpu} siblings {sorted(siblings)} disagree "
                    f"with the reference reading {sorted(observed[cpu])}"
                )
    index = record["index"]
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < ARMS_PER_ARTIFACT:
        raise TopologyProbeError(f"arm index {index!r} is outside 0..{ARMS_PER_ARTIFACT - 1}")
    planned = arm_order()[index]
    if (record["topology"], record["round"], record["orientation"]) != planned:
        raise TopologyProbeError(
            f"arm {index} records {(record['topology'], record['round'], record['orientation'])}, "
            f"the plan enumerates {planned}"
        )
    operands = record["operands"]
    if not isinstance(operands, dict):
        raise TopologyProbeError(f"arm {record['runId']}: operands is not an object")
    verdicts = record["verdicts"]
    # JSON objects carry no order (the artifact is canonically key-sorted), so
    # the ORDER of the closed vocabulary is carried by `verdictLine` below,
    # which is the serializer's own output. The mapping itself is checked for
    # exact membership: an omitted, added or renamed verdict is red here, and a
    # reordered or literalised one is red on the line.
    if not isinstance(verdicts, dict) or set(verdicts) != set(VERDICT_FIELDS):
        raise TopologyProbeError(
            f"arm {record['runId']}: verdict fields "
            f"{sorted(verdicts) if isinstance(verdicts, dict) else verdicts!r} "
            f"are not the closed set {sorted(VERDICT_FIELDS)}"
        )
    recomputed = evaluate_verdicts(dict(operands))
    for field in VERDICT_FIELDS:
        if verdicts[field] not in VERDICTS:
            raise TopologyProbeError(
                f"arm {record['runId']}: {field}={verdicts[field]!r} is not met/missed"
            )
        if verdicts[field] != recomputed[field]:
            raise TopologyProbeError(
                f"arm {record['runId']}: {field}={verdicts[field]!r} disagrees with its own "
                f"operands ({recomputed[field]!r})"
            )
    for field in INTEGRITY_VERDICT_FIELDS:
        if verdicts[field] != VERDICT_MET:
            raise TopologyProbeError(
                f"arm {record['runId']}: integrity status {field} is {verdicts[field]!r}; the "
                f"measurement is undefined, not merely unsatisfied"
            )
    line = record["verdictLine"]
    if not isinstance(line, str) or line != serialize_verdicts(recomputed):
        raise TopologyProbeError(
            f"arm {record['runId']}: verdictLine {line!r} is not the closed ordered "
            f"serialization of its own operands"
        )
    span = record["spanSeconds"]
    if not isinstance(span, (int, float)) or isinstance(span, bool) or span <= 0:
        raise TopologyProbeError(f"arm {record['runId']}: measured span {span!r} is not positive")
    if not _SHA_RE.match(str(record["headSha"])):
        raise TopologyProbeError(f"arm {record['runId']}: headSha {record['headSha']!r} is not 40 hex")
    for field in ("githubRunId", "githubRunAttempt"):
        if not _DECIMAL_RE.match(str(record[field])):
            raise TopologyProbeError(f"arm {record['runId']}: {field}={record[field]!r} is not decimal")
    if record["githubJob"] != PROBE_JOB:
        raise TopologyProbeError(f"arm {record['runId']}: githubJob {record['githubJob']!r}")
    if record["logicalCpuCount"] != REFERENCE_LOGICAL_CPUS:
        raise TopologyProbeError(
            f"arm {record['runId']}: logicalCpuCount {record['logicalCpuCount']!r}"
        )
    return record


def collect_artifact(plan: dict, records: list, *, failure: dict | None = None) -> dict:
    """Combine the immutable plan and every completed record into one artifact.

    ``status`` is ``complete`` only when all 28 planned arms are present, valid,
    mutually consistent and uniquely identified. Everything else is ``invalid``
    with a closed ``failureCode`` and the missing arms named -- never a partial
    artifact that reads like evidence.
    """
    identity = plan["identity"]
    base = {
        "schema": ARTIFACT_SCHEMA,
        "headSha": identity["headSha"],
        "githubRunId": identity["githubRunId"],
        "githubJob": identity["githubJob"],
        "githubRunAttempt": identity["githubRunAttempt"],
        "cpuModel": identity["cpuModel"],
        "logicalCpuCount": identity["logicalCpuCount"],
        "referenceCpus": identity["referenceCpus"],
        "siblingPairs": list(identity["siblingPairs"]),
        "topologySetVersion": plan["topologySetVersion"],
    }
    problems: list[str] = []
    code: str | None = None
    valid: list[dict] = []
    seen_index: dict[int, str] = {}
    seen_run_ids: set[str] = set()
    for raw in records:
        try:
            record = validate_record(raw)
        except TopologyProbeError as exc:
            problems.append(str(exc))
            code = code or "record_invalid"
            continue
        if record["index"] in seen_index:
            problems.append(f"arm index {record['index']} recorded twice")
            code = code or "duplicate_arm"
            continue
        if record["runId"] in seen_run_ids:
            problems.append(f"runId {record['runId']} reused across arms")
            code = code or "duplicate_run_id"
            continue
        drifted = [
            key for key in IDENTITY_KEYS
            if key in base and record[key] != base[key]
        ]
        drifted += [
            key for key in IDENTITY_KEYS
            if key not in base and valid and record[key] != valid[0][key]
        ]
        if drifted:
            problems.append(f"arm {record['index']} identity drift on {sorted(set(drifted))}")
            code = code or "identity_drift"
            continue
        seen_index[record["index"]] = record["runId"]
        seen_run_ids.add(record["runId"])
        valid.append(record)

    # FP-GC3-3/4: an artifact whose own model string is unreadable or outside
    # the closed validity rules cannot key a decision, so it is `invalid` with
    # its own named code rather than a complete record under the `unknown`
    # sentinel.
    if not is_decision_eligible_cpu_model(base["cpuModel"]):
        problems.append(f"cpuModel {base['cpuModel']!r} is not decision eligible")
        code = code or "cpu_model_unavailable"

    planned_indexes = set(range(ARMS_PER_ARTIFACT))
    unknown = sorted(set(seen_index) - planned_indexes)
    if unknown:
        problems.append(f"records for unplanned arms {unknown}")
        code = code or "unknown_arm"
    missing = sorted(planned_indexes - set(seen_index))
    if failure is not None:
        problems.append(
            f"arm {failure.get('armIndex')} failed with exit status {failure.get('exitCode')}"
        )
        code = "arm_failed" if failure.get("failureCode") is None else failure["failureCode"]
    if missing and code is None:
        code = "missing_arm"
    if missing:
        problems.append(f"missing arms {missing}")
    valid.sort(key=lambda record: record["index"])
    if code is None and not missing:
        return {**base, "status": ARTIFACT_COMPLETE, "arms": valid}
    if code not in FAILURE_CODES:
        raise TopologyProbeError(f"failure code {code!r} is not in the closed set {list(FAILURE_CODES)}")
    return {
        **base,
        "status": ARTIFACT_INVALID,
        "failureCode": code,
        "missingArms": missing,
        "failureDetail": problems,
        "arms": valid,
    }


def canonical_json(payload: dict) -> str:
    """Sorted keys, two-space indent, trailing newline -- byte-reproducible."""
    return json.dumps(payload, sort_keys=True, indent=2) + "\n"


def write_artifact(path: Path, artifact: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(canonical_json(artifact), encoding="utf-8")


def validate_artifact(payload: object) -> dict:
    """A complete artifact, or raise. Used by the selector and the delivery pin."""
    if not isinstance(payload, dict):
        raise TopologyProbeError(f"artifact is not an object: {type(payload).__name__}")
    keys = set(payload)
    allowed = ARTIFACT_KEYS | INVALID_ARTIFACT_EXTRA_KEYS
    if not keys <= allowed or not ARTIFACT_KEYS <= keys:
        raise TopologyProbeError(
            f"artifact keys drift: missing {sorted(ARTIFACT_KEYS - keys)}, "
            f"unknown {sorted(keys - allowed)}"
        )
    if payload["schema"] != ARTIFACT_SCHEMA:
        raise TopologyProbeError(f"artifact schema {payload['schema']!r}")
    if payload["topologySetVersion"] != TOPOLOGY_SET_VERSION:
        raise TopologyProbeError(
            f"artifact topologySetVersion {payload['topologySetVersion']!r} is not "
            f"{TOPOLOGY_SET_VERSION}"
        )
    if payload["status"] != ARTIFACT_COMPLETE:
        raise TopologyProbeError(
            f"artifact status is {payload['status']!r}; only a complete artifact is evidence"
        )
    if payload["githubJob"] != PROBE_JOB:
        raise TopologyProbeError(f"artifact githubJob {payload['githubJob']!r}")
    arms = payload["arms"]
    if not isinstance(arms, list) or len(arms) != ARMS_PER_ARTIFACT:
        raise TopologyProbeError(
            f"a complete artifact carries {ARMS_PER_ARTIFACT} arms; got "
            f"{len(arms) if isinstance(arms, list) else type(arms).__name__}"
        )
    indexes: set[int] = set()
    run_ids: set[str] = set()
    for raw in arms:
        record = validate_record(raw)
        if record["index"] in indexes:
            raise TopologyProbeError(f"artifact repeats arm index {record['index']}")
        if record["runId"] in run_ids:
            raise TopologyProbeError(f"artifact reuses runId {record['runId']}")
        indexes.add(record["index"])
        run_ids.add(record["runId"])
        for key in IDENTITY_KEYS:
            if key in payload and record[key] != payload[key]:
                raise TopologyProbeError(
                    f"arm {record['index']} {key}={record[key]!r} disagrees with the artifact"
                )
    if indexes != set(range(ARMS_PER_ARTIFACT)):
        raise TopologyProbeError(f"artifact arm indexes are {sorted(indexes)}")
    return payload


# ---------------------------------------------------------------------------
# FP-GC3-3 — ratification
# ---------------------------------------------------------------------------


def validate_cpu_model(value: object) -> str:
    """A decision-eligible exact CPU model string, or raise.

    The rules are closed and contain no manufacturer, family or SKU text: a
    model is eligible when it is a nonempty string of at most
    ``CPU_MODEL_MAX_CODE_POINTS`` code points, carries no control character,
    and is not the ``unknown`` sentinel the reader falls back to. Exact
    normalized text is the only decision key -- there is no prefix, family,
    vendor or case-fold fallback anywhere in this module.
    """
    if not isinstance(value, str):
        raise TopologyProbeError(f"cpuModel is not a string: {value!r}")
    if not value:
        raise TopologyProbeError("cpuModel is empty")
    if value == CPU_MODEL_UNKNOWN:
        raise TopologyProbeError(
            f"cpuModel {CPU_MODEL_UNKNOWN!r} is the unreadable-host sentinel; it is never a "
            "decision key"
        )
    if len(value) > CPU_MODEL_MAX_CODE_POINTS:
        raise TopologyProbeError(
            f"cpuModel holds {len(value)} code points; at most {CPU_MODEL_MAX_CODE_POINTS}"
        )
    for char in value:
        if ord(char) < 0x20 or ord(char) == 0x7F:
            raise TopologyProbeError(f"cpuModel carries the control character {char!r}")
    if value != " ".join(value.split()):
        raise TopologyProbeError(f"cpuModel {value!r} is not whitespace-canonical")
    return value


def is_decision_eligible_cpu_model(value: object) -> bool:
    """``validate_cpu_model`` as a predicate. No second set of rules."""
    try:
        validate_cpu_model(value)
    except TopologyProbeError:
        return False
    return True


def admit_evidence(first: dict, second: dict) -> str:
    """The six admission properties of one model's pair, and that model.

    The model is not compared against a literal: both artifacts must carry the
    SAME validated canonical `cpuModel`, and that string becomes the decision
    key. Evidence for one model therefore never satisfies, competes with,
    changes the rank of or blocks another model.
    """
    models: list[str] = []
    for artifact in (first, second):
        validate_artifact(artifact)
        if artifact["logicalCpuCount"] != REFERENCE_LOGICAL_CPUS:
            raise TopologyProbeError(
                f"artifact reports {artifact['logicalCpuCount']!r} logical CPUs; the reference "
                f"runner has {REFERENCE_LOGICAL_CPUS}"
            )
        models.append(validate_cpu_model(artifact["cpuModel"]))
        if artifact["githubJob"] != PROBE_JOB:
            raise TopologyProbeError(
                f"artifact githubJob {artifact['githubJob']!r} is not {PROBE_JOB!r}"
            )
        pairs = artifact["siblingPairs"]
        if not isinstance(pairs, list) or len(pairs) != 2:
            raise TopologyProbeError(f"artifact siblingPairs {pairs!r} is not two pairs")
        members: set[int] = set()
        for rendered in pairs:
            cpus = parse_cpu_list(rendered)
            if len(cpus) != 2:
                raise TopologyProbeError(f"sibling pair {rendered!r} is not two CPUs")
            if members & cpus:
                raise TopologyProbeError(f"sibling pairs overlap on {sorted(members & cpus)}")
            members |= cpus
        if members != parse_cpu_list(artifact["referenceCpus"]):
            raise TopologyProbeError(
                f"sibling pairs cover {sorted(members)}, referenceCpus is "
                f"{artifact['referenceCpus']}"
            )
    if first["githubRunId"] == second["githubRunId"]:
        raise TopologyProbeError(
            f"both artifacts come from GitHub run {first['githubRunId']}; two independent runs "
            "are required"
        )
    if first["headSha"] != second["headSha"]:
        raise TopologyProbeError(
            f"artifacts were produced at different heads: {first['headSha']} vs {second['headSha']}"
        )
    if models[0] != models[1]:
        raise TopologyProbeError(
            f"artifacts report different CPU models ({models[0]!r} vs {models[1]!r}); one model's "
            "evidence cannot ratify another model and the pair is not admissible"
        )
    return models[0]


def eligible_topologies(artifact: dict) -> tuple[str, ...]:
    """Classes whose four arm records in this artifact met every comparison."""
    per_class: dict[str, list[dict]] = {topology: [] for topology in TOPOLOGY_IDS}
    for record in artifact["arms"]:
        per_class[record["topology"]].append(record)
    out = []
    for topology in TOPOLOGY_IDS:
        records = per_class[topology]
        if len(records) != len(ORIENTATIONS) * len(ROUNDS):
            continue
        if all(
            record["verdicts"][field] == VERDICT_MET
            for record in records
            for field in VERDICT_FIELDS
        ):
            out.append(topology)
    return tuple(out)


def _class_records(artifacts: tuple[dict, dict], topology: str) -> list[dict]:
    return [
        record
        for artifact in artifacts
        for record in artifact["arms"]
        if record["topology"] == topology
    ]


def score_topology(artifacts: tuple[dict, dict], topology: str) -> tuple[float, int, float, str]:
    """The immutable lexicographic score over all eight records of one class.

    CPU utilisation and CPU cost per request are deliberately absent: they
    explain a result, they cannot prove due-time p99, errors, completion or
    audit accounting.
    """
    records = _class_records(artifacts, topology)
    if len(records) != 8:
        raise TopologyProbeError(f"{topology}: {len(records)} records across both artifacts, need 8")
    worst_p99 = max(float(record["operands"]["p99Ms"]) for record in records)
    worst_in_flight = max(int(record["operands"]["maxInFlight"]) for record in records)
    best_floor = min(float(record["operands"]["servedRate"]) for record in records)
    return (worst_p99, worst_in_flight, -best_floor, topology)


def select_topology(first: dict, second: dict) -> dict:
    """One exact model's decision entry: exactly one selected class, or unhostable.

    The entry is complete on its own -- status, the head both artifacts share,
    the chosen topology, that topology's derived cardinality, the placement
    schema the gate will be launched under, the ordered ratifiable list and the
    exact score operands -- because a model's outcome may never be read out of
    another model's entry or out of a slice-wide default.
    """
    admit_evidence(first, second)
    artifacts = (first, second)
    ratifiable = tuple(
        topology
        for topology in eligible_topologies(first)
        if topology in eligible_topologies(second)
    )
    entry = {
        "status": DECISION_UNHOSTABLE,
        "evidenceHeadSha": first["headSha"],
        "selected": None,
        "cardinality": None,
        "placementSchema": None,
        "ratifiable": list(ratifiable),
        "score": None,
    }
    if not ratifiable:
        return entry
    scored = sorted(score_topology(artifacts, topology) for topology in ratifiable)
    winner = scored[0]
    entry["status"] = DECISION_SELECTED
    entry["selected"] = winner[3]
    entry["cardinality"] = topology_cardinality(winner[3])
    entry["placementSchema"] = CONTRACT_SCHEMA
    entry["score"] = {
        "maxP99Ms": winner[0],
        "maxInFlight": winner[1],
        "minServedRate": -winner[2],
    }
    return entry


def digest_of(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _evidence_wrapper(artifact: dict, path: Path) -> dict:
    """One embedded complete artifact: its run URL, its digest and its bytes."""
    url = f"https://github.com/yabinma/dbagent/actions/runs/{artifact['githubRunId']}"
    if not _HTTPS_RUN_URL_RE.match(url):
        raise TopologyProbeError(f"evidence URL {url!r} is not an https GitHub run URL")
    return {"sourceUrl": url, "sha256": digest_of(path), "artifact": artifact}


def _ordered_pair(paths) -> tuple[Path, Path]:
    """The pair, ordered by numeric GitHub run id then run attempt."""
    entries = []
    for path in paths:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TopologyProbeError(f"{path}: artifact is not an object")
        run_id = payload.get("githubRunId")
        attempt = payload.get("githubRunAttempt")
        if not (isinstance(run_id, str) and _DECIMAL_RE.match(run_id)):
            raise TopologyProbeError(f"{path}: githubRunId {run_id!r} is not decimal text")
        if not (isinstance(attempt, str) and _DECIMAL_RE.match(attempt)):
            raise TopologyProbeError(f"{path}: githubRunAttempt {attempt!r} is not decimal text")
        entries.append((int(run_id), int(attempt), Path(path)))
    entries.sort()
    return entries[0][2], entries[1][2]


def verify_decision_ancestry(named_head: str, pair_head: str) -> None:
    """FP-GC3-7: prove ``pair_head`` is a STRICT descendant of ``named_head``.

    The proof is local Git history, never a field an artifact supplies and
    never a recorded parent-head string: two no-shell commands over
    ``REPO_ROOT``'s own object database, and a three-way outcome. Exit 0 from
    ``merge-base --is-ancestor`` is accepted only because the two values
    already differ, exit 1 is a divergent-or-older rejection, and anything
    else -- a missing object, no Git executable, a checkout without the
    history -- is the named fail-closed reason. There is no fetch and no
    network fallback: the ancestry authorities are the functional CI checkout
    with ``fetch-depth: 0`` and a full-history host checkout.
    """
    for label, sha in (("named head", named_head), ("pair head", pair_head)):
        if not (isinstance(sha, str) and _SHA_RE.match(sha)):
            raise TopologyProbeError(f"{label} {sha!r} is not 40 lowercase hex")
    if named_head == pair_head:
        raise TopologyProbeError(
            f"pair head {pair_head} equals the named head; a supersession requires a "
            "strictly newer product head"
        )
    for sha in (named_head, pair_head):
        try:
            found = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "cat-file", "-e", f"{sha}^{{commit}}"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False, check=False,
            )
        except OSError as exc:
            raise TopologyProbeError(
                f"{DECISION_ANCESTRY_UNAVAILABLE_REASON}: git is unavailable ({exc})"
            ) from exc
        if found.returncode != 0:
            raise TopologyProbeError(
                f"{DECISION_ANCESTRY_UNAVAILABLE_REASON}: {sha} is not a commit object in "
                f"{REPO_ROOT} (cat-file exit {found.returncode}); the ancestry authorities "
                "carry the full history"
            )
    try:
        result = subprocess.run(
            [
                "git", "-C", str(REPO_ROOT),
                "merge-base", "--is-ancestor", named_head, pair_head,
            ],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False, check=False,
        )
    except OSError as exc:
        raise TopologyProbeError(
            f"{DECISION_ANCESTRY_UNAVAILABLE_REASON}: git is unavailable ({exc})"
        ) from exc
    if result.returncode == 0:
        return
    if result.returncode == 1:
        raise TopologyProbeError(
            f"{pair_head} is not a strict descendant of {named_head}; an older or divergent "
            "head never supersedes a decision"
        )
    raise TopologyProbeError(
        f"{DECISION_ANCESTRY_UNAVAILABLE_REASON}: merge-base --is-ancestor exited "
        f"{result.returncode} ({result.stderr.decode('utf-8', 'replace').strip()})"
    )


def decision_chain(entry: dict) -> tuple[str, ...]:
    """One model's heads, oldest to newest, ending at its current decision."""
    return tuple(
        [record["decision"]["evidenceHeadSha"] for record in entry["superseded"]]
        + [entry["evidenceHeadSha"]]
    )


def verify_carrier_ancestry(payload: dict) -> int:
    """Repeat the strict-descendant proof for every retained edge; count them.

    Called by ``decide`` before it considers a new pair, and by the delivery
    tests. Deliberately NOT called by ``route``: the benchmark route classifies
    a host from the validated carrier alone and must work at a checkout of any
    depth, so publication through the Git-backed delivery gate is where the
    ancestry authority lives.
    """
    validate_decision(payload)
    edges = 0
    for entry in payload["models"].values():
        chain = decision_chain(entry)
        for older, newer in zip(chain, chain[1:]):
            verify_decision_ancestry(older, newer)
            edges += 1
    return edges


def build_decision(pair_paths, base_path, supersede=None) -> dict:
    """Merge one model's pair into the complete model-keyed carrier.

    One invocation admits exactly one exact model. The base is REQUIRED and is
    validated, independently recomputed and re-proved -- every current
    decision, every superseded decision and every ancestry edge -- before the
    new pair is considered, so a rejected model-X invocation cannot mutate,
    reorder or erase model Y's entry or history.

    For a model absent from the base, ``supersede`` is forbidden and the
    derived entry is added with an empty history. For a model already present:

    1. an exactly identical derived decision with no ``supersede`` is an
       idempotent no-op;
    2. any nonidentical result with no ``supersede`` is refused;
    3. a supersession requires ``supersede`` to equal that model's current
       ``evidenceHeadSha`` exactly and the pair head to be its strict
       descendant;
    4. retrying that same successful command against its own output is an
       idempotent no-op; and
    5. every other stale, historical, equal-head, older-head, divergent-head
       or nonidentical retry is refused.
    """
    first_path, second_path = _ordered_pair(pair_paths)
    first = json.loads(first_path.read_text(encoding="utf-8"))
    second = json.loads(second_path.read_text(encoding="utf-8"))
    model = admit_evidence(first, second)
    derived = select_topology(first, second)
    derived["artifacts"] = [
        _evidence_wrapper(first, first_path),
        _evidence_wrapper(second, second_path),
    ]
    base = json.loads(Path(base_path).read_text(encoding="utf-8"))
    validate_decision(base)
    verify_carrier_ancestry(base)
    models = {key: json.loads(json.dumps(value)) for key, value in base["models"].items()}
    existing = models.get(model)
    if existing is None:
        if supersede is not None:
            raise TopologyProbeError(
                f"{model!r} has no decision in the base carrier, so there is nothing to "
                f"supersede; --supersede {supersede!r} is refused"
            )
        models[model] = {**derived, "superseded": []}
    else:
        current = {key: existing[key] for key in existing if key != "superseded"}
        history = list(existing["superseded"])
        identical = current == derived
        if supersede is None:
            if not identical:
                raise TopologyProbeError(
                    f"{model!r} already has a decision at head "
                    f"{current['evidenceHeadSha']} and this pair derives a different one; "
                    "pass --supersede <that current evidence head> to replace it"
                )
            models[model] = existing
        elif identical:
            previous = history[-1] if history else None
            retry = (
                previous is not None
                and previous["decision"]["evidenceHeadSha"] == supersede
                and previous["supersededByHeadSha"] == current["evidenceHeadSha"]
            )
            if not retry:
                raise TopologyProbeError(
                    f"{model!r}'s current decision is already this pair's own result at "
                    f"{current['evidenceHeadSha']}; --supersede {supersede!r} is neither a "
                    "replacement nor the exact retry of one"
                )
            models[model] = existing
        else:
            if supersede != current["evidenceHeadSha"]:
                raise TopologyProbeError(
                    f"--supersede {supersede!r} is not {model!r}'s current evidence head "
                    f"{current['evidenceHeadSha']!r}; a stale or historical head never "
                    "authorises a replacement"
                )
            verify_decision_ancestry(
                current["evidenceHeadSha"], derived["evidenceHeadSha"]
            )
            models[model] = {
                **derived,
                "superseded": history + [
                    {
                        "supersededByHeadSha": derived["evidenceHeadSha"],
                        "decision": current,
                    }
                ],
            }
    decision = {
        "schema": DECISION_SCHEMA,
        "topologySetVersion": TOPOLOGY_SET_VERSION,
        "models": models,
    }
    validate_decision(decision)
    return decision


def _recompute_one(model: str, decision: object) -> dict:
    """Re-run the selector over ONE decision's own embedded artifacts, offline."""
    if not isinstance(decision, dict):
        raise TopologyProbeError(f"{model!r}: a decision is not an object")
    embedded = decision.get("artifacts")
    if not isinstance(embedded, list) or len(embedded) != 2:
        raise TopologyProbeError(
            f"{model!r}: a decision embeds exactly two complete artifacts"
        )
    seen_runs: set[str] = set()
    for wrapper in embedded:
        if not isinstance(wrapper, dict) or set(wrapper) != {"sourceUrl", "sha256", "artifact"}:
            raise TopologyProbeError(
                f"{model!r}: evidence wrapper keys are exactly "
                f"['artifact', 'sha256', 'sourceUrl']; got {sorted(wrapper)}"
                if isinstance(wrapper, dict) else f"{model!r}: evidence wrapper is not an object"
            )
        artifact = wrapper["artifact"]
        if not isinstance(artifact, dict):
            raise TopologyProbeError(f"{model!r}: embedded artifact is not an object")
        run_id = artifact.get("githubRunId")
        if run_id in seen_runs:
            raise TopologyProbeError(f"{model!r}: duplicate evidence for run {run_id!r}")
        seen_runs.add(run_id)
        if not _HTTPS_RUN_URL_RE.match(str(wrapper["sourceUrl"])):
            raise TopologyProbeError(
                f"{model!r}: evidence URL {wrapper['sourceUrl']!r} is not an https GitHub "
                "run URL"
            )
        if str(run_id) not in str(wrapper["sourceUrl"]):
            raise TopologyProbeError(
                f"{model!r}: evidence URL {wrapper['sourceUrl']!r} does not name run {run_id!r}"
            )
        canonical = canonical_json(artifact)
        if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != wrapper["sha256"]:
            raise TopologyProbeError(
                f"{model!r}: embedded artifact for run {run_id!r} does not match its digest"
            )
        if artifact.get("cpuModel") != model:
            raise TopologyProbeError(
                f"{model!r}: embedded artifact reports cpuModel "
                f"{artifact.get('cpuModel')!r}; a model key is the artifacts' own model"
            )
    recomputed = select_topology(embedded[0]["artifact"], embedded[1]["artifact"])
    recomputed["artifacts"] = list(embedded)
    return recomputed


def recompute_decision(decision: dict) -> dict:
    """Rebuild every CURRENT and SUPERSEDED decision from its own evidence.

    The edge heads are copied rather than derived -- nothing outside the file
    can recompute which head replaced which -- so `validate_decision` checks
    the chain's linkage separately. Everything else in every decision, current
    or historical, is the selector's own result over that decision's own pair.
    """
    if not isinstance(decision, dict):
        raise TopologyProbeError(f"decision is not an object: {type(decision).__name__}")
    models = decision.get("models")
    if not isinstance(models, dict) or not models:
        raise TopologyProbeError("a decision carries a nonempty models map")
    out: dict[str, dict] = {}
    for model, entry in models.items():
        validate_cpu_model(model)
        if not isinstance(entry, dict):
            raise TopologyProbeError(f"{model!r}: entry is not an object")
        current = _recompute_one(model, entry)
        history = entry.get("superseded")
        if not isinstance(history, list):
            raise TopologyProbeError(
                f"{model!r}: an entry carries an ordered, append-only superseded list"
            )
        rebuilt: list[dict] = []
        for index, record in enumerate(history):
            if not isinstance(record, dict) or set(record) != set(DECISION_HISTORY_KEYS):
                raise TopologyProbeError(
                    f"{model!r}: superseded[{index}] keys are exactly "
                    f"{sorted(DECISION_HISTORY_KEYS)}"
                )
            rebuilt.append({
                "supersededByHeadSha": record["supersededByHeadSha"],
                "decision": _recompute_one(model, record["decision"]),
            })
        out[model] = {**current, "superseded": rebuilt}
    return out


def _validate_decision_fields(model: str, label: str, decision: dict) -> None:
    """The closed decision shape, current or superseded, or raise."""
    if set(decision) != set(DECISION_DECISION_KEYS):
        raise TopologyProbeError(
            f"{model!r} {label}: closed decision keys {sorted(DECISION_DECISION_KEYS)}; "
            f"got {sorted(decision)}"
        )
    if decision["status"] not in (DECISION_SELECTED, DECISION_UNHOSTABLE):
        raise TopologyProbeError(f"{model!r} {label}: unknown status {decision['status']!r}")
    if decision["status"] == DECISION_SELECTED:
        if decision["selected"] not in TOPOLOGY_IDS:
            raise TopologyProbeError(f"{model!r} {label}: selected {decision['selected']!r}")
        if decision["cardinality"] != topology_cardinality(decision["selected"]):
            raise TopologyProbeError(f"{model!r} {label}: cardinality is not topology-derived")
        if decision["placementSchema"] != CONTRACT_SCHEMA:
            raise TopologyProbeError(
                f"{model!r} {label}: placementSchema {decision['placementSchema']!r}"
            )
    else:
        for null_field in ("selected", "cardinality", "placementSchema", "score"):
            if decision[null_field] is not None:
                raise TopologyProbeError(
                    f"{model!r} {label}: an unhostable decision carries no {null_field}"
                )
        if decision["ratifiable"] != []:
            raise TopologyProbeError(f"{model!r} {label}: an unhostable decision ratifies nothing")
    if not _SHA_RE.match(str(decision["evidenceHeadSha"])):
        raise TopologyProbeError(
            f"{model!r} {label}: evidenceHeadSha {decision['evidenceHeadSha']!r}"
        )


def validate_decision(payload: object) -> dict:
    """The closed schema-3 carrier, recomputed from its own evidence, or raise.

    Structural only: it spawns no Git and requires no repository history, so
    the ordinary benchmark route can validate the whole carrier at a checkout
    of any depth. `verify_carrier_ancestry` is the separate, Git-backed proof.
    """
    if not isinstance(payload, dict):
        raise TopologyProbeError(f"decision is not an object: {type(payload).__name__}")
    if set(payload) != {"schema", "topologySetVersion", "models"}:
        raise TopologyProbeError(
            f"closed decision keys ['models', 'schema', 'topologySetVersion']; "
            f"got {sorted(payload)}"
        )
    if payload["schema"] != DECISION_SCHEMA:
        raise TopologyProbeError(
            f"unsupported decision schema {payload['schema']!r}; this slice reads only "
            f"schema {DECISION_SCHEMA} and migrates nothing"
        )
    if payload["topologySetVersion"] != TOPOLOGY_SET_VERSION:
        raise TopologyProbeError(
            f"decision topologySetVersion {payload['topologySetVersion']!r} is not "
            f"{TOPOLOGY_SET_VERSION}"
        )
    models = payload["models"]
    if not isinstance(models, dict) or not models:
        raise TopologyProbeError("a decision carries a nonempty models map")
    recomputed = recompute_decision(payload)
    for model, entry in models.items():
        if set(entry) != set(DECISION_ENTRY_KEYS):
            raise TopologyProbeError(
                f"{model!r}: closed entry keys {sorted(DECISION_ENTRY_KEYS)}; got {sorted(entry)}"
            )
        if entry != recomputed[model]:
            raise TopologyProbeError(
                f"{model!r}: the stored entry is not what the selector derives from its own "
                "embedded artifacts"
            )
        _validate_decision_fields(
            model, "current", {key: entry[key] for key in entry if key != "superseded"}
        )
        history = entry["superseded"]
        chain: list[str] = []
        for index, record in enumerate(history):
            _validate_decision_fields(model, f"superseded[{index}]", record["decision"])
            target = record["supersededByHeadSha"]
            if not _SHA_RE.match(str(target)):
                raise TopologyProbeError(
                    f"{model!r}: superseded[{index}] supersededByHeadSha {target!r}"
                )
            successor = (
                history[index + 1]["decision"]["evidenceHeadSha"]
                if index + 1 < len(history) else entry["evidenceHeadSha"]
            )
            if target != successor:
                raise TopologyProbeError(
                    f"{model!r}: superseded[{index}] was replaced at {target}, but the next "
                    f"decision in the chain is at {successor}; an orphan or branching edge is "
                    "not a history"
                )
            chain.append(record["decision"]["evidenceHeadSha"])
        chain.append(entry["evidenceHeadSha"])
        if len(set(chain)) != len(chain):
            raise TopologyProbeError(
                f"{model!r}: head {sorted(h for h in set(chain) if chain.count(h) > 1)} appears "
                "twice in the chain; one head decides a model once"
            )
    return payload


def write_canonical(path: Path, payload: dict) -> None:
    """Write canonical JSON atomically: a reader never sees a partial carrier."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f"{target.name}.tmp")
    temporary.write_text(canonical_json(payload), encoding="utf-8")
    os.replace(temporary, target)


# ---------------------------------------------------------------------------
# FP-GC3-4 — the pre-placement route
#
# This is the ONLY place the exact host model is turned into a launcher
# decision. It reads the model once through the same reader the probe records
# its identity with, validates the whole carrier, performs one exact key
# lookup, and writes a closed record. It takes no profile, model, topology,
# status or reason argument: every value below comes from the carrier or from
# the reader.
# ---------------------------------------------------------------------------


def _route_record(state: str, disposition: str, *, cpu_model, reason, entry=None) -> dict:
    topology = cardinality = placement_schema = None
    if entry is not None:
        topology = entry["selected"]
        cardinality = entry["cardinality"]
        placement_schema = entry["placementSchema"]
    return {
        "schema": ROUTE_SCHEMA,
        "profile": SELECTED_PROFILE_NAME,
        "cpuModel": cpu_model,
        "decisionState": state,
        "disposition": disposition,
        "reason": reason,
        "topology": topology,
        "cardinality": cardinality,
        "placementSchema": placement_schema,
    }


def route_host(decision_path, *, cpu_model=None) -> dict:
    """Classify this host against the model-keyed carrier. Never launches.

    The reader runs first, but carrier validation still runs for a model that
    could not be read: an unavailable reader may not hide a missing or corrupt
    carrier, and infrastructure corruption is never reported as an unratified
    SKU.
    """
    raw_model = host_cpu_model() if cpu_model is None else cpu_model
    valid_model = is_decision_eligible_cpu_model(raw_model)
    path = Path(decision_path)
    if not path.is_file():
        return _route_record(
            ROUTE_STATE_INVALID, ROUTE_FAILURE,
            cpu_model=raw_model if valid_model else None,
            reason=DECISION_MISSING_REASON,
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        validate_decision(payload)
    except (TopologyProbeError, ValueError, OSError):
        return _route_record(
            ROUTE_STATE_INVALID, ROUTE_FAILURE,
            cpu_model=raw_model if valid_model else None,
            reason=DECISION_INVALID_REASON,
        )
    if not valid_model:
        return _route_record(
            ROUTE_STATE_UNAVAILABLE, ROUTE_RECORDED,
            cpu_model=None, reason=ROUTE_MODEL_UNAVAILABLE_REASON,
        )
    entry = payload["models"].get(raw_model)
    if entry is None:
        return _route_record(
            ROUTE_STATE_ABSENT, ROUTE_RECORDED,
            cpu_model=raw_model,
            reason=f"{ROUTE_UNRATIFIED_REASON_PREFIX}{raw_model}",
        )
    if entry["status"] == DECISION_UNHOSTABLE:
        return _route_record(
            ROUTE_STATE_UNHOSTABLE, ROUTE_RECORDED,
            cpu_model=raw_model,
            reason=f"{ROUTE_UNRATIFIED_REASON_PREFIX}{raw_model}",
        )
    return _route_record(
        ROUTE_STATE_SELECTED, ROUTE_GATING,
        cpu_model=raw_model, reason=None, entry=entry,
    )


def validate_route(payload: object) -> dict:
    """The closed schema-1 route record, or raise."""
    if not isinstance(payload, dict):
        raise TopologyProbeError(f"route record is not an object: {type(payload).__name__}")
    if tuple(sorted(payload)) != tuple(sorted(ROUTE_KEYS)):
        raise TopologyProbeError(
            f"closed route keys {sorted(ROUTE_KEYS)}; got {sorted(payload)}"
        )
    if payload["schema"] != ROUTE_SCHEMA:
        raise TopologyProbeError(f"unsupported route schema {payload['schema']!r}")
    if payload["profile"] != SELECTED_PROFILE_NAME:
        raise TopologyProbeError(f"route profile {payload['profile']!r}")
    state, disposition = payload["decisionState"], payload["disposition"]
    if state not in ROUTE_STATES:
        raise TopologyProbeError(f"unknown decisionState {state!r}")
    if disposition not in ROUTE_DISPOSITIONS:
        raise TopologyProbeError(f"unknown disposition {disposition!r}")
    expected = {
        ROUTE_STATE_SELECTED: ROUTE_GATING,
        ROUTE_STATE_UNHOSTABLE: ROUTE_RECORDED,
        ROUTE_STATE_ABSENT: ROUTE_RECORDED,
        ROUTE_STATE_UNAVAILABLE: ROUTE_RECORDED,
        ROUTE_STATE_INVALID: ROUTE_FAILURE,
    }[state]
    if disposition != expected:
        raise TopologyProbeError(f"{state} routes to {expected}, not {disposition}")
    model = payload["cpuModel"]
    if state == ROUTE_STATE_UNAVAILABLE and model is not None:
        raise TopologyProbeError("an unavailable model is recorded as null")
    if state in (ROUTE_STATE_SELECTED, ROUTE_STATE_UNHOSTABLE, ROUTE_STATE_ABSENT):
        validate_cpu_model(model)
    if state == ROUTE_STATE_SELECTED:
        if payload["reason"] is not None:
            raise TopologyProbeError("a gating route carries no reason")
        if payload["topology"] not in TOPOLOGY_IDS:
            raise TopologyProbeError(f"route topology {payload['topology']!r}")
        if payload["cardinality"] != topology_cardinality(payload["topology"]):
            raise TopologyProbeError("route cardinality is not topology-derived")
        if payload["placementSchema"] != CONTRACT_SCHEMA:
            raise TopologyProbeError(f"route placementSchema {payload['placementSchema']!r}")
    else:
        for null_field in ("topology", "cardinality", "placementSchema"):
            if payload[null_field] is not None:
                raise TopologyProbeError(f"a {state} route carries no {null_field}")
        reason = payload["reason"]
        if state in (ROUTE_STATE_UNHOSTABLE, ROUTE_STATE_ABSENT):
            if reason != f"{ROUTE_UNRATIFIED_REASON_PREFIX}{model}":
                raise TopologyProbeError(f"{state} reason {reason!r}")
        elif state == ROUTE_STATE_UNAVAILABLE:
            if reason != ROUTE_MODEL_UNAVAILABLE_REASON:
                raise TopologyProbeError(f"{state} reason {reason!r}")
        elif reason not in (DECISION_MISSING_REASON, DECISION_INVALID_REASON):
            raise TopologyProbeError(f"{state} reason {reason!r}")
    return payload


def route_fields(payload: dict) -> str:
    """The two closed branch values the shell reads, tab separated."""
    validate_route(payload)
    if payload["disposition"] == ROUTE_FAILURE:
        raise TopologyProbeError(
            f"route disposition {ROUTE_FAILURE} has no launcher branch; the target has already "
            "returned nonzero"
        )
    if payload["disposition"] == ROUTE_GATING:
        return f"{ROUTE_GATING}\t{payload['topology']}"
    return f"{ROUTE_RECORDED}\t{ROUTE_NONE}"


# ---------------------------------------------------------------------------
# Host-side CLI: plan, contract, collect, decide
#
# There is deliberately no candidate, threshold, tie-break or topology option
# on any subcommand: every value a decision rests on comes from a measured
# artifact, and every value a launch rests on comes from the closed enumerator.
# ---------------------------------------------------------------------------


def _identity_from_environment(cpu_model: str, reference: str, pairs) -> dict:
    """GitHub run identity for the record. Never a profile or topology value."""
    return {
        "headSha": os.environ.get("GITHUB_SHA", "0" * 40),
        "githubRunId": os.environ.get("GITHUB_RUN_ID", "0"),
        "githubRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
        "githubJob": PROBE_JOB,
        "cpuModel": cpu_model,
        "logicalCpuCount": REFERENCE_LOGICAL_CPUS,
        "referenceCpus": reference,
        "siblingPairs": [format_cpu_list(pair) for pair in pairs],
    }


def host_cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                return " ".join(line.split(":", 1)[1].split())
    except OSError:
        pass
    return "unknown"


def _allowed_cpus() -> frozenset[int]:
    return frozenset(os.sched_getaffinity(0))


def _plan_command(args) -> int:
    try:
        pair0, pair1 = reference_pairs(_allowed_cpus())
    except TopologyProbeError as exc:
        identity = {
            "headSha": os.environ.get("GITHUB_SHA", "0" * 40),
            "githubRunId": os.environ.get("GITHUB_RUN_ID", "0"),
            "githubRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
            "githubJob": PROBE_JOB,
            "cpuModel": host_cpu_model(),
            "logicalCpuCount": REFERENCE_LOGICAL_CPUS,
            "referenceCpus": "none",
            "siblingPairs": [],
        }
        write_artifact(
            Path(args.artifact),
            {
                "schema": ARTIFACT_SCHEMA,
                "status": ARTIFACT_INVALID,
                "failureCode": "unsupported_topology",
                "missingArms": list(range(ARMS_PER_ARTIFACT)),
                "failureDetail": [str(exc)],
                "topologySetVersion": TOPOLOGY_SET_VERSION,
                "arms": [],
                **{k: identity[k] for k in (
                    "headSha", "githubRunId", "githubJob", "githubRunAttempt",
                    "cpuModel", "logicalCpuCount", "referenceCpus", "siblingPairs",
                )},
            },
        )
        print(f"b1_topology_probe: {exc}", file=sys.stderr)
        return 1
    arms = enumerate_arms(pair0, pair1)
    identity = _identity_from_environment(
        host_cpu_model(), format_cpu_list((*pair0, *pair1)), (pair0, pair1)
    )
    plan = {
        "topologySetVersion": TOPOLOGY_SET_VERSION,
        "identity": identity,
        "siblingPairs": [list(pair0), list(pair1)],
        "arms": list(arms),
    }
    Path(args.out).write_text(canonical_json(plan), encoding="utf-8")
    print(len(arms))
    return 0


def _contract_command(args) -> int:
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    arms = plan["arms"]
    if not 0 <= args.arm < len(arms):
        raise TopologyProbeError(f"arm {args.arm} is outside the plan's 0..{len(arms) - 1}")
    arm = arms[args.arm]
    pair0 = tuple(plan["siblingPairs"][0])
    pair1 = tuple(plan["siblingPairs"][1])
    expected = enumerate_arms(pair0, pair1)[args.arm]
    if expected != arm:
        raise TopologyProbeError(
            f"plan arm {args.arm} is not what the closed enumerator derives: {arm} != {expected}"
        )
    contract = arm_contract(arm, args.run_id)
    parse_arm_contract(contract)
    Path(args.out).write_text(canonical_json(contract), encoding="utf-8")
    Path(args.context).write_text(
        canonical_json(
            {
                "index": arm["index"],
                **{k: plan["identity"][k] for k in (
                    "headSha", "githubRunId", "githubRunAttempt", "githubJob",
                    "cpuModel", "logicalCpuCount", "referenceCpus", "siblingPairs",
                )},
            }
        ),
        encoding="utf-8",
    )
    print(contract["roles"]["driver"]["allowedCpus"])
    return 0


def _collect_command(args) -> int:
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    records = []
    directory = Path(args.records)
    if directory.is_dir():
        for path in sorted(directory.glob("record-*.json")):
            records.append(json.loads(path.read_text(encoding="utf-8")))
    failure = None
    if args.failed_arm is not None:
        failure = {
            "armIndex": args.failed_arm,
            "exitCode": args.exit_code,
            "failureCode": "arm_failed",
        }
    artifact = collect_artifact(plan, records, failure=failure)
    write_artifact(Path(args.out), artifact)
    print(f"b1_topology_probe: artifact {artifact['status']} at {args.out}")
    if artifact["status"] != ARTIFACT_COMPLETE:
        print(
            f"b1_topology_probe: failureCode={artifact['failureCode']} "
            f"missingArms={artifact['missingArms']}",
            file=sys.stderr,
        )
        return 1
    return 0


def _decide_command(args) -> int:
    """FP-GC3-3/7: one model's decision, merged into the complete carrier.

    The output is written atomically and only after all validation, and it may
    never be the base: the base carrier is read, never rewritten, so a
    rejected invocation leaves both files exactly as they were and an
    idempotent success produces bytes identical to the base it was given.
    """
    out, base = Path(args.out), Path(args.base)
    if os.path.realpath(out) == os.path.realpath(base):
        raise TopologyProbeError(
            f"--out {args.out!r} and --base {args.base!r} resolve to one path; the base "
            "carrier is read, never rewritten"
        )
    decision = build_decision(args.pair, base, args.supersede)
    write_canonical(out, decision)
    for model, entry in sorted(decision["models"].items()):
        print(f"b1_topology_probe: {model} {entry['status']} {entry['selected']}")
    return 0


def _route_command(args) -> int:
    """FP-GC3-4: classify the host before pair discovery or any live process."""
    record = route_host(args.decision)
    validate_route(record)
    rendered = canonical_json(record)
    write_canonical(Path(args.out), record)
    print(f"{ROUTE_STDOUT_PREFIX}{urllib.parse.quote(rendered, safe='')}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(
                f"B1 topology route: cpuModel={record['cpuModel']} "
                f"decisionState={record['decisionState']} "
                f"disposition={record['disposition']} reason={record['reason']}\n"
            )
    if record["disposition"] == ROUTE_FAILURE:
        print(
            f"b1_topology_probe: {record['reason']} ({record['decisionState']})", file=sys.stderr
        )
        return 1
    return 0


def _route_fields_command(args) -> int:
    """The one closed read the shell performs: `<disposition><TAB><topology>`."""
    raw = Path(args.route).read_text(encoding="utf-8")
    payload = json.loads(raw)
    if canonical_json(payload) != raw:
        raise TopologyProbeError(f"{args.route} is not canonical")
    print(route_fields(payload))
    return 0


def _contract_selected_command(args) -> int:
    """Render the ratified topology over the observed pairs, at orientation 0."""
    contract = selected_contract(args.topology, args.pairs, args.run_id)
    parse_selected_contract(contract, pairs=args.pairs)
    Path(args.out).write_text(canonical_json(contract), encoding="utf-8")
    print(contract["roles"]["driver"]["allowedCpus"])
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="b1_topology_probe", add_help=True)
    sub = parser.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan", help="write the immutable 28-arm plan")
    plan.add_argument("--out", required=True)
    plan.add_argument("--artifact", required=True)
    plan.set_defaults(handler=_plan_command)

    contract = sub.add_parser("contract", help="write one arm's schema-3 launch contract")
    contract.add_argument("--plan", required=True)
    contract.add_argument("--arm", required=True, type=int)
    contract.add_argument("--run-id", required=True, dest="run_id")
    contract.add_argument("--out", required=True)
    contract.add_argument("--context", required=True)
    contract.set_defaults(handler=_contract_command)

    collect = sub.add_parser("collect", help="validate every record and write the artifact")
    collect.add_argument("--plan", required=True)
    collect.add_argument("--records", required=True)
    collect.add_argument("--out", required=True)
    collect.add_argument("--failed-arm", dest="failed_arm", type=int, default=None)
    collect.add_argument("--exit-code", dest="exit_code", type=int, default=0)
    collect.set_defaults(handler=_collect_command)

    # The decision generator: exactly one output path, the REQUIRED complete
    # base carrier to merge one model's entry into, exactly one two-value pair,
    # and an optional single evidence head that authorises replacing an
    # already decided model. Registered in that exact order. It has no
    # override option of any kind by construction, and takes no positional
    # argument at all.
    decide = sub.add_parser("decide", help="select one topology, or record unhostable")
    decide.add_argument("--out", required=True)
    decide.add_argument("--base", required=True)
    decide.add_argument("--pair", required=True, nargs=2, dest="pair")
    decide.add_argument("--supersede", default=None)
    decide.set_defaults(handler=_decide_command)

    # FP-GC3-4: the pre-placement route. It accepts no profile, model,
    # topology, status or reason argument -- every result value comes from the
    # shared host reader and the closed carrier.
    route = sub.add_parser("route", help="classify this host against the model-keyed carrier")
    route.add_argument("--decision", required=True)
    route.add_argument("--out", required=True)
    route.set_defaults(handler=_route_command)

    route_fields_parser = sub.add_parser("route-fields", help="print two closed branch values")
    route_fields_parser.add_argument("--route", required=True)
    route_fields_parser.set_defaults(handler=_route_fields_command)

    # The ratified launch contract. It accepts a closed topology id, the two
    # observed sibling pairs and a run id -- never a role mapping, a
    # cardinality, a profile or a model.
    contract_selected = sub.add_parser("contract-selected", help="write the ratified contract")
    contract_selected.add_argument("--topology", required=True)
    contract_selected.add_argument("--pairs", required=True, nargs=2)
    contract_selected.add_argument("--run-id", required=True, dest="run_id")
    contract_selected.add_argument("--out", required=True)
    contract_selected.set_defaults(handler=_contract_selected_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        return args.handler(args)
    except (TopologyProbeError, OSError, ValueError) as exc:
        print(f"b1_topology_probe: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
