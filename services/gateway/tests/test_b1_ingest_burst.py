"""FP-IG-7 / FP-IG-18 / UT-IG-5: B1 reference-tier burst measurement.

Run only from the CI ``benchmark`` job (excluded from unit-gateway/functional
via --ignore). Spawns the real gateway under uvicorn against testcontainers PG.
"""
from __future__ import annotations

import ast
import asyncio
import hashlib
import hmac
import json
import math
import os
import re
import signal
import socket
import select
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.parse
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from types import SimpleNamespace
from contextlib import ExitStack, asynccontextmanager, contextmanager
from pathlib import Path

import httpx
import pytest
import yaml

# Load profile module by path so we never mutate sys.path.
import importlib.util
import sys as _sys

_PROFILE_PATH = Path(__file__).resolve().parent / "b1_reference_profile.py"
_spec = importlib.util.spec_from_file_location("b1_reference_profile", _PROFILE_PATH)
assert _spec and _spec.loader
b1 = importlib.util.module_from_spec(_spec)
_sys.modules["b1_reference_profile"] = b1
_spec.loader.exec_module(b1)

# GC-3 (FP-GC3-1/2/3/5): the closed topology candidate space, the schema-3
# launch contract, the probe verdict vocabulary, the artifact collector and the
# immutable selector. Loaded by path for the same reason as the profile module,
# and stdlib-only so the shell launcher can run the same code on the host.
_TOPOLOGY_PROBE_PATH = Path(__file__).resolve().parent / "b1_topology_probe.py"
_topology_spec = importlib.util.spec_from_file_location(
    "b1_topology_probe", _TOPOLOGY_PROBE_PATH
)
assert _topology_spec and _topology_spec.loader
probe = importlib.util.module_from_spec(_topology_spec)
_sys.modules["b1_topology_probe"] = probe
_topology_spec.loader.exec_module(probe)

REPO_ROOT = Path(__file__).resolve().parents[3]
VALUES_YAML = REPO_ROOT / "deploy" / "charts" / "dbagent" / "values.yaml"
HMAC_SECRET = "b1-reference-hmac-secret"
PLATFORM_KEY = "b1-ref-platform"


# ---------------------------------------------------------------------------
# GC-1 — resource-declared reference topology (FP-GC1-1 / 2 / 3 / 4)
#
# Everything below is test-only: there is no product endpoint and no product
# configuration here. Its single job is to make a B1 number unreadable unless
# the three measured roles demonstrably ran on the CPUs the run claims.
#
# The allocation is scheduler affinity, not CFS bandwidth. Revision 0.4 of this
# slice declared per-role CPU quotas and measured the consequence: a bursty
# role exhausts a fractional 100 ms allowance early and is then suspended for
# the remainder of the period, so the gateway was throttled in 43 of 307
# periods while averaging only 1.15 of its 2.00 declared cores, PostgreSQL in
# 65 of 308, and CI-scale p99 landed at 614-794 ms against a 150 ms bar. That
# falsified the primitive, not the bar. Exact, pairwise-disjoint affinity sets
# give a role its full declared cores at any instant and never suspend it for
# accounting reasons.
#
# "Demonstrably" therefore means effective scheduler state -- /proc/<pid>/status
# Cpus_allowed_list and os.sched_getaffinity(pid), read for every live process
# of every role, at window open and again at window close. A `taskset` string
# the kernel did not enforce cannot masquerade as placement evidence. Every
# cgroup and host-CPU value below is a reported diagnostic and decides nothing.
# ---------------------------------------------------------------------------

B1_RUN_MOUNT = Path("/run/dbagent-b1")
B1_LAUNCH_CONTRACT = B1_RUN_MOUNT / "placement.json"
B1_WORKSPACE_MOUNT = "/workspace"
B1_DOCKER_SOCKET = "/var/run/docker.sock"
B1_RUN_LABEL_KEY = "dbagent.b1.run"
B1_ROLE_LABEL_KEY = "dbagent.b1.role"
B1_DRIVER_NAME_PREFIX = "dbagent-b1-driver-"
B1_RUN_ID_LENGTH = 32
B1_RUN_ID_ALPHABET = frozenset("0123456789abcdef")
B1_ROLES = ("gateway", "postgres", "driver")
B1_GATEWAY_IMPORT_PATH = "services/gateway/tests/b1_reference_profile.py"
# Both siblings are reached over the host network namespace the driver
# shares with them; there is no bridge hop to autodetect.
B1_SIBLING_HOST = "127.0.0.1"

# The launch contract is ephemeral and run-scoped, so the affinity change is a
# clean break: schema 2 carries CPU lists and a named mechanism, and carries no
# quota or period key at all. Schema 1 is rejected outright -- shell and
# fixture ship together and nothing stored is migrated.
#
# GC-3 (FP-GC3-4/5) splits the two lines apart for good. The PRODUCT-local
# contract stays schema 2, byte-for-byte; both CI-scale contracts -- the
# discovery arm and the ratified gate -- are schema 3, which carries the
# topology ID, the reference CPU set and the intentionally unassigned CPU as
# GATING fields. Schema 3 is not a migration of schema 2: it is a different
# document, and there is no scalar "the B1 placement schema" any more.
PRODUCT_PLACEMENT_SCHEMA = 2
B1_PLACEMENT_MECHANISM = "sched-affinity"
B1_TOPOLOGY_PLACEMENT_SCHEMA = probe.CONTRACT_SCHEMA
#: The tracked model-keyed decision carrier, at the exact path the driver
#: container reads it at through its existing read-only source mount. The host
#: route record is deliberately NOT copied into B1_RUN_DIR: the live witness
#: joins decision to fingerprint through this one shared file.
B1_DECISION_CARRIER = Path("/workspace/tests/benchmark/b1_topology_decision.json")

CI_SCALE_PROFILE_NAME = "ci-scale"
PRODUCT_PROFILE_NAME = "product-exclusive"
# The discovery profile. Its workload values are copied from CI_SCALE_PROFILE
# below and never altered: a discovery arm measures the same burst the gate
# measures, under a different placement.
CI_SCALE_PROBE_PROFILE_NAME = probe.PROBE_PROFILE_NAME
# Exact per-role affinity cardinalities.
#
# GC-3 (FP-GC3-4): the CI-scale allocation is no longer one fixed 2/1/1 over
# "the first four available CPUs". It is decided per exact CPU model by the
# tracked carrier, so the declaration surface here is a CLOSED MAP KEYED BY
# EXACT `cpuModel`, generated entry by entry from each `selected` entry's own
# topology, and every entry's cardinality is that topology's derived
# cardinality. A model with no entry has no cardinality here and no live gate;
# nothing is copied into a scalar default, and one model's entry is never
# another model's fallback.
#
# GENERATED ENTRY BY ENTRY FROM THE CARRIER'S `selected` ENTRIES, and pinned
# against them by the delivery and manifest guards, whatever their number. A
# model whose current decision is `unhostable`, or which the carrier does not
# name at all, has no entry here: it has no CI-scale topology, no cardinality
# and no live gate, and one model's entry is never another model's fallback.
CI_SCALE_AFFINITY_CARDINALITIES_BY_CPU_MODEL: "dict[str, dict[str, int]]" = {
    "AMD EPYC 7763 64-Core Processor": {"gateway": 2, "postgres": 1, "driver": 1},
}
#: ...and the placement schema each selected model's ordinary gate launches
#: under. Always schema 3 for a selected model; the fixed probe schema is 3 and
#: the fixed product schema is `PRODUCT_PLACEMENT_SCHEMA`.
CI_SCALE_PLACEMENT_SCHEMAS_BY_CPU_MODEL: "dict[str, int]" = {
    "AMD EPYC 7763 64-Core Processor": 3,
}
PRODUCT_AFFINITY_CARDINALITY = {"gateway": 4, "postgres": 3, "driver": 1}
CI_SCALE_REFERENCE_LOGICAL_CPUS = 4
PRODUCT_MINIMUM_HOST_LOGICAL_CPUS = 8
PRODUCT_GATEWAY_CPU_CARDINALITY = 4

# measurement_authority is derived, never supplied: only a CI-scale run whose
# observed host really has four logical CPUs is the CI measurement of record.
AUTHORITY_CI_SCALE_REFERENCE = "ci-scale-reference"
AUTHORITY_LOCAL_REPLICA = "local-replica"
AUTHORITY_PRODUCT_LOCAL = "product-local-reference"

PRODUCT_VERDICT_FIELDS = (
    "product_errors_eq_zero",
    "product_p99_lt_150_ms",
    "product_served_eq_offered",
)
VERDICT_MET = "met"
VERDICT_MISSED = "missed"

# Reported-only diagnostics render this when their source cannot be read or
# parsed. No gating field may ever carry it.
DIAGNOSTIC_UNAVAILABLE = "unavailable"

# The first five identity fields and the three affinity sets are the gate.
B1_GATING_PLACEMENT_FIELDS = (
    "placement_profile",
    "placement_schema",
    "placement_run_id",
    "measurement_authority",
    "placement_ok",
    "gateway_allowed_cpus",
    "postgres_allowed_cpus",
    "driver_allowed_cpus",
)
# Everything after them describes ambient cgroup policy and unrelated host
# work. None of it can fail a B1 tier.
B1_DIAGNOSTIC_PLACEMENT_FIELDS = (
    "gateway_quota_cpus",
    "gateway_cpu_period_us",
    "gateway_nr_periods",
    "gateway_nr_throttled",
    "gateway_throttled_usec",
    "postgres_quota_cpus",
    "postgres_cpu_period_us",
    "postgres_nr_periods",
    "postgres_nr_throttled",
    "postgres_throttled_usec",
    "driver_quota_cpus",
    "driver_cpu_period_us",
    "driver_nr_periods",
    "driver_nr_throttled",
    "driver_throttled_usec",
    "gateway_cpu_busy_usec",
    "gateway_nonrole_busy_cores_estimate",
    "gateway_cpu_cores_used",
    # GC-2 (FP-GC2-5): host and PostgreSQL attribution for the reference
    # record. Reported-only on both profiles, like everything above them: the
    # two free-form strings are percent-encoded so a comma inside a kernel
    # value cannot be read as a field separator.
    "postgres_usage_usec",
    "gateway_thread_siblings_pct",
    "spectre_v2_pct",
)
B1_PLACEMENT_FIELDS = B1_GATING_PLACEMENT_FIELDS + B1_DIAGNOSTIC_PLACEMENT_FIELDS

# GC-3 (FP-GC3-5): the schema-3 inventories. They are separate tuples, not an
# extension of the two above, because the field inventory is now chosen from
# the parsed profile/schema rather than shared: a schema-3 CI-scale record
# carries the physical-topology claim in its GATING prefix, while a schema-2
# record (the product-local profile, and the ordinary CI-scale contract until
# the topology is ratified) carries only the gateway sibling map, reported-only,
# in its diagnostic suffix.
B1_TOPOLOGY_GATING_PLACEMENT_FIELDS = (
    "placement_profile",
    "placement_schema",
    "placement_run_id",
    "measurement_authority",
    "reference_topology",
    "reference_cpus",
    "unassigned_cpus",
    "placement_ok",
    "gateway_allowed_cpus",
    "postgres_allowed_cpus",
    "driver_allowed_cpus",
    "gateway_thread_siblings_pct",
    "postgres_thread_siblings_pct",
    "driver_thread_siblings_pct",
)
# `gateway_thread_siblings_pct` is deliberately absent here: under schema 3 it
# appears exactly once, in the gating prefix above. The remaining attribution
# fields keep their GC-1/GC-2 reported-only semantics and their order.
B1_TOPOLOGY_DIAGNOSTIC_PLACEMENT_FIELDS = (
    "gateway_quota_cpus",
    "gateway_cpu_period_us",
    "gateway_nr_periods",
    "gateway_nr_throttled",
    "gateway_throttled_usec",
    "postgres_quota_cpus",
    "postgres_cpu_period_us",
    "postgres_nr_periods",
    "postgres_nr_throttled",
    "postgres_throttled_usec",
    "driver_quota_cpus",
    "driver_cpu_period_us",
    "driver_nr_periods",
    "driver_nr_throttled",
    "driver_throttled_usec",
    "gateway_cpu_busy_usec",
    "gateway_nonrole_busy_cores_estimate",
    "gateway_cpu_cores_used",
    "postgres_usage_usec",
    "spectre_v2_pct",
)
B1_TOPOLOGY_PLACEMENT_FIELDS = (
    B1_TOPOLOGY_GATING_PLACEMENT_FIELDS + B1_TOPOLOGY_DIAGNOSTIC_PLACEMENT_FIELDS
)
#: Schema-3 fields the product-local schema-2 line must never carry, in any
#: form -- not as `none` and not as `unavailable`.
B1_TOPOLOGY_ONLY_FIELDS = (
    "reference_topology",
    "reference_cpus",
    "unassigned_cpus",
    "postgres_thread_siblings_pct",
    "driver_thread_siblings_pct",
)
B1_UNASSIGNED_NONE = "none"


class B1PlacementError(RuntimeError):
    """The declared placement could not be proven; no B1 verdict may follow."""


@dataclass(frozen=True)
class B1Profile:
    """One immutable measured profile. Values come from the profile module."""

    name: str
    rate: int
    seconds: int
    total_requests: int
    prologue_requests: int
    max_in_flight: int
    p99_ms: float
    sustained_floor: int

    @property
    def affinity_cardinality(self) -> dict[str, int]:
        if self.name == PRODUCT_PROFILE_NAME:
            return dict(PRODUCT_AFFINITY_CARDINALITY)
        # GC-3: neither CI-scale profile has a fixed cardinality -- both are
        # derived from the schema-3 contract's topology class and carried on
        # the declaration. Failing closed here is deliberate: a caller that
        # asks the profile is asking the wrong object and must not silently
        # receive another profile's -- or another model's -- allocation.
        raise B1PlacementError(
            f"profile {self.name!r} has a topology-derived affinity cardinality; read it "
            f"from the parsed launch contract, not from the profile"
        )

    @property
    def declared_cpu_total(self) -> int:
        return sum(self.affinity_cardinality.values())


CI_SCALE_PROFILE = B1Profile(
    name=CI_SCALE_PROFILE_NAME,
    rate=b1.CI_SCALE_BURST_RATE,
    seconds=b1.CI_SCALE_BURST_SECONDS,
    total_requests=b1.CI_SCALE_TOTAL_REQUESTS,
    prologue_requests=b1.CI_SCALE_PROLOGUE_REQUESTS,
    max_in_flight=b1.CI_SCALE_MAX_IN_FLIGHT,
    p99_ms=b1.CI_SCALE_P99_MS,
    sustained_floor=b1.CI_SCALE_SUSTAINED_FLOOR,
)
PRODUCT_PROFILE = B1Profile(
    name=PRODUCT_PROFILE_NAME,
    rate=b1.BURST_RATE,
    seconds=b1.BURST_SECONDS,
    total_requests=b1.TOTAL_REQUESTS,
    prologue_requests=b1.PROLOGUE_REQUESTS,
    max_in_flight=b1.MAX_IN_FLIGHT,
    p99_ms=b1.P99_MS,
    sustained_floor=b1.SUSTAINED_FLOOR,
)
# GC-3 (FP-GC3-2): the discovery profile. Every workload value is copied from
# CI_SCALE_PROFILE rather than restated, so a discovery arm cannot measure a
# different burst from the one the gate measures. Only the name differs, and
# only so the launch contract, the fixture and the record can be told apart.
CI_SCALE_PROBE_PROFILE = B1Profile(
    name=CI_SCALE_PROBE_PROFILE_NAME,
    rate=CI_SCALE_PROFILE.rate,
    seconds=CI_SCALE_PROFILE.seconds,
    total_requests=CI_SCALE_PROFILE.total_requests,
    prologue_requests=CI_SCALE_PROFILE.prologue_requests,
    max_in_flight=CI_SCALE_PROFILE.max_in_flight,
    p99_ms=CI_SCALE_PROFILE.p99_ms,
    sustained_floor=CI_SCALE_PROFILE.sustained_floor,
)
B1_PROFILES = {
    CI_SCALE_PROFILE.name: CI_SCALE_PROFILE,
    CI_SCALE_PROBE_PROFILE.name: CI_SCALE_PROBE_PROFILE,
    PRODUCT_PROFILE.name: PRODUCT_PROFILE,
}
#: Profiles whose record is a CI-scale measurement: the gate and the discovery
#: instrument. The product-local profile is neither.
B1_CI_SCALE_PROFILES = (CI_SCALE_PROFILE_NAME, CI_SCALE_PROBE_PROFILE_NAME)


@dataclass(frozen=True)
class B1PlacementDeclaration:
    """The parsed schema-2 launch contract.

    The JSON is a launch contract, not a profile configuration interface: the
    Python constants above are authoritative and every shape below is checked
    against them, so a hand-edited placement.json cannot move a profile, a
    mechanism or an affinity cardinality -- it can only fail the run. The CPU
    *identities* are necessarily dynamic (they come from whatever the launcher
    was allowed to use), so they are checked against the closed-set rules --
    canonical form, exact cardinality, pairwise disjointness, union size --
    rather than against literals.
    """

    schema: int
    run_id: str
    profile: str
    mechanism: str
    allowed_cpus: tuple[tuple[str, frozenset[int]], ...]
    reference_logical_cpus: int | None
    minimum_host_logical_cpus: int | None
    # GC-3 (FP-GC3-1/5): schema-3 only. `None`/empty on every schema-2 contract.
    topology: str | None = None
    probe_round: int | None = None
    orientation: int | None = None
    reference_cpus: frozenset[int] = frozenset()
    unassigned_cpus: frozenset[int] = frozenset()

    def allowed(self, role: str) -> frozenset[int]:
        return dict(self.allowed_cpus)[role]

    @property
    def carries_topology(self) -> bool:
        return self.schema == B1_TOPOLOGY_PLACEMENT_SCHEMA

    @property
    def witness_orientation(self) -> int:
        """The orientation the physical relationship is reconstructed at.

        A discovery arm names its own orientation: the sweep measures both, so
        the witness must hold the arm to the one it was launched under. The
        ratified gate names none -- `contract-selected` renders exactly the
        fixed orientation 0 over the min-id-ordered observed pairs -- so the
        witness reconstructs at that same fixed orientation. Neither case lets
        the run choose whichever orientation happens to match.
        """
        return probe.SELECTED_ORIENTATION if self.orientation is None else self.orientation

    @property
    def cardinality(self) -> dict[str, int]:
        """The exact per-role cardinality this contract is held to.

        Topology-derived under schema 3, profile-fixed under schema 2. The
        declaration is authoritative either way: the witness never re-derives
        it from the profile name.
        """
        if self.carries_topology:
            return probe.topology_cardinality(self.topology)
        return B1_PROFILES[self.profile].affinity_cardinality

    @property
    def declared_cpu_total(self) -> int:
        return sum(self.cardinality.values())

    @property
    def declared_union(self) -> frozenset[int]:
        out: frozenset[int] = frozenset()
        for _role, cpus in self.allowed_cpus:
            out |= cpus
        return out

    @property
    def driver_name(self) -> str:
        return f"{B1_DRIVER_NAME_PREFIX}{self.run_id}"

    @property
    def run_label(self) -> str:
        return f"{B1_RUN_LABEL_KEY}={self.run_id}"

    def role_label(self, role: str) -> str:
        return f"{B1_ROLE_LABEL_KEY}={role}"

    def labels(self, role: str) -> dict[str, str]:
        return {B1_RUN_LABEL_KEY: self.run_id, B1_ROLE_LABEL_KEY: role}

    @classmethod
    def from_contract(cls, payload: object) -> "B1PlacementDeclaration":
        if not isinstance(payload, dict):
            raise B1PlacementError(f"launch contract is not a JSON object: {type(payload).__name__}")
        profile = payload.get("profile")
        if profile not in B1_PROFILES:
            raise B1PlacementError(f"unknown placement profile {profile!r}")
        # GC-3 (FP-GC3-4): BOTH CI-scale profiles arrive as schema-3
        # topology contracts -- the discovery arm and the ratified gate alike.
        # The product-local profile keeps the schema-2 document below.
        if profile in B1_CI_SCALE_PROFILES:
            return cls._from_topology_contract(payload)
        capacity_key = "minimumHostLogicalCpus"
        expected_keys = {"schema", "runId", "profile", "mechanism", "roles", capacity_key}
        got_keys = set(payload)
        if got_keys != expected_keys:
            raise B1PlacementError(
                f"closed schema-{PRODUCT_PLACEMENT_SCHEMA} contract keys {sorted(expected_keys)}; "
                f"got {sorted(got_keys)}"
            )
        if payload["schema"] != PRODUCT_PLACEMENT_SCHEMA:
            raise B1PlacementError(
                f"unsupported placement schema {payload['schema']!r}; this harness declares "
                f"scheduler affinity and only understands schema {PRODUCT_PLACEMENT_SCHEMA}"
            )
        if payload["mechanism"] != B1_PLACEMENT_MECHANISM:
            raise B1PlacementError(
                f"unsupported placement mechanism {payload['mechanism']!r}; "
                f"expected {B1_PLACEMENT_MECHANISM!r}"
            )
        run_id = payload["runId"]
        if (
            not isinstance(run_id, str)
            or len(run_id) != B1_RUN_ID_LENGTH
            or not set(run_id) <= B1_RUN_ID_ALPHABET
        ):
            raise B1PlacementError(
                f"runId must be {B1_RUN_ID_LENGTH} lowercase hex characters; got {run_id!r}"
            )
        capacity = payload[capacity_key]
        if capacity != PRODUCT_MINIMUM_HOST_LOGICAL_CPUS:
            raise B1PlacementError(
                f"minimumHostLogicalCpus is pinned at {PRODUCT_MINIMUM_HOST_LOGICAL_CPUS}; "
                f"got {capacity!r}"
            )
        roles = payload["roles"]
        if not isinstance(roles, dict) or set(roles) != set(B1_ROLES):
            raise B1PlacementError(f"contract roles must be exactly {sorted(B1_ROLES)}; got {roles!r}")
        cardinality = B1_PROFILES[profile].affinity_cardinality
        allowed_pairs: list[tuple[str, frozenset[int]]] = []
        for role in B1_ROLES:
            entry = roles[role]
            if not isinstance(entry, dict) or set(entry) != {"allowedCpus"}:
                raise B1PlacementError(
                    f"role {role!r} must carry exactly ['allowedCpus']; got {entry!r}"
                )
            raw = entry["allowedCpus"]
            if not isinstance(raw, str):
                raise B1PlacementError(f"role {role!r} needs a CPU list; got {raw!r}")
            cpus = b1.parse_cpu_list(raw)
            if b1.format_cpu_list(cpus) != raw:
                raise B1PlacementError(f"role {role!r} CPU list {raw!r} is not canonical")
            if len(cpus) != cardinality[role]:
                raise B1PlacementError(
                    f"profile {profile!r} declares {cardinality[role]} CPU(s) for {role!r}; "
                    f"contract carries {len(cpus)} ({raw})"
                )
            allowed_pairs.append((role, cpus))
        sets = dict(allowed_pairs)
        for left, right in (("gateway", "postgres"), ("gateway", "driver"), ("postgres", "driver")):
            overlap = sets[left] & sets[right]
            if overlap:
                raise B1PlacementError(
                    f"declared sets {left}/{right} overlap on {sorted(overlap)}"
                )
        union = frozenset().union(*sets.values())
        declared_total = B1_PROFILES[profile].declared_cpu_total
        if len(union) != declared_total:
            raise B1PlacementError(
                f"profile {profile!r} declares {declared_total} distinct CPUs; "
                f"contract union has {len(union)}"
            )
        return cls(
            schema=PRODUCT_PLACEMENT_SCHEMA,
            run_id=run_id,
            profile=profile,
            mechanism=B1_PLACEMENT_MECHANISM,
            allowed_cpus=tuple(allowed_pairs),
            reference_logical_cpus=None,
            minimum_host_logical_cpus=capacity,
        )

    @classmethod
    def _from_topology_contract(cls, payload: dict) -> "B1PlacementDeclaration":
        """GC-3 FP-GC3-1: the schema-3 contract, parsed by the closed enumerator.

        Every rule -- closed keys, canonical CPU lists, role cardinalities,
        disjointness, the zero-or-one unassigned CPU and the exact mapping --
        lives once, in ``b1_topology_probe``. This wrapper only adapts the
        result into the declaration the rest of the harness already speaks, so
        the shell, the planner and the fixture cannot drift into three
        different ideas of what an arm is.
        """
        try:
            parsed = probe.parse_contract(payload)
        except probe.TopologyProbeError as exc:
            raise B1PlacementError(str(exc)) from exc
        return cls(
            schema=B1_TOPOLOGY_PLACEMENT_SCHEMA,
            run_id=parsed["run_id"],
            profile=parsed["profile"],
            mechanism=B1_PLACEMENT_MECHANISM,
            allowed_cpus=tuple((role, parsed["roles"][role]) for role in B1_ROLES),
            reference_logical_cpus=probe.REFERENCE_LOGICAL_CPUS,
            minimum_host_logical_cpus=None,
            topology=parsed["topology"],
            probe_round=parsed["round"],
            orientation=parsed["orientation"],
            reference_cpus=parsed["reference_cpus"],
            unassigned_cpus=parsed["unassigned"],
        )


@dataclass(frozen=True)
class B1RolePlacement:
    """Effective scheduler state for one measured role. Purely gating."""

    role: str
    allowed_cpus: frozenset[int]
    pids: tuple[int, ...]


@dataclass(frozen=True)
class B1RoleDiagnostics:
    """Reported-only cgroup readings for one role. Never gating.

    Every field is already rendered, so an unreadable or nonsensical source
    reaches the fingerprint as the literal ``unavailable`` rather than as a
    zero that would read like a measurement.
    """

    role: str
    quota_cpus: str = DIAGNOSTIC_UNAVAILABLE
    cpu_period_us: str = DIAGNOSTIC_UNAVAILABLE
    nr_periods: str = DIAGNOSTIC_UNAVAILABLE
    nr_throttled: str = DIAGNOSTIC_UNAVAILABLE
    throttled_usec: str = DIAGNOSTIC_UNAVAILABLE
    usage_usec_delta: int | None = None
    notes: tuple[str, ...] = ()

    def rendered(self) -> tuple[tuple[str, str], ...]:
        return (
            (f"{self.role}_quota_cpus", self.quota_cpus),
            (f"{self.role}_cpu_period_us", self.cpu_period_us),
            (f"{self.role}_nr_periods", self.nr_periods),
            (f"{self.role}_nr_throttled", self.nr_throttled),
            (f"{self.role}_throttled_usec", self.throttled_usec),
        )


class B1PlacementWitness:
    """Profile-specific validation of the three roles' effective affinities."""

    def __init__(
        self,
        declaration: B1PlacementDeclaration,
        *,
        host_cpus: frozenset[int],
        sibling_groups: "dict[int, frozenset[int]] | None" = None,
    ):
        self.declaration = declaration
        self.host_cpus = frozenset(host_cpus)
        # GC-3 (FP-GC3-5): the kernel's own sibling reading for every reference
        # CPU, supplied by the caller that read it. A schema-3 declaration
        # cannot be witnessed without it, and that is the fail-closed part:
        # missing topology data prevents a B1 verdict rather than downgrading
        # the check to CPU identities.
        self.sibling_groups = dict(sibling_groups or {})

    @property
    def is_ci_scale(self) -> bool:
        return self.declaration.profile in B1_CI_SCALE_PROFILES

    def authority(self, observed_cpu_count: int) -> str:
        if not self.is_ci_scale:
            return AUTHORITY_PRODUCT_LOCAL
        if observed_cpu_count == CI_SCALE_REFERENCE_LOGICAL_CPUS:
            return AUTHORITY_CI_SCALE_REFERENCE
        return AUTHORITY_LOCAL_REPLICA

    def failures(
        self,
        roles: dict[str, B1RolePlacement],
        *,
        gateway_worker_pids: "set[int] | frozenset[int] | tuple[int, ...]" = (),
        when: str = "open",
    ) -> list[str]:
        out: list[str] = []
        decl = self.declaration
        # The declaration is authoritative for cardinality: schema-2 contracts
        # take it from their profile, schema-3 contracts from their topology
        # class. Reading it from the profile name would silently give a
        # discovery arm the gate's 2/1/1 shape.
        cardinality = decl.cardinality
        declared_total = decl.declared_cpu_total
        observed: dict[str, frozenset[int]] = {}
        for role in B1_ROLES:
            found = roles.get(role)
            if found is None:
                out.append(f"{when}: {role}: no effective placement reading")
                continue
            observed[role] = found.allowed_cpus
            if not found.pids:
                out.append(f"{when}: {role}: no live process observed")
            declared = decl.allowed(role)
            if found.allowed_cpus != declared:
                out.append(
                    f"{when}: {role}: effective CPUs "
                    f"{b1.format_cpu_list(found.allowed_cpus) if found.allowed_cpus else '<empty>'}, "
                    f"declared {b1.format_cpu_list(declared)}"
                )
            if len(found.allowed_cpus) != cardinality[role]:
                out.append(
                    f"{when}: {role}: {len(found.allowed_cpus)} effective CPUs, profile "
                    f"{decl.profile} declares {cardinality[role]}"
                )
            if found.allowed_cpus and not found.allowed_cpus <= self.host_cpus:
                out.append(
                    f"{when}: {role}: effective CPUs "
                    f"{b1.format_cpu_list(found.allowed_cpus)} are not a subset of the "
                    f"host-visible {b1.format_cpu_list(self.host_cpus)}"
                )
        for left, right in (
            ("gateway", "postgres"),
            ("gateway", "driver"),
            ("postgres", "driver"),
        ):
            overlap = observed.get(left, frozenset()) & observed.get(right, frozenset())
            if overlap:
                out.append(
                    f"{when}: {left}/{right}: measured roles share CPUs {sorted(overlap)}"
                )
        union = frozenset().union(*observed.values()) if observed else frozenset()
        if len(observed) == len(B1_ROLES) and len(union) != declared_total:
            out.append(
                f"{when}: measured roles occupy {len(union)} distinct CPUs, contract "
                f"{decl.profile} declares {declared_total}"
            )
        if decl.carries_topology and len(observed) == len(B1_ROLES):
            out.extend(self._topology_failures(observed, when=when))
        if self.is_ci_scale:
            if decl.reference_logical_cpus != CI_SCALE_REFERENCE_LOGICAL_CPUS:
                out.append(
                    f"{when}: ci-scale: declared reference capacity "
                    f"{decl.reference_logical_cpus}, pinned {CI_SCALE_REFERENCE_LOGICAL_CPUS}"
                )
            if len(self.host_cpus) < CI_SCALE_REFERENCE_LOGICAL_CPUS:
                out.append(
                    f"{when}: ci-scale: host offers {len(self.host_cpus)} logical CPUs, "
                    f"needs at least {CI_SCALE_REFERENCE_LOGICAL_CPUS}"
                )
        else:
            if len(self.host_cpus) < PRODUCT_MINIMUM_HOST_LOGICAL_CPUS:
                out.append(
                    f"{when}: product: host offers {len(self.host_cpus)} logical CPUs, "
                    f"needs at least {PRODUCT_MINIMUM_HOST_LOGICAL_CPUS}"
                )
            gateway_set = observed.get("gateway", frozenset())
            if len(gateway_set) != PRODUCT_GATEWAY_CPU_CARDINALITY:
                out.append(
                    f"{when}: gateway: {len(gateway_set)} exclusive CPUs, product declares "
                    f"{PRODUCT_GATEWAY_CPU_CARDINALITY}"
                )
        workers = set(gateway_worker_pids)
        if len(workers) != b1.INGEST_GATEWAY_WORKERS:
            out.append(
                f"{when}: gateway: {len(workers)} classified workers, declared "
                f"{b1.INGEST_GATEWAY_WORKERS}"
            )
        gateway = roles.get("gateway")
        if gateway is not None and workers and not workers <= set(gateway.pids):
            out.append(
                f"{when}: gateway: worker pids {sorted(workers - set(gateway.pids))} carry no "
                f"placement reading"
            )
        return out

    def _topology_failures(
        self, observed: "dict[str, frozenset[int]]", *, when: str
    ) -> list[str]:
        """FP-GC3-5: the physical relationship, proven from effective state.

        CPU identities alone prove nothing about cores: `0-1` is one physical
        core on a hosted four-vCPU guest and two different cores on the i7
        replica. This
        reconstructs the declared topology class from the sibling files and the
        *effective* role sets, and refuses the run when the two disagree.
        """
        out: list[str] = []
        decl = self.declaration
        reference = decl.reference_cpus
        groups = self.sibling_groups
        if not groups:
            return [f"{when}: topology: no thread_siblings_list reading for the reference set"]
        if set(groups) != set(reference):
            out.append(
                f"{when}: topology: sibling reading covers "
                f"{sorted(groups)}, referenceCpus is {sorted(reference)}"
            )
            return out
        seen: set[frozenset[int]] = set()
        for cpu in sorted(reference):
            group = groups[cpu]
            if len(group) != 2:
                out.append(
                    f"{when}: topology: cpu {cpu} reports {len(group)} thread sibling(s) "
                    f"({b1.format_cpu_list(group) if group else '<empty>'}); the reference "
                    f"deployment needs symmetric two-thread pairs"
                )
                continue
            if cpu not in group:
                out.append(f"{when}: topology: cpu {cpu} is missing from its own sibling list")
                continue
            if not group <= reference:
                out.append(
                    f"{when}: topology: cpu {cpu} has a sibling outside the reference set "
                    f"({b1.format_cpu_list(group)})"
                )
                continue
            if any(groups[member] != group for member in sorted(group)):
                out.append(
                    f"{when}: topology: cpu {cpu} sibling list {b1.format_cpu_list(group)} is "
                    f"not symmetric"
                )
                continue
            seen.add(group)
        if out:
            return out
        if len(seen) != 2 or frozenset().union(*seen) != reference:
            out.append(
                f"{when}: topology: the reference set splits into "
                f"{sorted(sorted(g) for g in seen)}, not two disjoint covering pairs"
            )
            return out
        measured = observed["gateway"] | observed["postgres"] | observed["driver"]
        unassigned = reference - measured
        if unassigned != decl.unassigned_cpus:
            out.append(
                f"{when}: topology: unassigned reference CPUs "
                f"{sorted(unassigned)}, contract declares {sorted(decl.unassigned_cpus)}"
            )
        expected_unassigned = probe.topology_unassigned_cardinality(decl.topology)
        if len(unassigned) != expected_unassigned:
            out.append(
                f"{when}: topology: {len(unassigned)} unassigned CPUs, class {decl.topology} "
                f"leaves {expected_unassigned}"
            )
        pair0, pair1 = sorted(tuple(sorted(group)) for group in seen)
        try:
            derived = probe.topology_mapping(
                decl.topology, pair0, pair1, decl.witness_orientation
            )
        except probe.TopologyProbeError as exc:
            return out + [f"{when}: topology: {exc}"]
        for role in B1_ROLES:
            if observed[role] != derived[role]:
                out.append(
                    f"{when}: topology: {role} effectively holds "
                    f"{b1.format_cpu_list(observed[role])}, class {decl.topology} orientation "
                    f"{decl.witness_orientation} over pairs {list(pair0)}/{list(pair1)} derives "
                    f"{b1.format_cpu_list(derived[role])}"
                )
        return out

    def sibling_map(self, cpu_ids) -> str:
        """The percent-encodable `<cpu>:<siblings>` map for one role's CPUs."""
        return probe.serialize_sibling_map(cpu_ids, self.sibling_groups)


def _product_promise_verdicts(result) -> "OrderedDict[str, str]":
    """The three product-promise comparisons, evaluated once, as met/missed.

    Recorded, not gating (FP-GC1-3): the values and operators are the shipped
    product promise and do not move; what changed is only that a truthful
    ``missed`` is data on the fingerprint rather than a failed test. The test
    that consumes this asserts each serialized token equals its live
    comparison -- so deleting a comparison, literalizing a token, or letting
    one disagree with its own operands is still a failure.
    """
    verdicts: "OrderedDict[str, str]" = OrderedDict()
    verdicts["product_errors_eq_zero"] = VERDICT_MET if result.errors == 0 else VERDICT_MISSED
    verdicts["product_p99_lt_150_ms"] = (
        VERDICT_MET if result.p99 < PRODUCT_P99_MS else VERDICT_MISSED
    )
    verdicts["product_served_eq_offered"] = (
        VERDICT_MET if result.served == result.offered else VERDICT_MISSED
    )
    return verdicts


def serialize_product_verdicts(verdicts: "dict[str, str]") -> str:
    """``field=token,`` in the fixed order, or the empty string for CI-scale."""
    if not verdicts:
        return ""
    if tuple(verdicts) != PRODUCT_VERDICT_FIELDS:
        raise B1PlacementError(
            f"product verdict fields {tuple(verdicts)} are not the closed ordered set "
            f"{PRODUCT_VERDICT_FIELDS}"
        )
    for field_name, token in verdicts.items():
        if token not in (VERDICT_MET, VERDICT_MISSED):
            raise B1PlacementError(f"{field_name}={token!r} is neither 'met' nor 'missed'")
    return "".join(f"{name}={verdicts[name]}," for name in PRODUCT_VERDICT_FIELDS)



# ---------------------------------------------------------------------------
# UT-IG-5 — harness unit tests (no server)
# ---------------------------------------------------------------------------


def test_due_times_monotone_at_burst_rate():
    rate = b1.BURST_RATE
    n = 1000
    t0 = 100.0
    dues = [t0 + i / rate for i in range(n)]
    assert all(dues[i] < dues[i + 1] for i in range(n - 1))
    assert abs((dues[1] - dues[0]) - 1 / rate) < 1e-12


def test_statistics_from_hand_written_vector():
    # 100 samples: latencies 1..100; p99 nearest-rank
    lats = [float(i) for i in range(1, 101)]
    p99 = b1.nearest_rank_p99(lats)
    # ceil(0.99*100)−1 = 98 → value 99 (1-indexed rank 99)
    assert p99 == 99.0
    result = b1.PhaseResult(
        offered=100,
        served=100,
        errors=0,
        latencies_ms=lats,
        t0=0.0,
        t_last_complete=0.5,
        due0=0.0,
        max_in_flight=10,
        max_backlog=0,
    )
    assert abs(result.served_rate - 200.0) < 1e-9
    assert result.max_lateness_ms == 100.0


def test_acceptance_cases_match_expected_verdicts():
    for name, expected in b1.ACCEPTANCE_EXPECTED.items():
        verdict, fails = b1.run_acceptance_case(name)
        assert verdict == expected, f"{name}: got {verdict} fails={fails}"


def test_acceptance_matrix_matches_superseded_formulations():
    """FP-IG-7: complete acceptance matrix incl. four superseded oracles."""
    for name, expected_final in b1.ACCEPTANCE_EXPECTED.items():
        matrix = b1.run_acceptance_matrix(name)
        assert matrix["final"] == expected_final, f"{name} final={matrix}"
        s1, s2, s3, s4 = b1.ACCEPTANCE_SUPERSEDED[name]
        assert matrix["form1"] == s1, f"{name} form1={matrix['form1']} want {s1}"
        assert matrix["form2"] == s2, f"{name} form2={matrix['form2']} want {s2}"
        assert matrix["form3"] == s3, f"{name} form3={matrix['form3']} want {s3}"
        assert matrix["form4"] == s4, f"{name} form4={matrix['form4']} want {s4}"


def test_serve_benchmark_passes_connection_ceiling_carrier(monkeypatch):
    """UT-IG-14 harness-side: B1 child passes the same serve carrier as main()."""
    from gateway.main import (
        BACKLOG,
        DEFAULT_MAX_CONNECTIONS_PER_WORKER,
        DEFAULT_TIMEOUT_KEEP_ALIVE_S,
    )

    called: dict = {}

    def fake_run(*args, **kwargs):
        called["args"] = args
        called["kwargs"] = kwargs

    monkeypatch.setattr("uvicorn.run", fake_run)
    b1.serve_benchmark(host="127.0.0.1", port=18080)
    assert called["kwargs"]["limit_concurrency"] == DEFAULT_MAX_CONNECTIONS_PER_WORKER
    assert called["kwargs"]["timeout_keep_alive"] == DEFAULT_TIMEOUT_KEEP_ALIVE_S
    assert called["kwargs"]["backlog"] == BACKLOG


# ---------------------------------------------------------------------------
# UT-IG-15 — histogram serializer, proc census parser, peak reducer (no server)
# ---------------------------------------------------------------------------


def test_status_histogram_serializer_sorts_and_counts():
    codes = [202, 202, 200, 503, 599, 202]
    assert b1.serialize_status_histogram(codes) == "200:1;202:3;503:1;599:1"
    assert sum(int(pair.split(":")[1]) for pair in b1.serialize_status_histogram(codes).split(";")) == len(
        codes
    )


def test_proc_tcp_established_parser_counts_matching_remote_port(tmp_path):
    serve_port = 0x1F90  # 8080
    remote_hex = f"{serve_port:04X}"
    tcp = textwrap.dedent(
        f"""
          sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
           0: 0100007F:EA60 0100007F:{remote_hex} 01 00000000:00000000 00000000:00000000 00000000     0        0 1 1 0000000000000000 20 4 30 10 40
           1: 0100007F:EA61 0100007F:{remote_hex} 06 00000000:00000000 00000000:00000000 00000000     0        0 2 1 0000000000000000 20 4 30 10 40
           2: 0100007F:EA62 0100007F:0050 01 00000000:00000000 00000000:00000000 00000000     0        0 3 1 0000000000000000 20 4 30 10 40
        """
    )
    tcp6 = textwrap.dedent(
        f"""
          sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
           0: 0000000000000000:0000000000000000:0000000000000000:0000000000000000:0100007F:EA70 0000000000000000:0000000000000000:0000000000000000:0000000000000000:0100007F:{remote_hex} 01 00000000:00000000 00000000:00000000 00000000     0        0 4 1 0000000000000000 20 4 30 10 40
        """
    )
    tcp_path = tmp_path / "tcp"
    tcp6_path = tmp_path / "tcp6"
    tcp_path.write_text(tcp, encoding="utf-8")
    tcp6_path.write_text(tcp6, encoding="utf-8")
    assert b1.count_established_to_serve_port(
        serve_port, tcp_path=tcp_path, tcp6_path=tcp6_path
    ) == 2


def test_proc_tcp_established_parser_returns_unavailable_on_malformed(tmp_path):
    bad = tmp_path / "tcp"
    good = tmp_path / "tcp6"
    bad.write_text("not a proc table\nbroken row\n", encoding="utf-8")
    good.write_text("  sl  local rem st\n", encoding="utf-8")
    assert (
        b1.count_established_to_serve_port(8080, tcp_path=bad, tcp6_path=good)
        == b1.UNAVAILABLE
    )


def test_proc_tcp_established_parser_returns_unavailable_on_unreadable(tmp_path):
    missing = tmp_path / "nonexistent_tcp"
    good = tmp_path / "tcp6"
    good.write_text("  sl  local rem st\n", encoding="utf-8")
    assert (
        b1.count_established_to_serve_port(8080, tcp_path=missing, tcp6_path=good)
        == b1.UNAVAILABLE
    )


def test_peak_established_reducer_returns_max_or_unavailable():
    assert b1.peak_established_from_samples([1, 5, 3]) == 5
    assert b1.peak_established_from_samples([b1.UNAVAILABLE, b1.UNAVAILABLE]) == b1.UNAVAILABLE
    assert b1.peak_established_from_samples([b1.UNAVAILABLE, 2]) == 2


# ---------------------------------------------------------------------------
# UT-IG-16 — shed probe classifier and probe-size arithmetic (no server)
# ---------------------------------------------------------------------------


def test_shed_probe_outcome_classifier_precedence():
    min_est = 8
    assert b1.classify_shed_probe_outcome(
        [(503, False), (200, False)], established_count=8, pigeonhole_minimum_count=min_est
    ) == "fired"
    assert b1.classify_shed_probe_outcome(
        [(503, False), (None, True)], established_count=8, pigeonhole_minimum_count=min_est
    ) == "fired"
    assert b1.classify_shed_probe_outcome(
        [(200, False), (200, False)], established_count=8, pigeonhole_minimum_count=min_est
    ) == "absent"
    assert b1.classify_shed_probe_outcome(
        [(200, False), (None, True)], established_count=8, pigeonhole_minimum_count=min_est
    ) == "timeout"
    assert b1.classify_shed_probe_outcome(
        [(503, False)], established_count=7, pigeonhole_minimum_count=min_est
    ) == b1.UNAVAILABLE


def test_probe_connection_count_recomputed_from_imported_constants():
    from gateway.main import DEFAULT_MAX_CONNECTIONS_PER_WORKER

    expected = (
        b1.INGEST_GATEWAY_WORKERS * (DEFAULT_MAX_CONNECTIONS_PER_WORKER - 1)
        + 1
        + b1.PROBE_SLACK
    )
    assert (
        b1.probe_connection_count(
            workers=b1.INGEST_GATEWAY_WORKERS,
            ceiling_per_worker=DEFAULT_MAX_CONNECTIONS_PER_WORKER,
        )
        == expected
    )


@pytest.mark.asyncio
async def test_run_open_loop_with_serve_port_records_peak_census():
    """Census sampler runs during the measured window when serve_port is set."""

    class StubTransport:
        async def post(self, url, *, content, headers):
            return 202, b'{"status":"ok"}', None

    measured = [
        (b'{"event_id":"a"}', {"Content-Type": "application/json"}),
        (b'{"event_id":"b"}', {"Content-Type": "application/json"}),
    ]
    result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=measured,
        rate=1000,
        transport=StubTransport(),
        max_in_flight=10,
        warmup=(b'{"event_id":"w"}', {"Content-Type": "application/json"}),
        include_sync_warmup=True,
        serve_port=65534,
    )
    assert result.peak_established_connections in (
        0,
        b1.UNAVAILABLE,
    ) or isinstance(result.peak_established_connections, int)


@pytest.mark.asyncio
async def test_run_shed_probe_fired_against_inline_ceiling_server():
    """run_shed_probe connect-all-then-request path against a shedding server."""
    ceiling = 4
    min_est = b1.pigeonhole_minimum(workers=1, ceiling_per_worker=ceiling)
    active = 0

    async def handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        nonlocal active
        active += 1
        slot = active
        try:
            await reader.read(4096)
            if slot <= ceiling - 1:
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                )
            else:
                writer.write(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n\r\n"
                )
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    try:
        outcome = await b1.run_shed_probe(
            host,
            port,
            workers=1,
            ceiling_per_worker=ceiling,
        )
        assert outcome == "fired"
        assert min_est == 4
    finally:
        server.close()
        await server.wait_closed()


def _parse_b1_env_field(line: str, field: str) -> str:
    """One value out of the flat `B1 env=` key/value list.

    The field separator is a comma FOLLOWED BY A NEW `key=` token, not every
    comma. `*_allowed_cpus`, `reference_cpus` and `unassigned_cpus` carry
    canonical Linux CPU-list syntax, which spells a non-contiguous set with a
    comma (`{0,2}` -> `0,2`), so splitting on every comma truncated such a
    value at its first range. No value carries a raw `=` -- it is absent from
    `B1_DIAGNOSTIC_SAFE_CHARACTERS` and every free-form diagnostic is
    percent-encoded -- so a fragment without one continues the value before it,
    and an empty fragment is the line terminator and continues nothing.
    """
    prefix = f"{field}="
    parts = line.split(",")
    for index, part in enumerate(parts):
        if not part.startswith(prefix):
            continue
        value = [part[len(prefix) :]]
        for fragment in parts[index + 1 :]:
            if not fragment or "=" in fragment:
                break
            value.append(fragment)
        return ",".join(value)
    raise KeyError(field)


def _is_never_served_status_code(code: int) -> bool:
    """HTTP codes that are errors without body inspection (200 stays ambiguous)."""
    if code in (503, 599):
        return True
    return 400 <= code < 600 and code != 200


@pytest.mark.b1_live
def test_b1_fingerprint_line_carries_terminal_fields(b1_ci_scale_run):
    """FP-IG-35: three reported-only fields present and reconciled."""
    from collections import Counter

    line = b1_ci_scale_run["fingerprint"]
    result = b1_ci_scale_run["result"]
    hist_raw = _parse_b1_env_field(line, "status_histogram")
    peak_raw = _parse_b1_env_field(line, "peak_established_connections")
    shed = _parse_b1_env_field(line, "shed_probe")

    assert hist_raw == b1.serialize_status_histogram(result.status_codes)
    hist_counts: Counter[int] = Counter()
    for pair in hist_raw.split(";"):
        if pair:
            code, count = pair.split(":")
            hist_counts[int(code)] = int(count)
    assert hist_counts == Counter(result.status_codes)
    assert sum(hist_counts.values()) == result.offered
    never_served_hist = sum(
        count for code, count in hist_counts.items()
        if _is_never_served_status_code(code)
    )
    assert never_served_hist <= result.errors
    assert hist_counts.get(202, 0) <= result.served

    assert peak_raw.isdigit() or peak_raw == b1.UNAVAILABLE
    assert shed in {"fired", "absent", "timeout", b1.UNAVAILABLE}


@pytest.mark.b1_live
def test_b1_fingerprint_line_locates_the_in_flight_population(b1_ci_scale_run):
    """FP-IG-37: pool census fields present, reconciled, two safe inequalities."""
    line = b1_ci_scale_run["fingerprint"]
    result = b1_ci_scale_run["result"]

    peak_pool_conn_raw = _parse_b1_env_field(line, "peak_pool_connections")
    peak_pool_requests_raw = _parse_b1_env_field(line, "peak_pool_requests")
    assert line.index("peak_pool_connections=") < line.index("peak_pool_requests=") < line.index("peak_pool_queued=")
    peak_pool_q_raw = _parse_b1_env_field(line, "peak_pool_queued")
    pool_seen_raw = _parse_b1_env_field(line, "pool_connections_seen")

    for raw, quantity in (
        (peak_pool_conn_raw, result.peak_pool_connections),
        (peak_pool_requests_raw, result.peak_pool_requests),
        (peak_pool_q_raw, result.peak_pool_queued),
        (pool_seen_raw, result.pool_connections_seen),
    ):
        assert raw.isdigit() or raw == b1.UNAVAILABLE
        expected = str(quantity) if isinstance(quantity, int) else quantity
        assert raw == expected

    if isinstance(result.peak_pool_queued, int):
        assert result.peak_pool_queued <= result.max_in_flight
    if isinstance(result.pool_connections_seen, int) and isinstance(
        result.peak_pool_connections, int
    ):
        assert result.pool_connections_seen >= result.peak_pool_connections


@pytest.mark.b1_live
def test_b1_fingerprint_line_carries_the_per_worker_census(b1_ci_scale_run):
    """FP-IG-38: per-worker census fields present and reconciled."""
    line = b1_ci_scale_run["fingerprint"]
    result = b1_ci_scale_run["result"]
    workers_pre = b1_ci_scale_run["workers_pre"]

    peaks_raw = _parse_b1_env_field(line, "worker_established_peaks")
    peak_worker_raw = _parse_b1_env_field(line, "peak_worker_established")

    expected_peaks_str = b1.serialize_worker_established_peaks(
        result.worker_established_peaks
    )
    expected_peak_worker = (
        str(result.peak_worker_established)
        if isinstance(result.peak_worker_established, int)
        else result.peak_worker_established
    )

    assert peaks_raw.isdigit() or "+" in peaks_raw or peaks_raw == b1.UNAVAILABLE
    assert peak_worker_raw.isdigit() or peak_worker_raw == b1.UNAVAILABLE
    assert peaks_raw == expected_peaks_str
    assert peak_worker_raw == expected_peak_worker

    if peaks_raw != b1.UNAVAILABLE:
        peak_parts = [int(x) for x in peaks_raw.split("+")]
        assert len(peak_parts) == len(workers_pre)
        assert peak_worker_raw.isdigit()
        assert int(peak_worker_raw) == max(peak_parts)


def _parse_leg_triple(raw: str) -> tuple[float, float, float]:
    parts = raw.split("/")
    assert len(parts) == 3, raw
    return float(parts[0]), float(parts[1]), float(parts[2])


@pytest.mark.b1_live
def test_b1_fingerprint_line_decomposes_the_headline_lateness(b1_ci_scale_run):
    """FP-IG-39: both leg fields present, numeric, wired to this run."""
    line = b1_ci_scale_run["fingerprint"]
    result = b1_ci_scale_run["result"]

    split_raw = _parse_b1_env_field(line, "p99_leg_split")
    p99s_raw = _parse_b1_env_field(line, "leg_p99s")
    p99_ms_raw = _parse_b1_env_field(line, "p99_ms")

    peak_at = line.index("peak_worker_established=")
    split_at = line.index("p99_leg_split=")
    p99s_at = line.index("leg_p99s=")
    assert peak_at < split_at < p99s_at

    assert "/" in split_raw and split_raw != b1.UNAVAILABLE
    assert "/" in p99s_raw and p99s_raw != b1.UNAVAILABLE
    split_vals = _parse_leg_triple(split_raw)
    p99s_vals = _parse_leg_triple(p99s_raw)
    assert all(math.isfinite(v) for v in split_vals + p99s_vals)

    assert split_raw == b1.serialize_leg_triple(result.p99_leg_split)
    assert p99s_raw == b1.serialize_leg_triple(result.leg_p99s)

    for vec in (
        result.pre_dispatch_slip_ms,
        result.start_lag_ms,
        result.attempt_duration_ms,
    ):
        assert len(vec) == result.offered
        assert all(v >= -b1.LEG_SUM_TOLERANCE_MS for v in vec)

    idx = result.p99_index
    assert idx is not None
    raw_triple = (
        result.pre_dispatch_slip_ms[idx],
        result.start_lag_ms[idx],
        result.attempt_duration_ms[idx],
    )
    assert abs(sum(raw_triple) - result.p99) <= b1.LEG_SUM_TOLERANCE_MS
    parsed_p99 = float(p99_ms_raw)
    assert abs(sum(split_vals) - parsed_p99) <= b1.LEG_LINE_TOLERANCE_MS


# ---------------------------------------------------------------------------
# UT-IG-19 — per-request station decomposition (no product server)
# ---------------------------------------------------------------------------


def _stub_payload(event_id: str) -> tuple[bytes, dict[str, str]]:
    return (
        json.dumps({"event_id": event_id}).encode(),
        {"Content-Type": "application/json"},
    )


class _QuantumTransport:
    """Stub that awaits a pinned quantum, then returns the served class."""

    def __init__(self, quantum_s: float):
        self.quantum_s = quantum_s

    async def post(self, url, *, content, headers):
        await asyncio.sleep(self.quantum_s)
        return 202, b'{"status":"ok"}', None


class _HoldThenQuantumTransport:
    """Attempts 0 and 1 wait on ``release`` then S; later attempts take S."""

    def __init__(self, quantum_s: float, release: asyncio.Event):
        self.quantum_s = quantum_s
        self.release = release
        self._arrivals = 0
        self.second_arrival = asyncio.Event()

    async def post(self, url, *, content, headers):
        self._arrivals += 1
        n = self._arrivals
        if n <= 2:
            if n == 2:
                self.second_arrival.set()
            await self.release.wait()
            await asyncio.sleep(self.quantum_s)
        else:
            await asyncio.sleep(self.quantum_s)
        return 202, b'{"status":"ok"}', None


@pytest.mark.asyncio
async def test_leg_derivation_runs_after_window_complete(monkeypatch):
    """C1 [live path]: CPU-window hook fires before named O(N) derivation."""
    order: list[str] = []
    real_derive = b1.derive_leg_vectors

    def _wrapped(*args, **kwargs):
        order.append("derive")
        return real_derive(*args, **kwargs)

    monkeypatch.setattr(b1, "derive_leg_vectors", _wrapped)
    n = 4
    measured = [_stub_payload(f"w{i}") for i in range(n)]
    result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=measured,
        rate=50,
        transport=_QuantumTransport(1.0 / 50),
        max_in_flight=n,
        include_sync_warmup=False,
        on_window_complete=lambda: order.append("window"),
    )
    assert order == ["window", "derive"], order
    assert len(result.pre_dispatch_slip_ms) == n


def test_window_complete_precedes_derivation_in_source():
    """C1 [live path]: hook call site is before the named derive call."""
    src = _PROFILE_PATH.read_text(encoding="utf-8")
    hook_at = src.index("on_window_complete()")
    derive_at = src.index("= derive_leg_vectors(")
    assert hook_at < derive_at


def test_b1_fixture_samples_cpu_after_on_window_complete():
    """C1 [consumer path]: the closing CPU read happens inside the hook.

    The carrier moved with GC-1: gateway CPU is a reported diagnostic taken
    from the gateway container's own cgroup rather than a /proc walk of a host
    child, so the property pinned here is that the closing counter is read
    *inside* ``_after_window`` and consumed from ``marks`` afterwards -- never
    re-read once the measured window has closed.
    """
    src = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    hook = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_after_window":
            hook = node
    assert hook is not None
    hook_src = ast.get_source_segment(src, hook)
    assert hook_src is not None
    assert "_collect_cpu_diagnostics" in hook_src
    assert '"after"' in hook_src

    fixture = next(
        n for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_run_b1_reference"
    )
    fixture_src = ast.get_source_segment(src, fixture)
    assert fixture_src is not None
    # The retired host-child reader must not have survived anywhere in the
    # live fixture: it would measure a process tree that no longer owns the
    # gateway's cgroup.
    assert "tree_cpu_seconds" not in fixture_src
    # ... and the collector itself reads the cgroup files, once per phase.
    collector = next(
        n for n in ast.walk(fixture)
        if isinstance(n, ast.FunctionDef) and n.name == "_collect_cpu_diagnostics"
    )
    collector_src = ast.get_source_segment(src, collector)
    assert "_read_cpu_files" in collector_src

    hooked = False
    diagnostics_from_marks = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if (
                    kw.arg == "on_window_complete"
                    and isinstance(kw.value, ast.Name)
                    and kw.value.id == "_after_window"
                ):
                    hooked = True
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "diagnostics"
        ):
            seg = ast.get_source_segment(src, node)
            assert seg is not None
            assert "_role_diagnostics" in seg
            assert 'marks.get(f"{role}_cpu_stat_before")' in seg
            assert 'marks.get(f"{role}_cpu_stat_after")' in seg
            assert "_read_cpu_files" not in seg
            diagnostics_from_marks = True
    assert hooked
    assert diagnostics_from_marks


@pytest.mark.asyncio
async def test_ut_ig19_leg_reconciliation():
    """UT-IG-19 (1) [live path]: per-request sum identity against a quantum stub."""
    rate = 50
    delta_s = 1.0 / rate
    quantum_s = 2 * delta_s
    n = 8
    measured = [_stub_payload(f"m{i}") for i in range(n)]
    result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=measured,
        rate=rate,
        transport=_QuantumTransport(quantum_s),
        max_in_flight=n,
        include_sync_warmup=False,
    )
    quantum_ms = quantum_s * 1000.0
    assert len(result.pre_dispatch_slip_ms) == n
    for i in range(n):
        total = (
            result.pre_dispatch_slip_ms[i]
            + result.start_lag_ms[i]
            + result.attempt_duration_ms[i]
        )
        assert abs(total - result.latencies_ms[i]) <= b1.LEG_SUM_TOLERANCE_MS
        assert result.attempt_duration_ms[i] >= quantum_ms
        assert result.pre_dispatch_slip_ms[i] >= -b1.LEG_SUM_TOLERANCE_MS


@pytest.mark.asyncio
async def test_ut_ig19_gate_placement():
    """UT-IG-19 (2) [live path]: d_i is after the gate; hold-run is sync-based."""
    delta_s = 20 * (10**-3)
    rate = int(round(1.0 / delta_s))
    assert abs(1.0 / rate - delta_s) < 1e-12
    k = 10
    quantum_s = k * delta_s
    n = 8
    measured = [_stub_payload(f"g{i}") for i in range(n)]
    result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=measured,
        rate=rate,
        transport=_QuantumTransport(quantum_s),
        max_in_flight=2,
        include_sync_warmup=False,
    )
    for i in range(2, n):
        bound = (math.floor(i / 2) * quantum_s - i * delta_s) * 1000.0
        if bound > 0:
            assert result.pre_dispatch_slip_ms[i] >= bound - b1.LEG_SUM_TOLERANCE_MS

    release = asyncio.Event()
    hold = _HoldThenQuantumTransport(quantum_s, release)
    hold_n = 4
    hold_measured = [_stub_payload(f"h{i}") for i in range(hold_n)]

    async def _release_after_second_arrival() -> None:
        await hold.second_arrival.wait()
        await asyncio.sleep(2 * delta_s)
        release.set()

    releaser = asyncio.create_task(_release_after_second_arrival())
    hold_result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=hold_measured,
        rate=rate,
        transport=hold,
        max_in_flight=2,
        include_sync_warmup=False,
    )
    await releaser
    lower = min(
        hold_result.latencies_ms[0] - 2 * delta_s * 1000.0,
        hold_result.latencies_ms[1] - delta_s * 1000.0,
    )
    assert hold_result.pre_dispatch_slip_ms[2] >= lower - b1.LEG_SUM_TOLERANCE_MS


def test_ut_ig19_summary_evaluator():
    """UT-IG-19 (3) [evaluator]: identity split ≠ per-leg p99s; tie → smallest index."""
    n = 100
    slip = [0.5] * n
    lag = [0.3] * n
    attempt = [0.2] * n
    latencies = [1.0] * n
    # Three-way tie at the p99 rank (sorted[98] = 100.0); smallest index wins.
    latencies[10] = latencies[50] = latencies[80] = 100.0
    slip[10], lag[10], attempt[10] = 11.0, 22.0, 67.0
    slip[50], lag[50], attempt[50] = 6.0, 8.0, 86.0
    slip[80], lag[80], attempt[80] = 7.0, 9.0, 84.0
    expected = {
        "p99_index": 10,
        "split": (11.0, 22.0, 67.0),
        "leg_p99s": (7.0, 9.0, 84.0),
    }
    values = (
        expected["split"] + expected["leg_p99s"] + (float(expected["p99_index"]),)
    )
    assert len(set(values)) == 7

    idx = b1.p99_index_of(latencies)
    split = b1.p99_leg_split_of(latencies, slip, lag, attempt)
    per_leg = b1.leg_p99s_of(slip, lag, attempt)
    assert idx == expected["p99_index"]
    assert split == expected["split"]
    assert per_leg == expected["leg_p99s"]
    assert split != per_leg


def _is_idx_range_guard(node: ast.AST) -> bool:
    """True iff ``node`` is the compare ``0 <= idx < n``."""
    if not isinstance(node, ast.Compare) or len(node.ops) != 2:
        return False
    return (
        isinstance(node.left, ast.Constant)
        and node.left.value == 0
        and isinstance(node.ops[0], ast.LtE)
        and isinstance(node.ops[1], ast.Lt)
        and isinstance(node.comparators[0], ast.Name)
        and node.comparators[0].id == "idx"
        and isinstance(node.comparators[1], ast.Name)
        and node.comparators[1].id == "n"
    )


def _is_attempt_at_idx_store(node: ast.AST) -> bool:
    """True iff ``node`` assigns to ``attempt_at[idx]``."""
    if not isinstance(node, ast.Assign):
        return False
    for target in node.targets:
        if (
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Name)
            and target.value.id == "attempt_at"
            and isinstance(target.slice, ast.Name)
            and target.slice.id == "idx"
        ):
            return True
    return False


def _one_records_c_i_behind_idx_guard(src: str) -> bool:
    """True iff nested ``_one`` stores ``attempt_at[idx]`` only under ``0 <= idx < n``.

    Every matching assignment must sit inside that guard's body; a matching
    compare anywhere in ``_one`` is not enough, and an unguarded store fails.
    """
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef) or node.name != "_one":
            continue
        stores: list[ast.Assign] = []
        guards: list[ast.If] = []
        for child in ast.walk(node):
            if _is_attempt_at_idx_store(child):
                stores.append(child)
            if isinstance(child, ast.If) and _is_idx_range_guard(child.test):
                guards.append(child)
        if not stores:
            return False
        guarded_ids: set[int] = set()
        for guard in guards:
            for stmt in guard.body:
                for inner in ast.walk(stmt):
                    guarded_ids.add(id(inner))
        return all(id(store) in guarded_ids for store in stores)
    return False


def test_ut_ig19_idx_guard_rejects_assignment_outside_compare():
    """W2: a matching ``0 <= idx < n`` anywhere in ``_one`` is not enough."""
    unguarded = textwrap.dedent(
        """
        async def _one(idx, raw, headers):
            if 0 <= idx < n:
                pass
            attempt_at[idx] = time.perf_counter()
        """
    )
    guarded = textwrap.dedent(
        """
        async def _one(idx, raw, headers):
            if 0 <= idx < n:
                attempt_at[idx] = time.perf_counter()
        """
    )
    assert _one_records_c_i_behind_idx_guard(unguarded) is False
    assert _one_records_c_i_behind_idx_guard(guarded) is True


@pytest.mark.asyncio
async def test_ut_ig19_negative_index_guard():
    """UT-IG-19 (4) [live path]: warmup/prologue never write a measured slot."""
    src = _PROFILE_PATH.read_text(encoding="utf-8")
    assert _one_records_c_i_behind_idx_guard(src)
    assert "complete_at" not in src
    rate = 50
    n = 3
    measured = [_stub_payload(f"n{i}") for i in range(n)]
    warmup = _stub_payload("warm")
    prologue = [_stub_payload("p0"), _stub_payload("p1")]
    result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=measured,
        rate=rate,
        transport=_QuantumTransport(1.0 / rate),
        max_in_flight=n,
        warmup=warmup,
        prologue=prologue,
        include_sync_warmup=True,
    )
    assert len(result.pre_dispatch_slip_ms) == n
    assert len(result.start_lag_ms) == n
    assert len(result.attempt_duration_ms) == n
    assert len(result.latencies_ms) == n
    for i in range(n):
        due_i = result.due0 + i / rate
        d_i = due_i + result.pre_dispatch_slip_ms[i] / 1000.0
        c_i = d_i + result.start_lag_ms[i] / 1000.0
        assert c_i >= d_i - 1e-12
        assert d_i >= result.t0 - 1e-12


def test_ut_ig19_serializer_round_trip():
    """UT-IG-19 (5) [consumer path]: :.3f width and the two-tolerance boundary."""
    assert b1.LEG_SUM_TOLERANCE_MS == 1e-6
    assert b1.LEG_LINE_TOLERANCE_MS == (
        3 * (10**-3) / 2 + (10**-1) / 2 + b1.LEG_SUM_TOLERANCE_MS
    )
    triple = (1.234567, 2.345678, 3.456789)
    rendered = b1.serialize_leg_triple(triple)
    assert rendered == f"{triple[0]:.3f}/{triple[1]:.3f}/{triple[2]:.3f}"
    parts = rendered.split("/")
    assert all(len(p.split(".")[1]) == 3 for p in parts)
    parsed = _parse_leg_triple(rendered)
    assert parsed == (float(f"{triple[0]:.3f}"), float(f"{triple[1]:.3f}"), float(f"{triple[2]:.3f}"))

    # Each raw leg sits just above the :.3f half-ulp so format rounds upward.
    raw_legs = (1.0005001, 2.0005001, 3.0005001)
    assert all(float(f"{leg:.3f}") > leg for leg in raw_legs)
    line_split = b1.serialize_leg_triple(raw_legs)
    parsed_split = _parse_leg_triple(line_split)
    raw_p99 = sum(raw_legs)
    parsed_p99 = float(f"{raw_p99:.1f}")
    parsed_sum = sum(parsed_split)
    assert abs(parsed_sum - parsed_p99) <= b1.LEG_LINE_TOLERANCE_MS
    assert abs(parsed_sum - parsed_p99) > b1.LEG_SUM_TOLERANCE_MS


# ---------------------------------------------------------------------------
# UT-IG-18 — per-worker established-socket census (no product server)
# ---------------------------------------------------------------------------


def _write_proc_tcp_fixture(
    tmp_path: Path, *, serve_port: int, rows: list[tuple[int, str, str, str]]
) -> tuple[Path, Path]:
    """Build tcp/tcp6 fixture files; each row is (inode, local, remote, state)."""
    serve_hex = f"{serve_port:04X}"
    lines = [
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
    ]
    for inode, local, remote, state in rows:
        lines.append(
            f"   {inode}: {local} {remote} {state} "
            "00000000:00000000 00000000:00000000 00000000     0        0 "
            f"{inode} 1 0000000000000000 20 4 30 10 40"
        )
    tcp = tmp_path / "tcp"
    tcp6 = tmp_path / "tcp6"
    tcp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tcp6.write_text("  sl  local_address rem_address st\n", encoding="utf-8")
    return tcp, tcp6


def _write_proc_fd_fixture(tmp_path: Path, pid: int, links: dict[str, str]) -> Path:
    fd_dir = tmp_path / f"proc_{pid}_fd"
    fd_dir.mkdir()
    for name, target in links.items():
        (fd_dir / name).symlink_to(target)
    return fd_dir


def test_per_worker_census_attributes_sockets_to_each_pid(tmp_path):
    """UT-IG-18: N held sockets on one pid, zero on another — not aggregate for both."""
    serve_port = 18080
    serve_hex = f"{serve_port:04X}"
    inode_a, inode_b = 101, 102
    tcp = tmp_path / "tcp"
    tcp6 = tmp_path / "tcp6"
    tcp.write_text(
        textwrap.dedent(
            f"""
              sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
               0: 0100007F:{serve_hex} 0100007F:EA60 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode_a} 1 0000000000000000 20 4 30 10 40
               1: 0100007F:{serve_hex} 0100007F:EA61 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode_b} 1 0000000000000000 20 4 30 10 40
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    tcp6.write_text("  sl  local_address rem_address st\n", encoding="utf-8")
    pid_with = 10001
    pid_without = 10002
    fd_with = _write_proc_fd_fixture(
        tmp_path,
        pid_with,
        {"3": f"socket:[{inode_a}]", "4": f"socket:[{inode_b}]", "5": "pipe:[999]"},
    )
    fd_without = _write_proc_fd_fixture(tmp_path, pid_without, {"3": "pipe:[888]"})

    def fd_for_pid(pid: int) -> Path:
        return fd_with if pid == pid_with else fd_without

    counts = b1.count_per_worker_established_to_serve_port(
        [pid_with, pid_without],
        serve_port,
        tcp_path=tcp,
        tcp6_path=tcp6,
        fd_dir_for_pid=fd_for_pid,
    )
    assert counts == [2, 0]


def test_per_worker_census_reads_proc_tcp_once_per_sample(tmp_path, monkeypatch):
    """UT-IG-18: one /proc/net/tcp[6] read per count_per_worker invocation, not per pid."""
    serve_port = 18081
    serve_hex = f"{serve_port:04X}"
    inode_a, inode_b = 201, 202
    tcp = tmp_path / "tcp"
    tcp6 = tmp_path / "tcp6"
    tcp.write_text(
        textwrap.dedent(
            f"""
              sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
               0: 0100007F:{serve_hex} 0100007F:EA60 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode_a} 1 0000000000000000 20 4 30 10 40
               1: 0100007F:{serve_hex} 0100007F:EA61 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode_b} 1 0000000000000000 20 4 30 10 40
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    tcp6.write_text("  sl  local_address rem_address st\n", encoding="utf-8")
    pid_with = 10003
    pid_without = 10004
    fd_with = _write_proc_fd_fixture(
        tmp_path,
        pid_with,
        {"3": f"socket:[{inode_a}]", "4": f"socket:[{inode_b}]"},
    )
    fd_without = _write_proc_fd_fixture(tmp_path, pid_without, {"3": "pipe:[888]"})

    def fd_for_pid(pid: int) -> Path:
        return fd_with if pid == pid_with else fd_without

    read_calls = 0
    real_read = b1.read_proc_net_tcp_tables

    def counting_read(**kwargs):
        nonlocal read_calls
        read_calls += 1
        return real_read(**kwargs)

    monkeypatch.setattr(b1, "read_proc_net_tcp_tables", counting_read)

    counts = b1.count_per_worker_established_to_serve_port(
        [pid_with, pid_without],
        serve_port,
        tcp_path=tcp,
        tcp6_path=tcp6,
        fd_dir_for_pid=fd_for_pid,
    )
    assert counts == [2, 0]
    assert read_calls == 1


@pytest.mark.asyncio
async def test_census_sampler_reads_proc_tcp_once_per_tick(tmp_path, monkeypatch):
    """UT-IG-18: production _census_sampler reads /proc/net/tcp[6] once per tick."""
    serve_port = 18082
    serve_hex = f"{serve_port:04X}"
    inode_client, inode_client2, inode_server = 111, 333, 222
    tcp = tmp_path / "tcp"
    tcp6 = tmp_path / "tcp6"
    tcp.write_text(
        textwrap.dedent(
            f"""
              sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
               0: 0100007F:EA60 0100007F:{serve_hex} 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode_client} 1 0000000000000000 20 4 30 10 40
               1: 0100007F:{serve_hex} 0100007F:EA61 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode_server} 1 0000000000000000 20 4 30 10 40
               2: 0100007F:EA62 0100007F:{serve_hex} 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode_client2} 1 0000000000000000 20 4 30 10 40
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    tcp6.write_text("  sl  local_address rem_address st\n", encoding="utf-8")

    tcp_text = tcp.read_text(encoding="utf-8")
    tcp6_text = tcp6.read_text(encoding="utf-8")

    pid_with = 10005
    pid_without = 10006
    fd_with = _write_proc_fd_fixture(
        tmp_path, pid_with, {"3": f"socket:[{inode_server}]"}
    )
    fd_without = _write_proc_fd_fixture(tmp_path, pid_without, {"3": "pipe:[888]"})

    def fd_for_pid(pid: int) -> Path:
        return fd_with if pid == pid_with else fd_without

    # Same bytes, different measurands: remote-port aggregate vs local-port inode set.
    # Two client-side rows (remote = serve port) vs one server-side inode {222} — counts
    # must diverge so a silent merge onto len(inodes) cannot pass.
    assert b1.count_established_from_proc_tables(tcp_text, tcp6_text, serve_port) == 2
    assert b1.established_serve_port_inodes_from_proc_tables(
        tcp_text, tcp6_text, serve_port
    ) == {inode_server}
    assert b1.count_per_worker_established_to_serve_port(
        [pid_with, pid_without],
        serve_port,
        tcp_text=tcp_text,
        tcp6_text=tcp6_text,
        fd_dir_for_pid=fd_for_pid,
    ) == [1, 0]

    real_per_worker = b1.count_per_worker_established_to_serve_port

    def per_worker_with_fd(worker_pids, serve_port, **kwargs):
        kwargs.setdefault("fd_dir_for_pid", fd_for_pid)
        return real_per_worker(worker_pids, serve_port, **kwargs)

    monkeypatch.setattr(
        b1, "count_per_worker_established_to_serve_port", per_worker_with_fd
    )

    read_calls = 0
    real_read = b1.read_proc_net_tcp_tables

    def counting_read(**kwargs):
        nonlocal read_calls
        read_calls += 1
        kwargs.setdefault("tcp_path", tcp)
        kwargs.setdefault("tcp6_path", tcp6)
        return real_read(**kwargs)

    monkeypatch.setattr(b1, "read_proc_net_tcp_tables", counting_read)

    parser_ticks = 0
    real_aggregate = b1.count_established_to_serve_port

    def counting_aggregate(serve_port, **kwargs):
        nonlocal parser_ticks
        if kwargs.get("tcp_text") is not None:
            parser_ticks += 1
        return real_aggregate(serve_port, **kwargs)

    monkeypatch.setattr(b1, "count_established_to_serve_port", counting_aggregate)

    class SlowStubTransport:
        async def post(self, url, *, content, headers):
            await asyncio.sleep(0.25)
            return 202, b'{"status":"ok"}', None

    measured = [
        (b'{"event_id":"a"}', {"Content-Type": "application/json"}),
        (b'{"event_id":"b"}', {"Content-Type": "application/json"}),
    ]
    result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=measured,
        rate=1000,
        transport=SlowStubTransport(),
        max_in_flight=2,
        include_sync_warmup=False,
        serve_port=serve_port,
        worker_pids=[pid_with, pid_without],
    )

    assert parser_ticks >= 1
    assert read_calls == parser_ticks
    assert result.peak_established_connections == 2
    assert result.worker_established_peaks == [1, 0]
    assert result.peak_worker_established == 1


def test_per_worker_census_skips_non_socket_and_vanished_fd(tmp_path):
    serve_port = 9000
    serve_hex = f"{serve_port:04X}"
    inode = 555
    tcp, tcp6 = _write_proc_tcp_fixture(
        tmp_path,
        serve_port=serve_port,
        rows=[(0, f"0100007F:{serve_hex}", "0100007F:EA60", "01")],
    )
    tcp.write_text(
        textwrap.dedent(
            f"""
              sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
               0: 0100007F:{serve_hex} 0100007F:EA60 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode} 1 0000000000000000 20 4 30 10 40
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fd_dir = tmp_path / "fd"
    fd_dir.mkdir()
    (fd_dir / "3").symlink_to(f"socket:[{inode}]")
    (fd_dir / "4").symlink_to("anon_inode:[eventfd]")
    (fd_dir / "5").symlink_to("socket:[99999]")  # foreign inode

    count = b1.count_worker_established_to_serve_port(
        42, serve_port, tcp_path=tcp, tcp6_path=tcp6, fd_dir=fd_dir
    )
    assert count == 1


def test_per_worker_census_vanished_fd_is_skipped_not_raised(tmp_path, monkeypatch):
    serve_port = 9001
    serve_hex = f"{serve_port:04X}"
    inode = 777
    tcp, tcp6 = _write_proc_tcp_fixture(
        tmp_path,
        serve_port=serve_port,
        rows=[(0, f"0100007F:{serve_hex}", "0100007F:EA60", "01")],
    )
    tcp.write_text(
        textwrap.dedent(
            f"""
              sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
               0: 0100007F:{serve_hex} 0100007F:EA60 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode} 1 0000000000000000 20 4 30 10 40
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fd_dir = tmp_path / "fd"
    fd_dir.mkdir()
    (fd_dir / "3").symlink_to(f"socket:[{inode}]")
    ghost = fd_dir / "4"
    ghost.symlink_to(f"socket:[{inode}]")

    real_readlink = os.readlink

    def flaky_readlink(path):
        if Path(path).name == "4":
            raise OSError("vanished")
        return real_readlink(path)

    monkeypatch.setattr(os, "readlink", flaky_readlink)
    count = b1.count_worker_established_to_serve_port(
        42, serve_port, tcp_path=tcp, tcp6_path=tcp6, fd_dir=fd_dir
    )
    assert count == 1


def test_per_worker_census_returns_unavailable_on_malformed_proc(tmp_path):
    tcp = tmp_path / "tcp"
    tcp6 = tmp_path / "tcp6"
    tcp.write_text("broken\n", encoding="utf-8")
    tcp6.write_text("  sl  local rem st\n", encoding="utf-8")
    fd_dir = tmp_path / "fd"
    fd_dir.mkdir()
    assert (
        b1.count_worker_established_to_serve_port(
            1, 8080, tcp_path=tcp, tcp6_path=tcp6, fd_dir=fd_dir
        )
        == b1.UNAVAILABLE
    )


def test_per_worker_census_returns_unavailable_on_unreadable_proc(tmp_path):
    missing = tmp_path / "nonexistent_tcp"
    good = tmp_path / "tcp6"
    good.write_text("  sl  local rem st\n", encoding="utf-8")
    fd_dir = tmp_path / "fd"
    fd_dir.mkdir()
    assert (
        b1.count_worker_established_to_serve_port(
            1, 8080, tcp_path=missing, tcp6_path=good, fd_dir=fd_dir
        )
        == b1.UNAVAILABLE
    )


def test_serialize_worker_established_peaks_preserves_pid_order():
    peaks = [3, 1, 7]
    assert b1.serialize_worker_established_peaks(peaks) == "3+1+7"
    assert b1.serialize_worker_established_peaks([1, b1.UNAVAILABLE]) == b1.UNAVAILABLE


def test_worker_established_peaks_from_sample_matrix():
    samples = [
        [1, 4, 2],
        [3, 4, 5],
        [2, 6, 5],
    ]
    peaks = b1.worker_established_peaks_from_samples(samples)
    assert peaks == [3, 6, 5]
    assert b1.peak_worker_established_from_peaks(peaks) == 6
    assert b1.peak_worker_established_from_peaks([b1.UNAVAILABLE]) == b1.UNAVAILABLE
    assert (
        b1.peak_worker_established_from_peaks([1, b1.UNAVAILABLE])
        == b1.UNAVAILABLE
    )


def test_per_worker_census_discriminating_pair_against_live_sockets():
    """Two children: one holds N accepted loopback sockets, one holds none."""
    n_sockets = 3
    src = textwrap.dedent(
        """
        import socket, sys, time
        port = int(sys.argv[1])
        role = sys.argv[2]
        n = int(sys.argv[3])
        if role == "acceptor":
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(n)
            sys.stdout.write("bound\\n")
            sys.stdout.flush()
            held = []
            for _ in range(n):
                conn, _addr = listener.accept()
                held.append(conn)
            sys.stdout.write("ready\\n")
            sys.stdout.flush()
            time.sleep(10)
        else:
            time.sleep(10)
        """
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    acceptor = subprocess.Popen(
        [sys.executable, "-c", src, str(port), "acceptor", str(n_sockets)],
        stdout=subprocess.PIPE,
        text=True,
    )
    empty = subprocess.Popen(
        [sys.executable, "-c", src, str(port), "empty", "0"],
        stdout=subprocess.PIPE,
        text=True,
    )
    clients: list[socket.socket] = []
    try:
        assert acceptor.stdout.readline().strip() == "bound"
        clients = []
        for _ in range(n_sockets):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", port))
            clients.append(s)
        assert acceptor.stdout.readline().strip() == "ready"
        time.sleep(0.1)
        holder_count = b1.count_worker_established_to_serve_port(acceptor.pid, port)
        empty_count = b1.count_worker_established_to_serve_port(empty.pid, port)
        assert isinstance(holder_count, int) and holder_count == n_sockets, holder_count
        assert empty_count == 0, empty_count
    finally:
        for s in clients:
            s.close()
        acceptor.send_signal(signal.SIGTERM)
        empty.send_signal(signal.SIGTERM)
        acceptor.wait(timeout=5)
        empty.wait(timeout=5)


# ---------------------------------------------------------------------------
# UT-IG-17 — pool census reader (no product server)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pool_census_reader_opposite_directions_and_reducers():
    """UT-IG-17 / FP-B1DF-5: sockets vs queued tasks, seen-union, fail-open."""
    pool_size = 2
    hold = asyncio.Event()
    release = asyncio.Event()

    async def handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await reader.read(65536)
        hold.set()
        await release.wait()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    url = f"http://{host}:{port}/"
    client = b1.build_httpx_client(max_connections=pool_size)
    try:
        # A readable empty pool is numeric zero, never unavailable.
        assert b1.read_pool_census_sample(client) == (0, 0, set(), 0)

        slow = [
            asyncio.create_task(client.post(url, content=b"slow", headers={}))
            for _ in range(pool_size)
        ]
        deadline = time.time() + 5.0
        while time.time() < deadline:
            conn, queued, _seen, _requests = b1.read_pool_census_sample(client)
            if isinstance(conn, int) and conn >= pool_size:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("pool never reached held-connection plateau")

        conn, queued, seen, requests_n = b1.read_pool_census_sample(client)
        assert conn == pool_size
        assert requests_n == pool_size
        assert queued == 0
        assert seen is not None and len(seen) == pool_size
        assert requests_n - queued <= conn

        extra_dispatch = 3
        extra = [
            asyncio.create_task(client.post(url, content=b"extra", headers={}))
            for _ in range(extra_dispatch)
        ]
        deadline = time.time() + 5.0
        while time.time() < deadline:
            conn_after, queued_after, _, requests_after = b1.read_pool_census_sample(client)
            if isinstance(queued_after, int) and queued_after == extra_dispatch:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError(
                f"queued never reached {extra_dispatch} (last={queued_after!r})"
            )
        # Held sockets and queued tasks move in opposite directions on the
        # same tick: connections stay at the cap while the ledger grows.
        assert conn_after == pool_size
        assert queued_after == extra_dispatch
        assert requests_after == pool_size + extra_dispatch
        assert requests_after - queued_after <= conn_after

        release.set()
        await asyncio.gather(*slow, *extra, return_exceptions=True)
        hold.clear()
        release.clear()
        await client.aclose()

        close_hold = asyncio.Event()
        close_release = asyncio.Event()

        async def close_handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await reader.read(65536)
            close_hold.set()
            await close_release.wait()
            writer.write(
                b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

        close_server = await asyncio.start_server(close_handler, "127.0.0.1", 0)
        close_host, close_port = close_server.sockets[0].getsockname()[:2]
        close_url = f"http://{close_host}:{close_port}/"
        churn_client = b1.build_httpx_client(max_connections=1)
        identity_sets: list[set[int]] = []
        try:
            for payload in (b"churn-a", b"churn-b"):
                close_hold.clear()
                close_release.clear()
                task = asyncio.create_task(
                    churn_client.post(close_url, content=payload, headers={})
                )
                deadline = time.time() + 5.0
                while time.time() < deadline:
                    _c, _q, seen_i, _r = b1.read_pool_census_sample(churn_client)
                    if seen_i:
                        identity_sets.append(set(seen_i))
                        break
                    await asyncio.sleep(0.01)
                else:
                    raise AssertionError("no connection identity sampled")
                close_release.set()
                await task
                await asyncio.sleep(0.05)

            seen_total = b1.pool_connections_seen_from_identity_sets(identity_sets)
            assert seen_total == 2
            # Stable monotonic ids: the union cannot be deceived by an object
            # address that a later connection happens to reuse.
            assert identity_sets[0].isdisjoint(identity_sets[1])
        finally:
            close_release.set()
            await churn_client.aclose()
            close_server.close()
            await close_server.wait_closed()

        # Fail-open: a client with no snapshot support, a snapshot object that
        # is missing fields, and a snapshot call that raises all degrade to
        # unavailable rather than fabricating zeros.
        unavailable = (b1.UNAVAILABLE, b1.UNAVAILABLE, None, b1.UNAVAILABLE)

        class _NoSnapshot:
            pass

        class _MalformedSnapshot:
            def pool_snapshot(self):
                return object()

        class _RaisingSnapshot:
            def pool_snapshot(self):
                raise TypeError("no snapshot support")

        for broken in (_NoSnapshot(), _MalformedSnapshot(), _RaisingSnapshot()):
            assert b1.read_pool_census_sample(broken) == unavailable
        assert b1.pool_census_from_snapshot(None) == unavailable
        assert b1.pool_census_from_snapshot(object()) == unavailable

        # Same-sample arithmetic: one snapshot yields both the four-tuple and
        # the assigned-identity list, so R - Q <= C is read on one tick.
        from types import SimpleNamespace

        def snapshot(c, q, r, assigned):
            return SimpleNamespace(
                held_connections=c, queued_requests=q, requests=r,
                connection_identities=frozenset(assigned),
                assigned_connection_identities=tuple(assigned),
            )

        samples = []
        for held, queued_n, requests_c, assigned in (
            (2, 0, 2, (7, 9)),
            (2, 1, 3, (7, 9)),
        ):
            c, q, ids, r = b1.pool_census_from_snapshot(
                snapshot(held, queued_n, requests_c, assigned)
            )
            assert r - q <= c
            assert ids == set(assigned)
            samples.append((c, q, r))
        assert samples == [(2, 0, 2), (2, 1, 3)]
        assert b1.peak_pool_metric_from_samples([b1.UNAVAILABLE, 3]) == 3
        assert b1.peak_pool_metric_from_samples([b1.UNAVAILABLE]) == b1.UNAVAILABLE
        assert b1.pool_connections_seen_from_identity_sets([]) == b1.UNAVAILABLE
    finally:
        release.set()
        if not client.is_closed:
            await client.aclose()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_open_loop_rejects_duplicate_event_ids_across_phases():
    """C2: warmup/prologue/measured must be disjoint — a reuse-aware stub fails."""

    class DupAwareTransport:
        def __init__(self):
            self.seen: set[bytes] = set()
            self.calls = 0
            self.unique = 0
            self.measured_errors = 0
            self.measured_served = 0

        async def post(self, url, *, content, headers):
            self.calls += 1
            if content in self.seen:
                # Unique event_id violated → gateway would reject / error.
                return 409, b'{"status":"error","reason":"duplicate"}', None
            self.seen.add(content)
            self.unique += 1
            return 202, b'{"investigation_id":"x"}', None

    transport = DupAwareTransport()
    # Old bug: same three payloads reused for warmup, prologue and measurement.
    shared = [(b'{"event_id":"same"}', {"Content-Type": "application/json"}) for _ in range(3)]
    # Correct API: measured-only list with optional disjoint prologue/warmup.
    warmup = (b'{"event_id":"warm"}', {"Content-Type": "application/json"})
    prologue = [
        (b'{"event_id":"pro0"}', {"Content-Type": "application/json"}),
        (b'{"event_id":"pro1"}', {"Content-Type": "application/json"}),
    ]
    measured = [
        (f'{{"event_id":"m{i}"}}'.encode(), {"Content-Type": "application/json"})
        for i in range(3)
    ]
    result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=measured,
        rate=100,
        transport=transport,
        max_in_flight=10,
        warmup=warmup,
        prologue=prologue,
        include_sync_warmup=True,
    )
    assert result.errors == 0
    assert result.served == 3
    assert transport.unique == 1 + 2 + 3  # warmup + prologue + measured
    assert transport.calls == 6



# ---------------------------------------------------------------------------
# Reference burst fixture
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _sign(body: bytes) -> str:
    return hmac.new(HMAC_SECRET.encode(), body, hashlib.sha256).hexdigest()


def _build_requests(count: int) -> list[tuple[bytes, dict[str, str]]]:
    out = []
    for i in range(count):
        payload = {
            "source": "grafana-b1",
            "platform_key": PLATFORM_KEY,
            "error_summary": f"burst-{i % 50}",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "event_id": str(uuid.uuid4()),
        }
        raw = json.dumps(payload).encode()
        out.append(
            (
                raw,
                {
                    "Content-Type": "application/json",
                    "X-Signature": _sign(raw),
                },
            )
        )
    return out


def _host_fingerprint() -> dict[str, str | int]:
    cpus = os.cpu_count() or 0
    model = "unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                model = " ".join(line.split(":", 1)[1].split())
                break
    except OSError:
        pass
    image = "unknown"
    for path, prefix in (
        (Path("/imagegeneration/imagedata.json"), "imagedata"),
        (Path("/etc/os-release"), "os-release"),
    ):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
            image = f"{prefix}:{digest}"
            break
    return {"cpus": cpus, "cpu_model": model, "image": image}


def _b1_gateway_warning_count(log_path: Path, prefix_bytes: int) -> int:
    """Count complete warning lines only in the saved spawn-to-window prefix."""
    count = 0
    pending = b""
    with log_path.open("rb") as reader:
        remaining = prefix_bytes
        while remaining:
            chunk = reader.read(min(65536, remaining))
            if not chunk:
                raise RuntimeError(f"gateway log shortened before snapshot read: {log_path}")
            remaining -= len(chunk)
            lines = (pending + chunk).split(b"\n")
            pending = lines.pop()
            for line in lines:
                if re.fullmatch(r"WARNING:\s+Exceeded concurrency limit\.",
                                line.decode("utf-8", errors="replace").rstrip("\r\n")):
                    count += 1
    return count


def _b1_gateway_log_tail(log_path: Path) -> str:
    tail = ""
    with log_path.open(encoding="utf-8", errors="replace", newline="") as reader:
        while chunk := reader.read(65536):
            tail = (tail + chunk)[-2000:]
    return tail


def _b1_gateway_group_alive(pgid: int) -> bool:
    """Linux reference harness: zombies have exited and cannot retain the sink."""
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
        except FileNotFoundError:
            continue  # Process exited during enumeration.
        if int(fields[2]) == pgid and fields[0] not in {"Z", "X"}:
            return True
    return False


def _b1_gateway_signal_group(pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        pass


@contextmanager
def _b1_gateway_process(argv, *, env, log_path: Path):
    """Own the regular-file sink and the entire isolated gateway process group."""
    with log_path.open("xb") as writer:
        proc = subprocess.Popen(
            argv, env=env, stdout=writer, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            try:
                yield proc
            finally:
                if proc.poll() is None or _b1_gateway_group_alive(proc.pid):
                    _b1_gateway_signal_group(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    _b1_gateway_signal_group(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=10)
                # A supervisor may exit while an inherited-output worker survives.
                if _b1_gateway_group_alive(proc.pid):
                    _b1_gateway_signal_group(proc.pid, signal.SIGKILL)
                    deadline = time.monotonic() + 10
                    while _b1_gateway_group_alive(proc.pid):
                        if time.monotonic() >= deadline:
                            raise RuntimeError(f"gateway process group {proc.pid} survived teardown")
                        time.sleep(0.01)
                if proc.poll() is None:
                    raise RuntimeError(f"gateway child {proc.pid} was not reaped")
        except Exception as exc:
            tail = _b1_gateway_log_tail(log_path)
            raise RuntimeError(f"{exc}; gateway log={log_path}; tail:\n{tail}") from exc


# ---------------------------------------------------------------------------
# GC-1 — sibling-container orchestration and the effective-placement probe
# ---------------------------------------------------------------------------


def _read_launch_contract(path: Path = B1_LAUNCH_CONTRACT) -> object:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise B1PlacementError(
            f"no closed launch contract at {path}; the b1/b1_product "
            f"shell target writes it before starting the driver"
        ) from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise B1PlacementError(f"launch contract at {path} is not JSON: {exc}") from exc


def _resolve_driver_container(client, declaration: B1PlacementDeclaration):
    """Identify this driver by its two labels -- never by hostname.

    Hostname is not identity: with ``--network host`` it is the *host's* name,
    and under any other mode it is a truncated container id that no label
    guarantees belongs to this run. The unique two-label match plus the exact
    derived name is what ties the running process to the contract it read.
    """
    matches = client.containers.list(
        filters={"label": [declaration.run_label, declaration.role_label("driver")]}
    )
    if len(matches) != 1:
        raise B1PlacementError(
            f"expected exactly one container labelled {declaration.run_label} + "
            f"{declaration.role_label('driver')}; found {[c.name for c in matches]}"
        )
    driver = matches[0]
    if driver.name != declaration.driver_name:
        raise B1PlacementError(
            f"driver container is named {driver.name!r}, contract derives "
            f"{declaration.driver_name!r}"
        )
    labels = dict(getattr(driver, "labels", None) or {})
    if labels.get(B1_RUN_LABEL_KEY) != declaration.run_id:
        raise B1PlacementError(
            f"driver label {B1_RUN_LABEL_KEY}={labels.get(B1_RUN_LABEL_KEY)!r} disagrees "
            f"with the contract runId {declaration.run_id!r}"
        )
    return driver


def _driver_mount_source(driver, destination: str) -> str:
    """The host source of one driver mount, read back from Docker inspect.

    The siblings are built from the driver's own inspected image id and mount
    sources, so no caller-provided image or host path can enter the topology.
    """
    mounts = (getattr(driver, "attrs", None) or {}).get("Mounts") or []
    sources = [m.get("Source") for m in mounts if m.get("Destination") == destination]
    if len(sources) != 1 or not sources[0]:
        raise B1PlacementError(
            f"driver container has {len(sources)} mount(s) at {destination}; expected exactly one"
        )
    return sources[0]


def _exec_text(container, argv: list[str]) -> str:
    """Run a reader inside a sibling container and return its stdout."""
    wrapped = container.get_wrapped_container() if hasattr(container, "get_wrapped_container") else container
    code, output = wrapped.exec_run(argv)
    if code != 0:
        raise B1PlacementError(
            f"{' '.join(argv)} in {wrapped.name} exited {code}: "
            f"{output.decode('utf-8', 'replace').strip()}"
        )
    return output.decode("utf-8", "replace")


def _proc_allowed_cpus(pid: int) -> frozenset[int]:
    """Both affinity views for one pid; they must agree after normalization."""
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except OSError as exc:
        raise B1PlacementError(f"cannot read /proc/{pid}/status: {exc}") from exc
    listed = [ln for ln in status.splitlines() if ln.startswith("Cpus_allowed_list:")]
    if len(listed) != 1:
        raise B1PlacementError(f"/proc/{pid}/status carries {len(listed)} Cpus_allowed_list lines")
    from_status = b1.parse_cpu_list(listed[0].split(":", 1)[1].strip())
    try:
        from_sched = frozenset(os.sched_getaffinity(pid))
    except OSError as exc:
        raise B1PlacementError(f"cannot sched_getaffinity({pid}): {exc}") from exc
    if from_status != from_sched:
        raise B1PlacementError(
            f"pid {pid} affinity views disagree: /proc says "
            f"{b1.format_cpu_list(from_status)}, sched_getaffinity says "
            f"{b1.format_cpu_list(from_sched)}"
        )
    return from_status


def _proc_cgroup_id(pid: int) -> str:
    try:
        text = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8")
    except OSError as exc:
        raise B1PlacementError(f"cannot read /proc/{pid}/cgroup: {exc}") from exc
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0":
            return parts[2]
    raise B1PlacementError(f"/proc/{pid}/cgroup carries no unified (0::) entry")


def _host_cpu_ids() -> frozenset[int]:
    """The host-visible logical CPU inventory, from the host /proc/stat.

    Deliberately not ``sched_getaffinity(0)``: the driver itself now runs under
    ``taskset``, so its own affinity is one CPU and would make every role look
    out of range.
    """
    text = Path("/proc/stat").read_text(encoding="utf-8")
    return frozenset(b1.parse_proc_stat_busy_usec(text, clock_ticks=os.sysconf("SC_CLK_TCK")))


def _gateway_set_busy_usec(allowed: frozenset[int]) -> dict[int, int]:
    text = Path("/proc/stat").read_text(encoding="utf-8")
    per_cpu = b1.parse_proc_stat_busy_usec(text, clock_ticks=os.sysconf("SC_CLK_TCK"))
    missing = sorted(set(allowed) - set(per_cpu))
    if missing:
        raise b1.B1PlacementParseError(f"/proc/stat carries no counters for gateway CPUs {missing}")
    return {cpu: per_cpu[cpu] for cpu in sorted(allowed)}


# ---------------------------------------------------------------------------
# GC-2 (FP-GC2-5) — reported-only host diagnostics.
#
# These three readers exist so the live read and its deterministic tests run
# the same code. Each returns its canonical, unencoded string or raises; only
# the `_try_diagnostic` boundary turns a failure into `unavailable`, and a
# partial map is never emitted as if it were complete. Nothing here decides a
# placement or a performance verdict.
# ---------------------------------------------------------------------------

# Percent-encoding safe set: everything else, commas and spaces included,
# becomes %XX with uppercase hex so the B1 `name=value` grammar stays
# unambiguous and the value still round-trips exactly.
B1_DIAGNOSTIC_SAFE_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:+"
)
# The kernel spells the per-CPU directory `cpu<id>`; §3.6's `<id>` names that
# directory. Reading `<root>/<id>/...` finds nothing on any Linux host, so the
# field would be permanently `unavailable` -- an honest miss that reports
# nothing (observed on the pre-change local CI-scale run).
B1_CPU_DIRECTORY_PREFIX = "cpu"
B1_THREAD_SIBLINGS_RELATIVE = "topology/thread_siblings_list"
B1_SPECTRE_V2_FILE = "spectre_v2"


def _percent_encode_diagnostic(value: str) -> str:
    """Percent-encode one free-form diagnostic value (uppercase hex)."""
    if not isinstance(value, str):
        raise b1.B1PlacementParseError(f"diagnostic value is not a string: {value!r}")
    out: list[str] = []
    for byte in value.encode("utf-8"):
        char = chr(byte)
        out.append(char if char in B1_DIAGNOSTIC_SAFE_CHARACTERS else f"%{byte:02X}")
    return "".join(out)


def _read_gateway_thread_siblings(
    cpu_ids: frozenset[int], *, cpu_root: Path = Path("/sys/devices/system/cpu")
) -> str:
    """`<cpu>:<siblings>` for every gateway CPU, CPU-id sorted, `+`-joined.

    Each kernel list is canonicalized through the existing CPU-list
    parser/formatter, so a value the kernel could not have emitted raises
    rather than reaching the record.
    """
    ordered = sorted(cpu_ids)
    if not ordered:
        raise b1.B1PlacementParseError("no gateway CPU to read thread siblings for")
    parts: list[str] = []
    for cpu in ordered:
        raw = (
            cpu_root
            / f"{B1_CPU_DIRECTORY_PREFIX}{cpu}"
            / B1_THREAD_SIBLINGS_RELATIVE
        ).read_text(encoding="utf-8")
        parts.append(f"{cpu}:{b1.format_cpu_list(b1.parse_cpu_list(raw))}")
    return "+".join(parts)


def _read_reference_sibling_groups(declaration) -> "dict[int, frozenset[int]]":
    """GC-3 FP-GC3-5: the kernel sibling list for every reference CPU.

    Deliberately NOT routed through `_try_diagnostic`: under schema 3 this is
    gating evidence, so an unreadable or non-canonical sysfs value raises and
    stops the run instead of arriving as `unavailable`. Schema-2 contracts make
    no topology claim and get an empty reading.
    """
    if not declaration.carries_topology:
        return {}
    try:
        return probe.sibling_groups(declaration.reference_cpus)
    except probe.TopologyProbeError as exc:
        raise B1PlacementError(
            f"{declaration.profile}: cannot read thread_siblings_list for the reference set "
            f"{b1.format_cpu_list(declaration.reference_cpus)}: {exc}"
        ) from exc


def _read_spectre_v2(
    *, vulnerabilities_root: Path = Path("/sys/devices/system/cpu/vulnerabilities")
) -> str:
    """The host's `spectre_v2` mitigation string, whitespace-normalized."""
    raw = (vulnerabilities_root / B1_SPECTRE_V2_FILE).read_text(encoding="utf-8")
    collapsed = " ".join(raw.split())
    if not collapsed:
        raise b1.B1PlacementParseError("spectre_v2 is empty")
    return collapsed


def _try_diagnostic(label: str, notes: list[str], reader):
    """Attempt one reported-only diagnostic; never let it fail the run."""
    try:
        return reader()
    except Exception as exc:  # noqa: BLE001 — diagnostics must never gate
        notes.append(f"{label}: {type(exc).__name__}: {exc}")
        return None


def _read_cpu_files(container=None):
    """``(cpu.max, cpu.stat)`` for a sibling container, or for the driver itself."""
    if container is None:
        return (
            Path("/sys/fs/cgroup/cpu.max").read_text(encoding="utf-8"),
            Path("/sys/fs/cgroup/cpu.stat").read_text(encoding="utf-8"),
        )
    return (
        _exec_text(container, ["cat", "/sys/fs/cgroup/cpu.max"]),
        _exec_text(container, ["cat", "/sys/fs/cgroup/cpu.stat"]),
    )


# ---------------------------------------------------------------------------
# GC-4 (FP-GC4-5) — measured-window PostgreSQL cost and wait diagnostics.
#
# Test-only, reported-only, and symmetric: the same sampler runs in a control
# and in a candidate record, so its own small PostgreSQL cost is included in
# both rather than subtracted by estimate. It touches no product engine or
# pool; it opens its OWN autocommit connection, reads `pg_stat_activity`, and
# nothing it produces is a B1 verdict, a GC-3 selector input or a sizing value.
# ---------------------------------------------------------------------------

#: The six reported-only cost fields, in the order the fingerprint carries
#: them -- after the two existing lateness-leg fields, never before a gating one.
B1_POSTGRES_COST_FIELDS = (
    "postgres_cpu_us_per_req",
    "postgres_wait_scheduled",
    "postgres_wait_completed",
    "postgres_wait_failed",
    "postgres_wait_observations",
    "postgres_wait_events_pct",
)
B1_WAIT_SAMPLER_APPLICATION_NAME = "gc4-wait-sampler"
B1_WAIT_SAMPLE_INTERVAL_S = 0.05
B1_WAIT_ACTIVE_CPU_KEY = "active/CPU/running"
B1_WAIT_NONE = "none"
B1_WAIT_JOIN_TIMEOUT_S = 10.0
# Diagnostic-integrity rule for ONE wait sample. It decides only whether the
# five wait fields carry readings or `unavailable` plus a note; it is not a bar,
# not a verdict and never fatal on any route. The former absolute floor of 500
# completed samples is retired: valid observed counts ranged from 486 to 576
# because each `pg_stat_activity` query itself took 4-12 ms, so an absolute
# floor rejected honest records for a reason unrelated to their integrity.
B1_WAIT_MIN_COMPLETION_RATIO = 0.90
# `:` and `+` are this histogram's own separators, so they are NOT safe inside
# a key. Derived from the existing diagnostic set rather than re-typed.
B1_WAIT_KEY_SAFE_CHARACTERS = B1_DIAGNOSTIC_SAFE_CHARACTERS - frozenset(":+")
# Non-idle client backends of the measured database, grouped exactly as §3.6
# specifies, with this sampler's own backend excluded by pid AND by name.
#
# GC-5 (FP-GC5-7): the sampler's own connection moved to a MAINTENANCE
# database, so `current_database()` is no longer the measured one and the
# target is named explicitly instead. The application-name exclusion is
# retained exactly as GC-4 wrote it, and every GC-4 field keeps its meaning:
# this still counts non-idle client backends of the measured database.
B1_WAIT_SAMPLE_SQL = (
    "SELECT state, wait_event_type, wait_event, count(*) AS backends "
    "FROM pg_stat_activity "
    "WHERE datname = %(target_database)s "
    "AND backend_type = 'client backend' "
    "AND pid <> pg_backend_pid() "
    "AND coalesce(application_name, '') <> %(application_name)s "
    "AND state IS NOT NULL AND state <> 'idle' "
    "GROUP BY 1, 2, 3"
)


def classify_postgres_wait(state, wait_event_type, wait_event) -> str:
    """One canonical histogram key for one observed backend group.

    An active backend with no wait event is on CPU; every other observation
    keeps its own `<state>/<wait_event_type>/<wait_event>` identity. A row
    without a state is a malformed sample and raises rather than being
    silently folded into the CPU bucket.
    """
    if not state:
        raise b1.B1PlacementParseError(
            f"wait sample carries no state: {(state, wait_event_type, wait_event)!r}"
        )
    if state == "active" and wait_event_type is None and wait_event is None:
        return B1_WAIT_ACTIVE_CPU_KEY
    return (
        f"{state}/{wait_event_type or B1_WAIT_NONE}/{wait_event or B1_WAIT_NONE}"
    )


def _percent_encode_wait_key(value: str) -> str:
    """Percent-encode one histogram key (uppercase hex), separators included."""
    if not isinstance(value, str):
        raise b1.B1PlacementParseError(f"wait histogram key is not a string: {value!r}")
    out: list[str] = []
    for byte in value.encode("utf-8"):
        char = chr(byte)
        out.append(char if char in B1_WAIT_KEY_SAFE_CHARACTERS else f"%{byte:02X}")
    return "".join(out)


def serialize_postgres_wait_histogram(histogram) -> str:
    """Sorted, percent-encoded `key:count` pairs, `+`-joined; never a literal."""
    if not histogram:
        return DIAGNOSTIC_UNAVAILABLE
    parts: list[str] = []
    for key in sorted(histogram):
        count = histogram[key]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise b1.B1PlacementParseError(
                f"wait histogram count for {key!r} is not a count: {count!r}"
            )
        parts.append(f"{_percent_encode_wait_key(key)}:{count}")
    return "+".join(parts)


@dataclass(frozen=True)
class B1PostgresWaitSample:
    """One measured window's PostgreSQL wait observation. Reported-only."""

    scheduled: int
    completed: int
    failed: int
    observations: int
    histogram: "dict[str, int]"


class B1PostgresWaitSampler:
    """One thread, one connection, one stop event, for one measured window.

    `stop()` is idempotent and always does all four things in order: set the
    event, join the thread, verify it is no longer alive, close the connection.
    A thread that outlives its join is a defect and raises -- after the
    connection has been closed, so a stuck sampler never also leaks a backend.
    """

    def __init__(
        self,
        connect,
        *,
        target_database: str,
        interval_s: float = B1_WAIT_SAMPLE_INTERVAL_S,
        join_timeout_s: float = B1_WAIT_JOIN_TIMEOUT_S,
    ) -> None:
        self._connect = connect
        self._target_database = target_database
        self._interval_s = interval_s
        self._join_timeout_s = join_timeout_s
        self._stop_event = threading.Event()
        self._thread: "threading.Thread | None" = None
        self._connection = None
        self._started = False
        self._result: "B1PostgresWaitSample | None" = None
        self.scheduled = 0
        self.completed = 0
        self.failed = 0
        self.observations = 0
        self.histogram: "dict[str, int]" = {}

    @property
    def started(self) -> bool:
        return self._started

    def start(self) -> None:
        if self._started:
            raise B1PlacementError("the GC-4 wait sampler is already running")
        self._connection = self._connect()
        self._started = True
        self._thread = threading.Thread(
            target=self._run, name=B1_WAIT_SAMPLER_APPLICATION_NAME, daemon=True
        )
        self._thread.start()

    def _sample(self):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                B1_WAIT_SAMPLE_SQL,
                {
                    "application_name": B1_WAIT_SAMPLER_APPLICATION_NAME,
                    "target_database": self._target_database,
                },
            )
            return list(cursor.fetchall())
        finally:
            cursor.close()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self.scheduled += 1
            try:
                rows = self._sample()
            except Exception:  # noqa: BLE001 — a failed sample is recorded, never raised
                self.failed += 1
            else:
                for state, wait_event_type, wait_event, backends in rows:
                    key = classify_postgres_wait(state, wait_event_type, wait_event)
                    count = int(backends)
                    self.histogram[key] = self.histogram.get(key, 0) + count
                    self.observations += count
                self.completed += 1
            self._stop_event.wait(self._interval_s)

    def stop(self) -> "B1PostgresWaitSample | None":
        if self._result is not None or not self._started:
            return self._result
        self._stop_event.set()
        thread, self._thread = self._thread, None
        alive = False
        if thread is not None:
            thread.join(self._join_timeout_s)
            alive = thread.is_alive()
        connection, self._connection = self._connection, None
        if connection is not None:
            try:
                connection.close()
            except Exception:  # noqa: BLE001 — a diagnostic must never fail the run
                pass
        if alive:
            raise B1PlacementError(
                f"the GC-4 wait sampler thread is still alive "
                f"{self._join_timeout_s} s after its stop event"
            )
        self._result = B1PostgresWaitSample(
            scheduled=self.scheduled,
            completed=self.completed,
            failed=self.failed,
            observations=self.observations,
            histogram=dict(self.histogram),
        )
        return self._result

    def shutdown(self) -> None:
        """Teardown-safe stop: still sets, joins, verifies and closes, but a
        stuck thread is reported by `stop()`'s own raise at the seam that owns
        it, never by failing a fixture that has already emitted its record."""
        try:
            self.stop()
        except B1PlacementError:
            pass


def target_database_name(dsn: str) -> str:
    """The measured database's own name, read from the harness DSN."""
    from sqlalchemy.engine import make_url

    database = make_url(dsn).database
    if not database:
        raise B1PlacementError(f"the measured DSN names no database: {dsn!r}")
    return database


def maintenance_database_name(dsn: str) -> str:
    """A maintenance database that is NOT the measured one (FP-GC5-7).

    Every diagnostic connection of this harness lives here, so its own read
    transactions are counted against this database and can never inflate the
    measured database's `xact_commit`.
    """
    if target_database_name(dsn) == B1_MAINTENANCE_DATABASE:
        return B1_MAINTENANCE_DATABASE_ALTERNATE
    return B1_MAINTENANCE_DATABASE


def maintenance_dsn(dsn: str, application_name: str) -> str:
    """The same server, the maintenance database, one named application."""
    from sqlalchemy.engine import make_url

    url = (
        make_url(dsn)
        .set(drivername="postgresql", database=maintenance_database_name(dsn))
        .update_query_dict({"application_name": application_name})
    )
    return url.render_as_string(hide_password=False)


def _open_postgres_wait_connection(dsn: str):
    """One dedicated autocommit diagnostic connection, named for exclusion.

    GC-5: opened against the maintenance database rather than the measured
    one, so each polling query commits there instead of inflating the
    measured database's transaction count. The application name is unchanged
    and is still what the sample statement excludes.
    """
    import psycopg2

    connection = psycopg2.connect(
        maintenance_dsn(dsn, B1_WAIT_SAMPLER_APPLICATION_NAME)
    )
    connection.autocommit = True
    return connection


def _open_postgres_stats_connection(dsn: str):
    """The GC-5 stats reader's own autocommit maintenance connection."""
    import psycopg2

    connection = psycopg2.connect(
        maintenance_dsn(dsn, B1_STATS_READER_APPLICATION_NAME)
    )
    connection.autocommit = True
    return connection


def serialize_postgres_cost_fields(usage_usec, served, sample) -> str:
    """The six reported-only cost fields, in their pinned order.

    A missing PostgreSQL usage reading or a non-positive served count
    serializes `unavailable`, never a zero that would read like a measurement.
    """
    if (
        isinstance(usage_usec, (int, float))
        and not isinstance(usage_usec, bool)
        and isinstance(served, int)
        and not isinstance(served, bool)
        and served > 0
    ):
        cpu_per_req = f"{usage_usec / served:.3f}"
    else:
        cpu_per_req = DIAGNOSTIC_UNAVAILABLE
    if postgres_wait_sample_failure(sample) is not None:
        # Missing OR unusable: every wait field is `unavailable`, and the run's
        # diagnostic notes carry the reason with the raw counts. Never a zero,
        # which would read like a measurement.
        scheduled = completed = failed = observations = DIAGNOSTIC_UNAVAILABLE
        events = DIAGNOSTIC_UNAVAILABLE
    else:
        scheduled = str(sample.scheduled)
        completed = str(sample.completed)
        failed = str(sample.failed)
        observations = str(sample.observations)
        events = serialize_postgres_wait_histogram(sample.histogram)
    return (
        f"postgres_cpu_us_per_req={cpu_per_req},"
        f"postgres_wait_scheduled={scheduled},"
        f"postgres_wait_completed={completed},"
        f"postgres_wait_failed={failed},"
        f"postgres_wait_observations={observations},"
        f"postgres_wait_events_pct={events}"
    )


def postgres_wait_sample_failure(sample) -> "str | None":
    """Why this wait sample is not usable, or ``None`` when it is.

    Diagnostic integrity only. An unusable -- or absent -- sample publishes
    `unavailable` in all five wait fields plus this reason as a note, carrying
    whatever raw counts exist. It is NEVER fatal: it voids no product record
    and no GC-3 discovery arm, because a test-only sampler must not be able to
    destroy a 28-arm sweep's evidence.
    """
    if sample is None:
        return "no measured-window PostgreSQL wait sample was taken"
    counts = (
        f"scheduled={sample.scheduled} completed={sample.completed} "
        f"failed={sample.failed} observations={sample.observations}"
    )
    if sample.failed != 0:
        return f"{sample.failed} wait samples failed ({counts})"
    if sample.scheduled <= 0:
        return f"no wait sample was scheduled ({counts})"
    if sample.completed < B1_WAIT_MIN_COMPLETION_RATIO * sample.scheduled:
        return (
            f"only {sample.completed}/{sample.scheduled} wait samples completed, "
            f"below {B1_WAIT_MIN_COMPLETION_RATIO:.0%} ({counts})"
        )
    if not sample.histogram:
        return f"the wait histogram is empty ({counts})"
    return None


def postgres_cost_record_failures(run: dict) -> list[str]:
    """Are this record's HARNESS-OWNED cost operands present and numeric?

    Exactly three things, all produced by the workload/placement harness
    itself: a positive served count, a positive PostgreSQL CPU reading, and
    both finite three-lateness-leg tuples.

    Deliberately NOT here: the wait sampler. A missing, failed, sub-90%-complete
    or empty sample selects `unavailable` wait fields plus a note and is never
    fatal (`postgres_wait_sample_failure`). Also not here: load accounting and
    any performance comparison -- on the discovery route those are recorded
    data owned by `build_probe_arm_record` and GC-3's verdicts, and gating them
    here would stop the sweep at the first expected miss.
    """
    fails: list[str] = []
    result = run.get("result")
    served = getattr(result, "served", None)
    usage = run.get("postgres_usage_usec")
    if isinstance(served, bool) or not isinstance(served, int) or served <= 0:
        fails.append(f"served is not a positive count: {served!r}")
    if (
        isinstance(usage, bool)
        or not isinstance(usage, (int, float))
        or usage <= 0
    ):
        fails.append(f"postgres_usage_usec is not a positive number: {usage!r}")
    for field in ("p99_leg_split", "leg_p99s"):
        legs = run.get(field)
        if (
            not isinstance(legs, tuple)
            or len(legs) != 3
            or not all(isinstance(v, float) and math.isfinite(v) for v in legs)
        ):
            fails.append(f"{field} is not a finite three-leg value: {legs!r}")
    return fails


def assert_complete_postgres_cost_record(run: dict) -> None:
    """FP-GC4-5: refuse a record whose harness-owned cost operands are missing.

    Wait-sampler availability is explicitly outside this contract.
    """
    fails = postgres_cost_record_failures(run)
    if fails:
        raise B1PlacementError(
            "incomplete GC-4 cost record: " + "; ".join(fails)
        )


# ---------------------------------------------------------------------------
# GC-5 (FP-GC5-7/8) — measured-window transaction and WAL counters.
#
# The quantity the commit coalescer governs is how many durable database
# transactions one served request costs. It is read from `pg_stat_database`
# for the measured database and `pg_stat_wal` for the cluster, through a
# connection to a DIFFERENT (maintenance) database: a reader connected to the
# measured database would commit its own read transactions there and inflate
# exactly the counter it is reporting. Only `postgres_xact_commits_per_served`
# is an outcome; every other field here is recorded context.
# ---------------------------------------------------------------------------

#: The eight fields, in the order the fingerprint carries them -- after the six
#: GC-4 cost fields, never before a gating one.
B1_POSTGRES_COMMIT_FIELDS = (
    "postgres_xact_commit_delta",
    "postgres_xact_rollback_delta",
    "postgres_xact_commits_per_served",
    "postgres_wal_records_delta",
    "postgres_wal_bytes_delta",
    "postgres_wal_write_delta",
    "postgres_wal_sync_delta",
    "postgres_wal_syncs_per_served",
)
#: FP-GC5-7's one quantitative bar: committed database transactions per served
#: request on a qualifying product-shaped record. The pre-GC-5 shape is one
#: transaction per served request; a perfect group of eight would approach
#: 0.125 on the hit population. Not tuned from a post-change result.
B1_COMMIT_SHAPE_MAX_COMMITS_PER_SERVED = 0.60
B1_MAINTENANCE_DATABASE = "postgres"
B1_MAINTENANCE_DATABASE_ALTERNATE = "template1"
B1_STATS_READER_APPLICATION_NAME = "gc5-stats-reader"
#: PostgreSQL publishes cumulative statistics from each backend at an interval
#: of its own; this is the floor before the first read, not a tuning knob.
B1_STATS_PUBLICATION_WAIT_S = 1.1
B1_STATS_STABLE_INTERVAL_S = 0.1
B1_STATS_STABLE_TIMEOUT_S = 5.0
B1_DATABASE_STATS_SQL = (
    "SELECT d.oid, d.datname, s.xact_commit, s.xact_rollback, s.stats_reset "
    "FROM pg_database d JOIN pg_stat_database s ON s.datid = d.oid "
    "WHERE d.datname = %(target_database)s"
)
B1_WAL_STATS_SQL = (
    "SELECT wal_records, wal_bytes, wal_write, wal_sync, stats_reset FROM pg_stat_wal"
)


@dataclass(frozen=True)
class B1PostgresCommitSnapshot:
    """One end of the measured window's transaction/WAL counters."""

    database_name: str
    database_oid: int
    xact_commit: int
    xact_rollback: int
    database_stats_reset: str
    wal_records: int
    wal_bytes: int
    wal_write: int
    wal_sync: int
    wal_stats_reset: str


class B1PostgresStatsReader:
    """One autocommit maintenance connection, for one measured window.

    It reads the measured database's row by name and the cluster-wide WAL row;
    its own transactions belong to the maintenance database, so they cannot
    enter either delta it reports.
    """

    def __init__(self, connect, *, target_database: str, sleep=time.sleep,
                 monotonic=time.monotonic) -> None:
        self._connect = connect
        self._target_database = target_database
        self._sleep = sleep
        self._monotonic = monotonic
        self._connection = None

    @property
    def target_database(self) -> str:
        return self._target_database

    def _cursor_rows(self, statement, parameters=None):
        if self._connection is None:
            self._connection = self._connect()
        cursor = self._connection.cursor()
        try:
            cursor.execute(statement, parameters)
            return list(cursor.fetchall())
        finally:
            cursor.close()

    def _database_row(self):
        rows = self._cursor_rows(
            B1_DATABASE_STATS_SQL, {"target_database": self._target_database}
        )
        if len(rows) != 1:
            raise B1PlacementError(
                f"pg_stat_database has {len(rows)} rows for "
                f"{self._target_database!r}; exactly one is required"
            )
        return rows[0]

    def read_xact_commit(self) -> int:
        return int(self._database_row()[2])

    def snapshot(self) -> B1PostgresCommitSnapshot:
        """Both counter sets, read through one maintenance connection."""
        oid, datname, xact_commit, xact_rollback, database_reset = self._database_row()
        wal_rows = self._cursor_rows(B1_WAL_STATS_SQL)
        if len(wal_rows) != 1:
            raise B1PlacementError(
                f"pg_stat_wal has {len(wal_rows)} rows; exactly one is required"
            )
        wal_records, wal_bytes, wal_write, wal_sync, wal_reset = wal_rows[0]
        return B1PostgresCommitSnapshot(
            database_name=str(datname),
            database_oid=int(oid),
            xact_commit=int(xact_commit),
            xact_rollback=int(xact_rollback),
            database_stats_reset=str(database_reset),
            wal_records=int(wal_records),
            wal_bytes=int(wal_bytes),
            wal_write=int(wal_write),
            wal_sync=int(wal_sync),
            wal_stats_reset=str(wal_reset),
        )

    def wait_until_published(self) -> int:
        """Wait for publication, then for two equal readings 100 ms apart."""
        self._sleep(B1_STATS_PUBLICATION_WAIT_S)
        deadline = self._monotonic() + B1_STATS_STABLE_TIMEOUT_S
        previous = self.read_xact_commit()
        while True:
            self._sleep(B1_STATS_STABLE_INTERVAL_S)
            current = self.read_xact_commit()
            if current == previous:
                return current
            previous = current
            if self._monotonic() >= deadline:
                raise B1PlacementError(
                    f"the measured database's xact_commit did not settle within "
                    f"{B1_STATS_STABLE_TIMEOUT_S} s (last {current})"
                )

    def published_snapshot(self) -> B1PostgresCommitSnapshot:
        """The post-window end: publication wait, stability, then one read."""
        self.wait_until_published()
        return self.snapshot()

    def close(self) -> None:
        connection, self._connection = self._connection, None
        if connection is not None:
            try:
                connection.close()
            except Exception:  # noqa: BLE001 — a diagnostic must never fail the run
                pass


def postgres_commit_snapshot_failure(before, after, served) -> "str | None":
    """Why this window's transaction counters are unusable, or ``None``.

    Counter reset, unavailable, negative, unstable or cross-database
    observations cannot satisfy FP-GC5-7, and they are never repaired into a
    zero: the fields serialize `unavailable` and the record carries the reason.
    """
    if before is None or after is None:
        return "no measured-window PostgreSQL transaction snapshot was taken"
    if (before.database_name, before.database_oid) != (
        after.database_name,
        after.database_oid,
    ):
        return (
            f"the measured database changed identity between snapshots: "
            f"{before.database_name}/{before.database_oid} -> "
            f"{after.database_name}/{after.database_oid}"
        )
    if before.database_stats_reset != after.database_stats_reset:
        return (
            f"pg_stat_database was reset inside the measured window "
            f"({before.database_stats_reset} -> {after.database_stats_reset})"
        )
    if before.wal_stats_reset != after.wal_stats_reset:
        return (
            f"pg_stat_wal was reset inside the measured window "
            f"({before.wal_stats_reset} -> {after.wal_stats_reset})"
        )
    for field in (
        "xact_commit", "xact_rollback", "wal_records", "wal_bytes",
        "wal_write", "wal_sync",
    ):
        start = getattr(before, field)
        end = getattr(after, field)
        if end < start:
            return f"{field} decreased across the measured window ({start} -> {end})"
    if isinstance(served, bool) or not isinstance(served, int) or served <= 0:
        return f"served is not a positive count: {served!r}"
    if after.xact_commit - before.xact_commit <= 0:
        return (
            f"no database transaction committed inside the measured window "
            f"({before.xact_commit} -> {after.xact_commit})"
        )
    for name, value in (
        ("postgres_xact_commits_per_served",
         (after.xact_commit - before.xact_commit) / served),
        ("postgres_wal_syncs_per_served", (after.wal_sync - before.wal_sync) / served),
    ):
        if not math.isfinite(value):
            return f"{name} is not finite: {value!r}"
    return None


def postgres_xact_commits_per_served(before, after, served) -> float:
    """The FP-GC5-7 quantity itself, unrounded.

    The gate consumes THIS value, never its rendered form: rounding before
    comparing would let a ratio above the bar pass as `0.600000`.
    """
    return (after.xact_commit - before.xact_commit) / served


def serialize_postgres_commit_fields(before, after, served) -> str:
    """The eight transaction/WAL fields, in their pinned order.

    An unusable observation renders `unavailable` in ALL of them -- never a
    zero, never a mixture -- and the run's notes carry the reason.
    """
    if postgres_commit_snapshot_failure(before, after, served) is not None:
        return ",".join(
            f"{field}={DIAGNOSTIC_UNAVAILABLE}" for field in B1_POSTGRES_COMMIT_FIELDS
        )
    commits = after.xact_commit - before.xact_commit
    rollbacks = after.xact_rollback - before.xact_rollback
    wal_records = after.wal_records - before.wal_records
    wal_bytes = after.wal_bytes - before.wal_bytes
    wal_write = after.wal_write - before.wal_write
    wal_sync = after.wal_sync - before.wal_sync
    return (
        f"postgres_xact_commit_delta={commits},"
        f"postgres_xact_rollback_delta={rollbacks},"
        f"postgres_xact_commits_per_served={commits / served:.6f},"
        f"postgres_wal_records_delta={wal_records},"
        f"postgres_wal_bytes_delta={wal_bytes},"
        f"postgres_wal_write_delta={wal_write},"
        f"postgres_wal_sync_delta={wal_sync},"
        f"postgres_wal_syncs_per_served={wal_sync / served:.6f}"
    )


def commit_shape_record_failures(run: dict) -> list[str]:
    """Is this record admissible as FP-GC5-7 mechanism evidence?

    Complete, non-contaminated transaction counters are MANDATORY here --
    unlike the GC-4 wait sampler, whose absence stays fail-soft. The ratio bar
    itself is asserted by the node, not by this validator.
    """
    fails: list[str] = []
    result = run.get("result")
    served = getattr(result, "served", None)
    reason = postgres_commit_snapshot_failure(
        run.get("postgres_commit_before"), run.get("postgres_commit_after"), served
    )
    if reason is not None:
        fails.append(reason)
    return fails


def assert_complete_commit_shape_record(run: dict) -> None:
    """FP-GC5-7: refuse a record whose transaction counters are not usable."""
    fails = commit_shape_record_failures(run)
    if fails:
        raise B1PlacementError(
            "incomplete GC-5 commit-shape record: " + "; ".join(fails)
        )


def _role_diagnostics(role: str, cpu_max_text, stat_before, stat_after) -> B1RoleDiagnostics:
    """Render one role's reported-only cgroup fields, failing soft to `unavailable`."""
    notes: list[str] = []
    quota_cpus = DIAGNOSTIC_UNAVAILABLE
    period_us = DIAGNOSTIC_UNAVAILABLE
    if cpu_max_text is None:
        notes.append(f"{role} cpu.max: source was not readable")
        parsed_max = None
    else:
        parsed_max = _try_diagnostic(
            f"{role} cpu.max", notes, lambda: b1.parse_cpu_max(cpu_max_text)
        )
    if parsed_max is not None:
        quota_raw, period_raw = parsed_max
        quota_cpus = b1.format_quota_cpus(quota_raw, period_raw)
        period_us = str(period_raw)
    if stat_before is None or stat_after is None:
        notes.append(f"{role} cpu.stat: a measured-window snapshot was not readable")
        delta = None
    else:
        delta = _try_diagnostic(
            f"{role} cpu.stat", notes,
            lambda: b1.cpu_stat_delta(
                b1.parse_cpu_stat(stat_before), b1.parse_cpu_stat(stat_after)
            ),
        )
    if delta is None:
        return B1RoleDiagnostics(
            role=role, quota_cpus=quota_cpus, cpu_period_us=period_us, notes=tuple(notes)
        )
    return B1RoleDiagnostics(
        role=role,
        quota_cpus=quota_cpus,
        cpu_period_us=period_us,
        nr_periods=str(delta["nr_periods"]),
        nr_throttled=str(delta["nr_throttled"]),
        throttled_usec=str(delta["throttled_usec"]),
        usage_usec_delta=delta["usage_usec"],
        notes=tuple(notes),
    )


def _role_placement(role: str, pids: "list[int] | tuple[int, ...]") -> B1RolePlacement:
    """Effective scheduler affinity for every live process of one role."""
    ordered = tuple(sorted(set(pids)))
    if not ordered:
        raise B1PlacementError(f"{role}: no live pid to read placement from")
    views = [_proc_allowed_cpus(pid) for pid in ordered]
    distinct = {view for view in views}
    if len(distinct) != 1:
        raise B1PlacementError(
            f"{role}: processes carry different allowed-CPU sets "
            f"{sorted(b1.format_cpu_list(v) for v in distinct)}"
        )
    return B1RolePlacement(role=role, allowed_cpus=views[0], pids=ordered)


def _container_root_pid(container) -> int:
    wrapped = container.get_wrapped_container() if hasattr(container, "get_wrapped_container") else container
    wrapped.reload()
    pid = ((wrapped.attrs.get("State") or {}).get("Pid"))
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise B1PlacementError(f"{wrapped.name} reports no live host pid ({pid!r})")
    return pid


def _tree_pids(root_pid: int) -> tuple[int, ...]:
    return tuple(sorted({root_pid, *b1.iter_live_descendants(root_pid)}))


def _snapshot_container_log(container, log_path: Path) -> int:
    """Copy the sibling's retained Docker log to the run mount; return its size.

    Docker's log store replaces the old ``Popen(stdout=file)`` carrier, so the
    measured-window prefix is taken here, once, at window completion -- the
    later shed-probe phase cannot enter the warning count.
    """
    wrapped = container.get_wrapped_container() if hasattr(container, "get_wrapped_container") else container
    payload = wrapped.logs(stdout=True, stderr=True)
    with log_path.open("wb") as writer:
        writer.write(payload)
    return log_path.stat().st_size


def _verify_no_survivors(client, declaration: B1PlacementDeclaration) -> None:
    """Teardown is observed, not assumed (FP-GC1-2)."""
    survivors = client.containers.list(
        all=True, filters={"label": [declaration.run_label]}
    )
    stragglers = [c.name for c in survivors if c.name != declaration.driver_name]
    if stragglers:
        raise B1PlacementError(
            f"run {declaration.run_id} left containers behind after teardown: {stragglers}"
        )


def _restore_ryuk(config, previous: bool) -> None:
    config.ryuk_disabled = previous


def _restore_attr(config, name: str, previous) -> None:
    setattr(config, name, previous)


def _gateway_config(dsn: str) -> dict:
    return {
        "temporal": {"address": "localhost:7233", "namespace": "default", "task_queue": "t"},
        "storage": {
            "postgres_dsn": dsn,
            "s3_endpoint": "http://127.0.0.1:9",
            "s3_bucket": "b",
            "s3_access_key": "a",
            "s3_secret_key": "s",
            "s3_region": "us-east-1",
        },
        "model_gateway": {"url": "http://127.0.0.1:9", "master_key": "k"},
        "probe_gateway": {"url": "http://127.0.0.1:9"},
        "signing": {"key_path": "/tmp/nope", "rotation_grace_seconds": 600},
        "dashboard": {"jwt_secret": "j", "cors_origins": [], "bootstrap_ca_cert_path": ""},
        "notifications": {"outbound_webhooks": []},
        "ingest": {
            "sources": [{"name": "grafana-b1", "secret": HMAC_SECRET}],
            "correlation_window_seconds": 1800,
        },
        "budget_defaults": {"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800},
        "agents": {},
        "tracing": {"backend": "builtin"},
    }


def _migrate_and_seed(dsn: str) -> None:
    from rca_common.db.session import make_engine, make_session_factory
    from rca_common.db.models import Platform
    import alembic.config
    import alembic.command

    mig_dir = REPO_ROOT / "libs" / "py" / "rca_common"
    alembic_ini = mig_dir / "alembic.ini"
    migrations_dir = mig_dir / "migrations"
    if alembic_ini.is_file() and migrations_dir.is_dir():
        cfg = alembic.config.Config(str(alembic_ini))
        cfg.set_main_option("sqlalchemy.url", dsn)
        cfg.set_main_option("script_location", str(migrations_dir))
        alembic.command.upgrade(cfg, "head")
    else:
        from rca_common.db.models import Base

        engine = make_engine(dsn)
        Base.metadata.create_all(engine)
        engine.dispose()
    engine = make_engine(dsn)
    sf = make_session_factory(engine)
    with sf() as session:
        session.add(
            Platform(
                platform_key=PLATFORM_KEY,
                platform_type="presto",
                deployment="k8s",
                status="online",
                config={},
            )
        )
        session.commit()
    engine.dispose()


def _committed_ingest_rows(dsn: str) -> int:
    from rca_common.db.session import make_engine, make_session_factory
    from sqlalchemy import text

    engine = make_engine(dsn)
    sf = make_session_factory(engine)
    try:
        with sf() as session:
            return int(
                session.execute(
                    text(
                        "SELECT count(*) FROM audit_log "
                        "WHERE action IN ('event_received','event_merged')"
                    )
                ).scalar()
                or 0
            )
    finally:
        engine.dispose()


def _run_b1_reference(profile: B1Profile, tmp_path_factory):
    """One placement-valid B1 measurement of ``profile``.

    The driver never starts a gateway inside its own container: the two
    measured siblings are peer containers, each narrowed to its own exact,
    pairwise-disjoint CPU set, so every role has an independent and
    inspectable allocation. Placement is proven before warmup and again at
    window close; a bad declaration raises ``B1PlacementError`` and no burst is
    offered under it, while closing drift invalidates the run before any
    verdict is emitted.
    """
    import docker
    from testcontainers.core.config import ConnectionMode, testcontainers_config
    from testcontainers.core.container import DockerContainer
    from testcontainers.postgres import PostgresContainer

    declaration = B1PlacementDeclaration.from_contract(_read_launch_contract())
    if declaration.profile != profile.name:
        raise B1PlacementError(
            f"launch contract declares profile {declaration.profile!r}; this fixture "
            f"measures {profile.name!r}"
        )
    # FP-GC3-5, view 1 of 3: read before any sibling container exists, so a
    # topology that changes while the deployment is being built is caught.
    siblings_before = _read_reference_sibling_groups(declaration)
    client = docker.from_env()
    driver = _resolve_driver_container(client, declaration)
    image_id = driver.image.id
    workspace_source = _driver_mount_source(driver, B1_WORKSPACE_MOUNT)
    run_source = _driver_mount_source(driver, str(B1_RUN_MOUNT))
    socket_source = _driver_mount_source(driver, B1_DOCKER_SOCKET)

    run_dir = B1_RUN_MOUNT / f"profile-{profile.name}"
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / "gateway.log"
    log_path.unlink(missing_ok=True)
    cfg_path = run_dir / "gateway.yaml"
    gateway_cpus = declaration.allowed("gateway")
    postgres_cpus = declaration.allowed("postgres")

    with ExitStack() as stack:
        stack.callback(_verify_no_survivors, client, declaration)
        previous_ryuk = testcontainers_config.ryuk_disabled
        # Ryuk is an unmeasured sidecar: it would be a fourth uncontrolled
        # container inside the measured window, on nobody's declared CPUs.
        # Scoped to this ExitStack only, never a persistent global setting.
        testcontainers_config.ryuk_disabled = True
        stack.callback(_restore_ryuk, testcontainers_config, previous_ryuk)
        # The driver is in the host network namespace by construction, so a
        # sibling's published port is on loopback there. testcontainers would
        # otherwise autodetect "inside a container" and hand back the bridge
        # gateway address, which nothing is listening on. Scoped to this stack
        # and restored with it, exactly like the Ryuk setting above.
        for name, value in (
            ("connection_mode_override", ConnectionMode.docker_host),
            ("tc_host_override", B1_SIBLING_HOST),
        ):
            stack.callback(
                _restore_attr, testcontainers_config, name,
                getattr(testcontainers_config, name),
            )
            setattr(testcontainers_config, name, value)

        postgres = PostgresContainer(
            "postgres:16-alpine", dbname="dbagent", username="dbagent", password="dbagent"
        )
        # No quota, no period, no cpuset: the allocation is scheduler affinity
        # and it is applied to the process tree, below.
        postgres.with_kwargs(labels=declaration.labels("postgres"))
        stack.enter_context(postgres)

        # Both profiles pin PostgreSQL the same way. The postmaster is
        # Docker-owned, so exactly one short-lived CAP_SYS_NICE helper narrows
        # its tree and reads every member back; new backends inherit it.
        _pin_postgres_tree(
            client,
            declaration,
            image_id=image_id,
            container_id=postgres.get_wrapped_container().id,
            workspace_source=workspace_source,
            socket_source=socket_source,
        )
        postgres_pid = _container_root_pid(postgres)

        dsn = postgres.get_connection_url()
        _migrate_and_seed(dsn)
        cfg_path.write_text(yaml.safe_dump(_gateway_config(dsn)), encoding="utf-8")

        port = _free_port()
        gateway_command = (
            f"taskset -c {b1.format_cpu_list(gateway_cpus)} "
            f"python3 {B1_GATEWAY_IMPORT_PATH} --host {B1_SIBLING_HOST} --port {port}"
        )
        gateway = DockerContainer(image_id)
        gateway.with_command(gateway_command)
        gateway.with_env("DBAGENT_GATEWAY_CONFIG", str(cfg_path))
        gateway.with_env(
            "PYTHONPATH",
            os.pathsep.join(
                [
                    f"{B1_WORKSPACE_MOUNT}/services/gateway/tests",
                    f"{B1_WORKSPACE_MOUNT}/services/gateway",
                    f"{B1_WORKSPACE_MOUNT}/libs/py/rca_common",
                ]
            ),
        )
        gateway.with_volume_mapping(workspace_source, B1_WORKSPACE_MOUNT, "ro")
        gateway.with_volume_mapping(run_source, str(B1_RUN_MOUNT), "rw")
        gateway.with_kwargs(
            labels=declaration.labels("gateway"),
            network_mode="host",
            working_dir=B1_WORKSPACE_MOUNT,
        )
        stack.enter_context(gateway)

        endpoint = f"http://{B1_SIBLING_HOST}:{port}/api/v1/events"
        health = f"http://{B1_SIBLING_HOST}:{port}/healthz"
        _wait_for_gateway(gateway, health, log_path)

        assert httpx.get(health, timeout=5).status_code == 200
        platform_online = True

        gateway_pid = _container_root_pid(gateway)
        trackers_pre, workers_pre = b1.wait_for_classified_workers(
            gateway_pid, workers=b1.INGEST_GATEWAY_WORKERS
        )
        gateway_pids = (gateway_pid, *sorted(workers_pre), *sorted(trackers_pre))

        host_cpus = _host_cpu_ids()
        # View 2 of 3, contemporaneous with the opening placement probe below.
        siblings_open = _read_reference_sibling_groups(declaration)
        if siblings_open != siblings_before:
            raise B1PlacementError(
                f"{profile.name}: thread siblings changed while the deployment was built: "
                f"{sorted((c, sorted(v)) for c, v in siblings_before.items())} -> "
                f"{sorted((c, sorted(v)) for c, v in siblings_open.items())}"
            )
        witness = B1PlacementWitness(
            declaration, host_cpus=host_cpus, sibling_groups=siblings_open
        )

        driver_root_pid = _container_root_pid(driver)

        def _probe(when: str, workers, gw_pids, pg_pid):
            # The driver role is its container root plus the live pytest tree:
            # everything beneath the `taskset` the launcher applied.
            return {
                "gateway": _role_placement("gateway", gw_pids),
                "postgres": _role_placement("postgres", _tree_pids(pg_pid)),
                "driver": _role_placement(
                    "driver", (driver_root_pid, *_tree_pids(os.getpid()))
                ),
            }

        roles_open = _probe("open", workers_pre, gateway_pids, postgres_pid)
        # `cpus` is os.cpu_count(), never the affinity-restricted count: the
        # driver now runs under taskset, so sched_getaffinity(0) would report 1
        # and silently demote a real CI run to `local-replica`.
        fp = _host_fingerprint()
        authority = witness.authority(int(fp["cpus"]))
        failures = witness.failures(roles_open, gateway_worker_pids=workers_pre, when="open")
        if failures:
            print(
                _placement_fingerprint(declaration, authority, roles_open, failures),
                flush=True,
            )
            raise B1PlacementError(
                f"{profile.name}: declared placement not observed at window open; "
                f"run dir {run_dir}; " + "; ".join(failures)
            )

        warmup = _build_requests(1)[0]
        prologue = _build_requests(profile.prologue_requests)
        measured = _build_requests(profile.total_requests)
        marks: dict = {}

        # FP-GC2-5: host attribution, read once after the opening placement
        # witness so the CPU set is the proven one. Both are reported-only and
        # fail soft to `unavailable`.
        topology_notes: list[str] = marks.setdefault("diagnostic_notes", [])
        gateway_thread_siblings = _try_diagnostic(
            "gateway thread_siblings_list", topology_notes,
            lambda: _read_gateway_thread_siblings(roles_open["gateway"].allowed_cpus),
        )
        spectre_v2 = _try_diagnostic("spectre_v2", topology_notes, _read_spectre_v2)

        def _collect_cpu_diagnostics(phase: str) -> None:
            notes: list[str] = []
            for role, container in (("gateway", gateway), ("postgres", postgres), ("driver", None)):
                files = _try_diagnostic(
                    f"{role} cgroup files", notes, lambda c=container: _read_cpu_files(c)
                )
                marks[f"{role}_cpu_max_{phase}"] = files[0] if files else None
                marks[f"{role}_cpu_stat_{phase}"] = files[1] if files else None
            marks[f"busy_{phase}"] = _try_diagnostic(
                "gateway /proc/stat", notes,
                lambda: _gateway_set_busy_usec(roles_open["gateway"].allowed_cpus),
            )
            marks.setdefault("diagnostic_notes", []).extend(notes)

        # GC-4 (FP-GC4-5): one wait sampler per run, stopped exactly once
        # however this fixture ends. Its own PostgreSQL cost is inside the
        # measured window on purpose, identically in control and candidate.
        wait_sampler = B1PostgresWaitSampler(
            lambda: _open_postgres_wait_connection(dsn),
            target_database=target_database_name(dsn),
        )
        stack.callback(wait_sampler.shutdown)
        # GC-5 (FP-GC5-7): the transaction/WAL reader, on the SAME maintenance
        # database as the sampler and never on the measured one.
        stats_reader = B1PostgresStatsReader(
            lambda: _open_postgres_stats_connection(dsn),
            target_database=target_database_name(dsn),
        )
        stack.callback(stats_reader.close)

        def _after_prologue() -> None:
            # Snapshot AFTER the unmeasured prologue so CPU/audit exclude it (C2).
            _collect_cpu_diagnostics("before")
            marks["committed_before"] = _committed_ingest_rows(dsn)
            # GC-5: the pre-window transaction/WAL snapshot is taken AFTER that
            # audit-count query, so the prologue's own transactions are outside
            # the measured delta.
            notes = marks.setdefault("diagnostic_notes", [])
            marks["postgres_commit_before"] = _try_diagnostic(
                "postgres transaction snapshot (before)", notes, stats_reader.snapshot,
            )
            # ...and only then open the diagnostic connection and start sampling.
            _try_diagnostic(
                "postgres wait sampler", notes,
                wait_sampler.start,
            )

        def _after_window() -> None:
            # Stop sampling at window close, BEFORE the CPU-after snapshot, so
            # the sampler's own backend is not inside the reported interval's
            # tail. A sampler that cannot be stopped cleanly is a diagnostic
            # failure like any other here: it becomes a note and `unavailable`
            # fields, never a lost record. Then close the reported CPU interval
            # at drain/census stop, before the O(N) leg derivation; the log
            # prefix is taken strictly after it.
            notes = marks.setdefault("diagnostic_notes", [])
            sample = _try_diagnostic("postgres wait sampler stop", notes,
                                     wait_sampler.stop)
            marks["postgres_wait_sample"] = sample
            reason = postgres_wait_sample_failure(sample)
            if reason is not None:
                notes.append(f"postgres wait sampler: {reason}")
            _collect_cpu_diagnostics("after")
            marks["log_prefix_bytes"] = _snapshot_container_log(gateway, log_path)
            # GC-5: wait for cumulative-stat publication, require two equal
            # readings 100 ms apart, then take the post-window snapshot --
            # still before the post-window audit-count query below.
            marks["postgres_commit_after"] = _try_diagnostic(
                "postgres transaction snapshot (after)", notes,
                stats_reader.published_snapshot,
            )

        result = asyncio.run(
            b1.run_open_loop(
                endpoint=endpoint,
                requests=measured,
                rate=profile.rate,
                max_in_flight=profile.max_in_flight,
                warmup=warmup,
                prologue=prologue,
                include_sync_warmup=True,
                on_prologue_complete=_after_prologue,
                on_window_complete=_after_window,
                serve_port=port,
                worker_pids=sorted(workers_pre),
            )
        )
        concurrency_limit_warnings = _b1_gateway_warning_count(
            log_path, marks["log_prefix_bytes"]
        )
        trackers_post, workers_post = b1.classify_tree(gateway_pid)
        gateway_pids_post = (gateway_pid, *sorted(workers_post), *sorted(trackers_post))

        # Closing placement gate: a late process that escaped its declared set
        # invalidates the run before any B1 verdict is emitted.
        roles_close = _probe("close", workers_post, gateway_pids_post, postgres_pid)
        # View 3 of 3: the same reading at window close. All three must agree
        # before the closing relationship check is allowed to mean anything.
        siblings_close = _read_reference_sibling_groups(declaration)
        if siblings_close != siblings_open:
            raise B1PlacementError(
                f"{profile.name}: thread siblings changed during the measured window: "
                f"{sorted((c, sorted(v)) for c, v in siblings_open.items())} -> "
                f"{sorted((c, sorted(v)) for c, v in siblings_close.items())}"
            )
        closing = witness.failures(roles_close, gateway_worker_pids=workers_post, when="close")
        if closing:
            print(
                _placement_fingerprint(declaration, authority, roles_close, closing),
                flush=True,
            )
            raise B1PlacementError(
                f"{profile.name}: placement drifted during the measured window; "
                f"run dir {run_dir}; " + "; ".join(closing)
            )

        shed_probe = asyncio.run(b1.run_shed_probe(B1_SIBLING_HOST, port))

        diagnostics = {
            role: _role_diagnostics(
                role,
                marks.get(f"{role}_cpu_max_after"),
                marks.get(f"{role}_cpu_stat_before"),
                marks.get(f"{role}_cpu_stat_after"),
            )
            for role in B1_ROLES
        }
        busy_delta = _try_diagnostic(
            "gateway busy delta", marks.setdefault("diagnostic_notes", []),
            lambda: _busy_delta(marks["busy_before"], marks["busy_after"]),
        )
        span = result.t_last_complete - result.due0
        if span <= 0:
            raise B1PlacementError(f"measured span is not positive: {span}")
        if result.served <= 0:
            raise B1PlacementError("no request was served; the measurement is undefined")
        usage_usec = diagnostics["gateway"].usage_usec_delta
        cpu_ms = usage_usec / 1000.0 / result.served if usage_usec is not None else None
        cpu_cores_used = usage_usec / 1_000_000.0 / span if usage_usec is not None else None
        nonrole_busy_cores = (
            (sum(busy_delta.values()) - usage_usec) / 1_000_000.0 / span
            if (busy_delta is not None and usage_usec is not None)
            else None
        )
        worker_set_ok = trackers_post == trackers_pre and workers_post == workers_pre

        committed = _committed_ingest_rows(dsn) - int(marks.get("committed_before", 0))
        values = yaml.safe_load(VALUES_YAML.read_text(encoding="utf-8"))
        basis = float(values["ingestGateway"]["sizingBasis"]["cpuMsPerRequest"])

        med_a, med_b = b1.half_window_medians(result.latencies_ms)
        status_histogram = b1.serialize_status_histogram(result.status_codes)
        peak_est = result.peak_established_connections
        peak_est_str = str(peak_est) if isinstance(peak_est, int) else peak_est
        peak_pool_conn = result.peak_pool_connections
        peak_pool_conn_str = str(peak_pool_conn) if isinstance(peak_pool_conn, int) else peak_pool_conn
        peak_pool_q = result.peak_pool_queued
        peak_pool_q_str = str(peak_pool_q) if isinstance(peak_pool_q, int) else peak_pool_q
        pool_seen = result.pool_connections_seen
        pool_seen_str = str(pool_seen) if isinstance(pool_seen, int) else pool_seen
        worker_peaks = result.worker_established_peaks
        worker_peaks_str = b1.serialize_worker_established_peaks(worker_peaks)
        peak_worker_est = result.peak_worker_established
        peak_worker_est_str = (
            str(peak_worker_est) if isinstance(peak_worker_est, int) else peak_worker_est
        )
        p99_leg_split_str = b1.serialize_leg_triple(result.p99_leg_split)
        leg_p99s_str = b1.serialize_leg_triple(result.leg_p99s)
        wait_sample = marks.get("postgres_wait_sample")
        commit_before = marks.get("postgres_commit_before")
        commit_after = marks.get("postgres_commit_after")
        commit_reason = postgres_commit_snapshot_failure(
            commit_before, commit_after, result.served
        )
        if commit_reason is not None:
            # Recorded as a note with its reason, exactly like an unusable wait
            # sample: never repaired into a zero, and never fatal here -- the
            # FP-GC5-7 node is what refuses such a record.
            marks.setdefault("diagnostic_notes", []).append(
                f"postgres transaction snapshot: {commit_reason}"
            )
        verdicts = (
            _product_promise_verdicts(result)
            if profile.name == PRODUCT_PROFILE_NAME
            else OrderedDict()
        )
        product_fields = serialize_product_verdicts(verdicts)
        # FP-GC3-5: the field inventory is chosen from the parsed contract, not
        # shared. Schema 3 carries the physical-topology claim in its gating
        # prefix; schema 2 is byte-for-byte the GC-1/GC-2 line.
        role_thread_siblings = (
            {role: witness.sibling_map(roles_close[role].allowed_cpus) for role in B1_ROLES}
            if declaration.carries_topology
            else {}
        )
        if declaration.carries_topology:
            placement_fields = _serialize_topology_placement_fields(
                declaration,
                authority,
                roles_close,
                diagnostics,
                busy_delta,
                nonrole_busy_cores,
                cpu_cores_used,
                role_thread_siblings=role_thread_siblings,
                spectre_v2=spectre_v2,
            )
        else:
            placement_fields = _serialize_placement_fields(
                declaration,
                authority,
                roles_close,
                diagnostics,
                busy_delta,
                nonrole_busy_cores,
                cpu_cores_used,
                gateway_thread_siblings=gateway_thread_siblings,
                spectre_v2=spectre_v2,
            )
        cpu_ms_str = f"{cpu_ms:.3f}" if cpu_ms is not None else DIAGNOSTIC_UNAVAILABLE
        diagnostic_notes = list(marks.get("diagnostic_notes", []))
        for note in diagnostic_notes:
            print(f"B1 diagnostic unavailable: {note}", flush=True)
        # Plain locals for the yielded record: the fixture's mapping is also
        # evaluated symbolically by test_b1_fingerprint_line_reports_scoped_
        # concurrency_warnings, which binds every free name to a placeholder.
        # An attribute or subscript there would make that guard a type error
        # rather than the shape check it is.
        probe_topology = declaration.topology
        probe_round = declaration.probe_round
        probe_orientation = declaration.orientation
        probe_reference_cpus = declaration.reference_cpus
        probe_unassigned_cpus = declaration.unassigned_cpus
        postgres_usage_usec = diagnostics["postgres"].usage_usec_delta
        postgres_cost_fields = serialize_postgres_cost_fields(
            postgres_usage_usec, result.served, wait_sample
        )
        postgres_commit_fields = serialize_postgres_commit_fields(
            commit_before, commit_after, result.served
        )
        fingerprint_line = (
            f"B1 env=cpus={fp['cpus']},cpu_model={fp['cpu_model']},image={fp['image']},"
            f"tier=reference,workers={b1.INGEST_GATEWAY_WORKERS},"
            f"{placement_fields}"
            f"max_lateness_ms={result.max_lateness_ms:.1f},"
            f"p99_ms={result.p99:.1f},served_rate={result.served_rate:.1f},"
            f"served={result.served},errors={result.errors},committed={int(committed)},"
            f"platform_online={1 if platform_online else 0},"
            f"workers_pre={b1.format_pid_list(workers_pre)},"
            f"workers_post={b1.format_pid_list(workers_post)},"
            f"median_lateness_a_ms={med_a:.1f},median_lateness_b_ms={med_b:.1f},"
            f"lateness_drift_ms={result.lateness_drift_ms:.1f},"
            f"cpu_ms_per_req={cpu_ms_str},"
            f"basis_ms_per_req={basis},"
            f"max_in_flight={result.max_in_flight},max_backlog={result.max_backlog},"
            f"status_histogram={status_histogram},"
            f"concurrency_limit_warnings={concurrency_limit_warnings},"
            f"peak_established_connections={peak_est_str},"
            f"shed_probe={shed_probe},"
            f"peak_pool_connections={peak_pool_conn_str},"
            f"peak_pool_requests={result.peak_pool_requests},"
            f"peak_pool_queued={peak_pool_q_str},"
            f"pool_connections_seen={pool_seen_str},"
            f"worker_established_peaks={worker_peaks_str},"
            f"peak_worker_established={peak_worker_est_str},"
            f"{product_fields}"
            f"p99_leg_split={p99_leg_split_str},"
            f"leg_p99s={leg_p99s_str},"
            f"{postgres_cost_fields},"
            f"{postgres_commit_fields}"
        )
        print(fingerprint_line, flush=True)

        yield {
            "profile": profile,
            "declaration": declaration,
            "placement_ok": True,
            "placement": roles_close,
            "placement_open": roles_open,
            "measurement_authority": authority,
            "diagnostics": diagnostics,
            "gateway_cpu_busy_usec": busy_delta,
            "gateway_nonrole_busy_cores_estimate": nonrole_busy_cores,
            "product_verdicts": dict(verdicts),
            "result": result,
            "committed": int(committed),
            "cpu_ms_per_request": cpu_ms,
            "gateway_cpu_cores_used": cpu_cores_used,
            "worker_set_ok": worker_set_ok,
            "workers_pre": workers_pre,
            "workers_post": workers_post,
            "fingerprint": fingerprint_line,
            "status_histogram": status_histogram,
            "concurrency_limit_warnings": concurrency_limit_warnings,
            "gateway_log_path": log_path,
            "peak_established_connections": peak_est,
            "peak_pool_connections": peak_pool_conn,
            "peak_pool_queued": peak_pool_q,
            "pool_connections_seen": pool_seen,
            "worker_established_peaks": worker_peaks,
            "peak_worker_established": peak_worker_est,
            "p99_leg_split": result.p99_leg_split,
            "leg_p99s": result.leg_p99s,
            "shed_probe": shed_probe,
            "host": fp,
            "platform_online": platform_online,
            "basis_ms_per_req": basis,
            # GC-3 (FP-GC3-2/5): the topology view of this run. Empty on every
            # schema-2 contract, so the ordinary gate and the product record
            # carry exactly what they carried before.
            "topology": probe_topology,
            "round": probe_round,
            "orientation": probe_orientation,
            "reference_cpus": probe_reference_cpus,
            "unassigned_cpus": probe_unassigned_cpus,
            "sibling_groups": siblings_close,
            "role_thread_siblings": role_thread_siblings,
            "measured_span_seconds": span,
            "postgres_usage_usec": postgres_usage_usec,
            # GC-4 (FP-GC4-5): reported-only cost diagnostics of this window.
            "postgres_wait_sample": wait_sample,
            "postgres_cost_fields": postgres_cost_fields,
            # GC-5 (FP-GC5-7/8): the raw ends of the window and the rendered
            # deltas. The gate consumes the snapshots, never the rendering.
            "postgres_commit_before": commit_before,
            "postgres_commit_after": commit_after,
            "postgres_commit_fields": postgres_commit_fields,
            "diagnostic_notes": diagnostic_notes,
        }


def _pin_postgres_tree(client, declaration, *, image_id, container_id, workspace_source,
                       socket_source) -> None:
    """Run the closed pin helper once, before warmup, then let it disappear."""
    cpus = declaration.allowed("postgres")
    client.containers.run(
        image_id,
        command=[
            "python3",
            f"{B1_WORKSPACE_MOUNT}/scripts/b1-affinity-helper.py",
            "pin-postgres",
            container_id,
            b1.format_cpu_list(cpus),
            declaration.run_label,
        ],
        network_mode="host",
        pid_mode="host",
        cap_add=["SYS_NICE"],
        volumes={
            workspace_source: {"bind": B1_WORKSPACE_MOUNT, "mode": "ro"},
            socket_source: {"bind": B1_DOCKER_SOCKET, "mode": "rw"},
        },
        labels=declaration.labels("pin-helper"),
        remove=True,
        detach=False,
    )


def _wait_for_gateway(gateway, health: str, log_path: Path, *, timeout_s: float = 120.0) -> None:
    deadline = time.time() + timeout_s
    wrapped = gateway.get_wrapped_container()
    while time.time() < deadline:
        wrapped.reload()
        if wrapped.status not in {"running", "created"}:
            _snapshot_container_log(gateway, log_path)
            raise B1PlacementError(
                f"gateway container is {wrapped.status}; log={log_path}; tail:\n"
                f"{_b1_gateway_log_tail(log_path)}"
            )
        try:
            if httpx.get(health, timeout=1.0).status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.2)
    _snapshot_container_log(gateway, log_path)
    raise B1PlacementError(
        f"gateway never became healthy; log={log_path}; tail:\n{_b1_gateway_log_tail(log_path)}"
    )


def _busy_delta(before: dict[int, int], after: dict[int, int]) -> dict[int, int]:
    if before is None or after is None:
        raise b1.B1PlacementParseError("gateway-set /proc/stat sample missing")
    if set(before) != set(after):
        raise b1.B1PlacementParseError(
            f"gateway-set /proc/stat CPUs changed mid-window: {sorted(before)} -> {sorted(after)}"
        )
    out: dict[int, int] = {}
    for cpu in sorted(before):
        delta = after[cpu] - before[cpu]
        if delta < 0:
            raise b1.B1PlacementParseError(f"cpu{cpu} busy counter decreased across the window")
        out[cpu] = delta
    return out


def _serialize_placement_fields(declaration, authority, roles, diagnostics, busy_delta,
                                nonrole_busy_cores, cpu_cores_used,
                                gateway_thread_siblings=None, spectre_v2=None) -> str:
    """Gating identity and affinity first; every reported diagnostic after.

    The three ``*_allowed_cpus`` values are the CLOSING effective sets, never
    copies of the launch contract.
    """
    parts = [
        f"placement_profile={declaration.profile}",
        f"placement_schema={declaration.schema}",
        f"placement_run_id={declaration.run_id}",
        f"measurement_authority={authority}",
        "placement_ok=1",
    ]
    for role in B1_ROLES:
        parts.append(f"{role}_allowed_cpus={b1.format_cpu_list(roles[role].allowed_cpus)}")
    for role in B1_ROLES:
        parts.extend(f"{name}={value}" for name, value in diagnostics[role].rendered())
    busy = (
        b1.serialize_cpu_busy(busy_delta) if busy_delta is not None else DIAGNOSTIC_UNAVAILABLE
    )
    # Already measured by the harness for the PostgreSQL role; GC-2 only stops
    # dropping it. No extra cgroup read and no new measurement interval.
    postgres_usage = diagnostics["postgres"].usage_usec_delta
    parts.extend(
        [
            f"gateway_cpu_busy_usec={busy}",
            "gateway_nonrole_busy_cores_estimate="
            + (f"{nonrole_busy_cores:.3f}" if nonrole_busy_cores is not None
               else DIAGNOSTIC_UNAVAILABLE),
            "gateway_cpu_cores_used="
            + (f"{cpu_cores_used:.2f}" if cpu_cores_used is not None
               else DIAGNOSTIC_UNAVAILABLE),
            "postgres_usage_usec="
            + (str(postgres_usage) if postgres_usage is not None
               else DIAGNOSTIC_UNAVAILABLE),
            "gateway_thread_siblings_pct="
            + (_percent_encode_diagnostic(gateway_thread_siblings)
               if gateway_thread_siblings is not None else DIAGNOSTIC_UNAVAILABLE),
            "spectre_v2_pct="
            + (_percent_encode_diagnostic(spectre_v2)
               if spectre_v2 is not None else DIAGNOSTIC_UNAVAILABLE),
        ]
    )
    return ",".join(parts) + ","


def _serialize_topology_placement_fields(
    declaration, authority, roles, diagnostics, busy_delta, nonrole_busy_cores,
    cpu_cores_used, *, role_thread_siblings, spectre_v2=None,
) -> str:
    """GC-3 FP-GC3-5: the schema-3 CI-scale line.

    The physical-topology claim is part of the GATING prefix, not an
    attribution suffix: ``reference_topology``, ``reference_cpus``,
    ``unassigned_cpus`` and the three role sibling maps all describe the
    allocation this measurement was taken under, and none of them may be
    ``unavailable`` on a valid record. ``gateway_thread_siblings_pct`` appears
    here and, deliberately, nowhere else on a schema-3 line -- GC-2 emitted it
    once as a reported-only diagnostic and this slice promotes that one field
    and generalises it to all three roles.

    Everything after ``driver_thread_siblings_pct`` keeps its GC-1/GC-2
    reported-only semantics: ambient cgroup policy, host busy time, PostgreSQL
    usage and the Spectre text explain a result and decide nothing.
    """
    missing = [role for role in B1_ROLES if not role_thread_siblings.get(role)]
    if missing:
        raise B1PlacementError(
            f"schema-{B1_TOPOLOGY_PLACEMENT_SCHEMA} record needs a sibling map for every role; "
            f"{missing} are absent"
        )
    unassigned = (
        b1.format_cpu_list(declaration.unassigned_cpus)
        if declaration.unassigned_cpus
        else B1_UNASSIGNED_NONE
    )
    parts = [
        f"placement_profile={declaration.profile}",
        f"placement_schema={declaration.schema}",
        f"placement_run_id={declaration.run_id}",
        f"measurement_authority={authority}",
        f"reference_topology={declaration.topology}",
        f"reference_cpus={b1.format_cpu_list(declaration.reference_cpus)}",
        f"unassigned_cpus={unassigned}",
        "placement_ok=1",
    ]
    for role in B1_ROLES:
        parts.append(f"{role}_allowed_cpus={b1.format_cpu_list(roles[role].allowed_cpus)}")
    for role in B1_ROLES:
        parts.append(
            f"{role}_thread_siblings_pct="
            + _percent_encode_diagnostic(role_thread_siblings[role])
        )
    for role in B1_ROLES:
        parts.extend(f"{name}={value}" for name, value in diagnostics[role].rendered())
    busy = (
        b1.serialize_cpu_busy(busy_delta) if busy_delta is not None else DIAGNOSTIC_UNAVAILABLE
    )
    postgres_usage = diagnostics["postgres"].usage_usec_delta
    parts.extend(
        [
            f"gateway_cpu_busy_usec={busy}",
            "gateway_nonrole_busy_cores_estimate="
            + (f"{nonrole_busy_cores:.3f}" if nonrole_busy_cores is not None
               else DIAGNOSTIC_UNAVAILABLE),
            "gateway_cpu_cores_used="
            + (f"{cpu_cores_used:.2f}" if cpu_cores_used is not None
               else DIAGNOSTIC_UNAVAILABLE),
            "postgres_usage_usec="
            + (str(postgres_usage) if postgres_usage is not None
               else DIAGNOSTIC_UNAVAILABLE),
            "spectre_v2_pct="
            + (_percent_encode_diagnostic(spectre_v2)
               if spectre_v2 is not None else DIAGNOSTIC_UNAVAILABLE),
        ]
    )
    return ",".join(parts) + ","


def _placement_fingerprint(declaration, authority, roles, failures) -> str:
    """Printed on a mismatch, before the run is refused: no verdict follows it."""
    parts = [
        f"placement_profile={declaration.profile}",
        f"placement_schema={declaration.schema}",
        f"placement_run_id={declaration.run_id}",
        f"measurement_authority={authority}",
        "placement_ok=0",
    ]
    for role in B1_ROLES:
        found = roles.get(role)
        if found is None or not found.allowed_cpus:
            parts.append(f"{role}_allowed_cpus=missing")
            continue
        parts.append(f"{role}_allowed_cpus={b1.format_cpu_list(found.allowed_cpus)}")
    return "B1 placement=" + ",".join(parts) + ",failures=" + "|".join(failures)


# ---------------------------------------------------------------------------
# GC-3 (FP-GC3-2) — the discovery arm record.
#
# Container-free on purpose: the live module holds only the fixture and the
# assertions, so everything that builds, checks or serialises a record is
# exercised by the ordinary traced coverage phase with fake runs.
# ---------------------------------------------------------------------------

B1_PROBE_CONTEXT = B1_RUN_MOUNT / "probe-context.json"
B1_PROBE_RECORD = B1_RUN_MOUNT / "arm-record.json"


def read_probe_context(path: Path = B1_PROBE_CONTEXT) -> dict:
    """The run identity the launcher wrote beside this arm's contract.

    Identity only -- head SHA, GitHub run/attempt/job, observed CPU model and
    sibling pairs. No profile, candidate, affinity or threshold value crosses
    this boundary, which is why the harness itself still reads no environment.
    """
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise B1PlacementError(f"no probe context at {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise B1PlacementError(f"probe context at {path} is not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise B1PlacementError(f"probe context at {path} is not an object")
    required = {
        "index", "headSha", "githubRunId", "githubRunAttempt", "githubJob",
        "cpuModel", "logicalCpuCount", "referenceCpus", "siblingPairs",
    }
    if set(payload) != required:
        raise B1PlacementError(
            f"probe context keys drift: missing {sorted(required - set(payload))}, "
            f"unknown {sorted(set(payload) - required)}"
        )
    return payload


def probe_operands(run: dict) -> dict:
    """The raw operands of the ten unchanged comparisons, read once."""
    result = run["result"]
    return {
        "offered": result.offered,
        "served": result.served,
        "errors": result.errors,
        "committed": run["committed"],
        "p99Ms": result.p99,
        "servedRate": result.served_rate,
        "maxInFlight": result.max_in_flight,
        "platformOnline": bool(run["platform_online"]),
        "workerSetStable": bool(run["worker_set_ok"]),
    }


def build_probe_arm_record(run: dict, context: dict) -> dict:
    """One arm's complete, closed record; raises rather than recording a guess."""
    declaration = run["declaration"]
    if not declaration.carries_topology:
        raise B1PlacementError(
            f"profile {declaration.profile!r} carries no topology; it cannot produce a "
            f"discovery arm record"
        )
    groups = run["sibling_groups"]
    operands = probe_operands(run)
    record = {
        "index": context["index"],
        "runId": declaration.run_id,
        "topology": declaration.topology,
        "round": declaration.probe_round,
        "orientation": declaration.orientation,
        "profile": declaration.profile,
        "referenceCpus": b1.format_cpu_list(declaration.reference_cpus),
        "declaredRoles": {
            role: b1.format_cpu_list(declaration.allowed(role)) for role in B1_ROLES
        },
        "effectiveRoles": {
            role: b1.format_cpu_list(run["placement"][role].allowed_cpus) for role in B1_ROLES
        },
        "unassignedCpus": (
            b1.format_cpu_list(declaration.unassigned_cpus)
            if declaration.unassigned_cpus else B1_UNASSIGNED_NONE
        ),
        "siblingMap": dict(run["role_thread_siblings"]),
        "referenceSiblingMap": probe.serialize_sibling_map(sorted(groups), groups),
        "fingerprint": run["fingerprint"],
        "operands": operands,
        "verdicts": probe.evaluate_verdicts(operands),
        "verdictLine": probe.serialize_verdicts(probe.evaluate_verdicts(operands)),
        "spanSeconds": run["measured_span_seconds"],
        "postgresUsageUsec": run["postgres_usage_usec"],
        "gatewayCpuCoresUsed": run["gateway_cpu_cores_used"],
        "measurementAuthority": run["measurement_authority"],
        "cpuModel": context["cpuModel"],
        "logicalCpuCount": context["logicalCpuCount"],
        "siblingPairs": list(context["siblingPairs"]),
        "headSha": context["headSha"],
        "githubRunId": context["githubRunId"],
        "githubRunAttempt": context["githubRunAttempt"],
        "githubJob": context["githubJob"],
        "notes": list(run.get("diagnostic_notes", ())),
    }
    try:
        probe.validate_record(record)
    except probe.TopologyProbeError as exc:
        raise B1PlacementError(f"arm {context['index']} record is not admissible: {exc}") from exc
    return record


def write_probe_arm_record(record: dict, path: Path = B1_PROBE_RECORD) -> None:
    Path(path).write_text(probe.canonical_json(record), encoding="utf-8")


@pytest.fixture(scope="module")
def b1_ci_scale_run(tmp_path_factory):
    """FP-GC1-1/4: the gating CI-scale burst under the declared 2/1/1 affinity."""
    yield from _run_b1_reference(CI_SCALE_PROFILE, tmp_path_factory)


@pytest.fixture(scope="module")
def b1_product_run(tmp_path_factory):
    """FP-GC1-3/4: the recorded product-promise burst on exclusive 4/3/1 cores."""
    yield from _run_b1_reference(PRODUCT_PROFILE, tmp_path_factory)


# Module-scope bars for the manifest threshold checker (ordering comparisons
# against bare Name bindings to numeric literals — FP-M6-31 / §11.1.3).
#
# Two independent literal sets, one per tier. They are deliberately literals
# rather than imported profile values: the covered-entry AST guard resolves
# numeric bindings in this file and does not trust an imported runtime value
# as a threshold, so a drifted profile constant must be caught by the delivery
# pin that compares the two — not hidden behind an alias.
CI_SCALE_P99_MS = 150.0
CI_SCALE_SUSTAINED_FLOOR = 450
CI_SCALE_MAX_IN_FLIGHT = 500
CI_SCALE_TOTAL_REQUESTS = 15000
PRODUCT_P99_MS = 150.0
PRODUCT_SUSTAINED_FLOOR = 200
PRODUCT_MAX_IN_FLIGHT = 1000
PRODUCT_TOTAL_REQUESTS = 30000


@pytest.mark.b1_live
def test_b1_ci_scale_reference_profile(b1_ci_scale_run):
    """FP-GC1-1: the gating CI-scale bar under the declared CPU affinity.

    Renamed from ``test_b1_ingest_burst_reference_profile``, not duplicated:
    this is the same seven-clause B1 shape, restated as fixed numbers for the
    2/1/1 four-CPU affinity allocation. It is explicitly not the product
    promise and predicts nothing about the later write-path slice.
    """
    r = b1_ci_scale_run["result"]
    committed = b1_ci_scale_run["committed"]
    served = r.served
    errors = r.errors
    offered = r.offered
    p99 = r.p99
    served_rate = r.served_rate
    max_in_flight = r.max_in_flight
    # (0) placement is a precondition, re-asserted here so a fixture refactor
    # cannot quietly remove it.
    assert b1_ci_scale_run["placement_ok"] is True, b1_ci_scale_run["fingerprint"]
    assert offered == CI_SCALE_TOTAL_REQUESTS, (
        f"offered={offered}; {b1_ci_scale_run['fingerprint']}"
    )
    # (7) platform ONLINE — fixture seeds status=online and asserts reachability
    platform_online = b1_ci_scale_run["platform_online"]
    assert platform_online == True  # noqa: E712 — named Eq for FP-IG-19
    # (1)(2)(3)
    assert served + errors == offered, (
        f"served+errors!=offered {served}+{errors}!={offered}; {b1_ci_scale_run['fingerprint']}"
    )
    assert errors == 0, f"errors={errors}; {b1_ci_scale_run['fingerprint']}"
    assert served == offered, f"served={served}; {b1_ci_scale_run['fingerprint']}"
    # (4) ordering comparison against module constant — measurement-of-record bar
    assert p99 < CI_SCALE_P99_MS, f"p99={p99}; {b1_ci_scale_run['fingerprint']}"
    # (5)
    assert committed == served, (
        f"committed={committed} served={served}; {b1_ci_scale_run['fingerprint']}"
    )
    # (6)
    assert served_rate >= CI_SCALE_SUSTAINED_FLOOR, (
        f"served_rate={served_rate}; {b1_ci_scale_run['fingerprint']}"
    )
    # harness integrity
    assert max_in_flight < CI_SCALE_MAX_IN_FLIGHT, (
        f"max_in_flight={max_in_flight} hit ceiling; harness was binding"
    )
    assert b1_ci_scale_run["worker_set_ok"], (
        f"worker set changed or under-populated; "
        f"pre={sorted(b1_ci_scale_run['workers_pre'])} "
        f"post={sorted(b1_ci_scale_run['workers_post'])}"
    )


@pytest.mark.b1_live
def test_b1_ci_scale_fingerprint_proves_reference_topology(b1_ci_scale_run):
    """FP-GC3-5: the CI-scale run carries its complete effective REFERENCE TOPOLOGY.

    This replaces and renames the GC-1/GC-2 witness
    ``test_b1_ci_scale_fingerprint_proves_placement``. The exact affinity sets
    it proved are still proved here; what is new -- and what the rename is
    about -- is that the PHYSICAL relationship is now part of the same gate.
    The gating half is therefore the schema-3 prefix: the topology ID, the
    reference CPU set, the intentionally unassigned CPU, the three exact
    pairwise-disjoint ``*_allowed_cpus`` sets and all three role sibling maps.
    None of them may be ``unavailable``.

    The second leg is the decision join. The launcher routed this run by
    reading the host's exact ``cpuModel`` and looking it up in the tracked
    carrier; this node reads that SAME carrier -- through the driver's existing
    read-only source mount, never a copied host route record -- and requires
    the entry for the model observed INSIDE the measured container to be
    `selected` with exactly this topology. Route -> decision -> live
    fingerprint is transitive through one file, with no second selector.

    Everything after ``driver_thread_siblings_pct`` is a reported
    cgroup/host diagnostic and is checked only for presence and shape: those
    values describe ambient policy, not this run's allocation, and an
    ``unavailable`` among them is a truthful record rather than a failure.
    """
    line = b1_ci_scale_run["fingerprint"]
    declaration = b1_ci_scale_run["declaration"]
    placement = b1_ci_scale_run["placement"]
    assert "placement_ok=1" in line, line
    assert _parse_b1_env_field(line, "placement_profile") == CI_SCALE_PROFILE_NAME
    assert _parse_b1_env_field(line, "placement_schema") == str(B1_TOPOLOGY_PLACEMENT_SCHEMA)
    assert _parse_b1_env_field(line, "placement_run_id") == declaration.run_id
    assert _parse_b1_env_field(line, "measurement_authority") == (
        b1_ci_scale_run["measurement_authority"]
    )
    # The topology claim is gating: the ID is one of the closed seven, the
    # reference set is the four CPUs the launcher discovered as two complete
    # SMT pairs, and the unassigned field is exact.
    assert declaration.carries_topology
    topology = _parse_b1_env_field(line, "reference_topology")
    assert topology in probe.TOPOLOGY_IDS, topology
    assert topology == declaration.topology
    assert _parse_b1_env_field(line, "reference_cpus") == b1.format_cpu_list(
        declaration.reference_cpus
    )
    expected_unassigned = (
        b1.format_cpu_list(declaration.unassigned_cpus)
        if declaration.unassigned_cpus else B1_UNASSIGNED_NONE
    )
    assert _parse_b1_env_field(line, "unassigned_cpus") == expected_unassigned
    assert len(declaration.unassigned_cpus) == probe.topology_unassigned_cardinality(topology)
    # Exact declared sets, at the topology-derived cardinalities, read back
    # from the kernel at window close.
    cardinality = probe.topology_cardinality(topology)
    assert cardinality == declaration.cardinality
    observed: dict[str, frozenset[int]] = {}
    for role in B1_ROLES:
        effective = placement[role].allowed_cpus
        observed[role] = effective
        assert effective == declaration.allowed(role), role
        assert len(effective) == cardinality[role], (role, sorted(effective))
        assert _parse_b1_env_field(line, f"{role}_allowed_cpus") == b1.format_cpu_list(effective)
        assert _parse_b1_env_field(line, f"{role}_allowed_cpus") != DIAGNOSTIC_UNAVAILABLE
    assert not observed["gateway"] & observed["postgres"]
    assert not observed["gateway"] & observed["driver"]
    assert not observed["postgres"] & observed["driver"]
    union = observed["gateway"] | observed["postgres"] | observed["driver"]
    assert union | declaration.unassigned_cpus == declaration.reference_cpus
    assert not union & declaration.unassigned_cpus
    assert len(declaration.reference_cpus) == CI_SCALE_REFERENCE_LOGICAL_CPUS
    # The opening probe agreed with the closing one.
    for role in B1_ROLES:
        assert b1_ci_scale_run["placement_open"][role].allowed_cpus == observed[role]
    # All three role sibling maps are GATING under schema 3: present, decodable,
    # covering exactly that role's effective set, and never `unavailable`.
    groups = b1_ci_scale_run["sibling_groups"]
    assert set(groups) == set(declaration.reference_cpus)
    for cpu, members in groups.items():
        assert len(members) == 2, (cpu, sorted(members))
        assert cpu in members
        for member in members:
            assert groups[member] == members, (cpu, member)
    for role in B1_ROLES:
        rendered = _parse_b1_env_field(line, f"{role}_thread_siblings_pct")
        assert rendered != DIAGNOSTIC_UNAVAILABLE, role
        decoded = urllib.parse.unquote(rendered)
        assert _percent_encode_diagnostic(decoded) == rendered, decoded
        mapped = probe.parse_sibling_map(decoded)
        assert set(mapped) == set(observed[role]), (role, sorted(mapped))
        for cpu, members in mapped.items():
            assert members == groups[cpu], (role, cpu)
    # ...and the relationship they describe is the declared topology, rebuilt
    # from the effective state rather than copied from the contract.
    pair0, pair1 = probe.normalize_pairs(
        sorted({tuple(sorted(members)) for members in groups.values()}),
        declaration.reference_cpus,
    )
    assert declaration.witness_orientation == probe.SELECTED_ORIENTATION
    reconstructed = probe.topology_mapping(
        topology, pair0, pair1, declaration.witness_orientation
    )
    for role in B1_ROLES:
        assert reconstructed[role] == observed[role], (
            topology, role, sorted(observed[role]), sorted(reconstructed[role])
        )
    assert reconstructed["unassigned"] == declaration.unassigned_cpus
    # Gating fields precede every diagnostic, in the pinned schema-3 order.
    positions = [line.index(f"{name}=") for name in B1_TOPOLOGY_GATING_PLACEMENT_FIELDS]
    assert positions == sorted(positions), B1_TOPOLOGY_GATING_PLACEMENT_FIELDS
    assert max(positions) < min(
        line.index(f"{name}=") for name in B1_TOPOLOGY_DIAGNOSTIC_PLACEMENT_FIELDS
    )

    # --- the decision join (FP-GC3-4/5) ------------------------------------
    # The mounted carrier is the ONLY input: no host route record is copied
    # into the run directory and the closed placement contract carries no
    # `cpuModel` key, so this leg cannot be satisfied by the launcher's own
    # claim about the host.
    assert "cpuModel" not in _read_launch_contract()
    assert B1_DECISION_CARRIER.is_file(), (
        f"{probe.DECISION_MISSING_REASON}: {B1_DECISION_CARRIER} is not mounted; a CI-scale "
        f"gate exists only for a model the tracked carrier has ratified"
    )
    carrier = json.loads(B1_DECISION_CARRIER.read_text(encoding="utf-8"))
    probe.validate_decision(carrier)
    measured_model = probe.validate_cpu_model(_host_fingerprint()["cpu_model"])
    entry = carrier["models"].get(measured_model)
    assert entry is not None, (
        f"the measured container reports {measured_model!r}, which has no entry in "
        f"{B1_DECISION_CARRIER}; another model's entry is never a fallback"
    )
    assert entry["status"] == probe.DECISION_SELECTED, (measured_model, entry["status"])
    assert entry["selected"] == topology, (measured_model, entry["selected"], topology)
    assert entry["cardinality"] == cardinality
    assert entry["placementSchema"] == B1_TOPOLOGY_PLACEMENT_SCHEMA
    assert CI_SCALE_AFFINITY_CARDINALITIES_BY_CPU_MODEL[measured_model] == cardinality
    assert CI_SCALE_PLACEMENT_SCHEMAS_BY_CPU_MODEL[measured_model] == (
        B1_TOPOLOGY_PLACEMENT_SCHEMA
    )

    # Reported-only diagnostics: present, and either a legal value or
    # `unavailable`. Their content never decides anything here.
    for role in B1_ROLES:
        quota = _parse_b1_env_field(line, f"{role}_quota_cpus")
        assert quota == DIAGNOSTIC_UNAVAILABLE or quota == b1.CPU_QUOTA_MAX or float(quota) > 0
        period = _parse_b1_env_field(line, f"{role}_cpu_period_us")
        assert period == DIAGNOSTIC_UNAVAILABLE or int(period) > 0
        for counter in ("nr_periods", "nr_throttled", "throttled_usec"):
            value = _parse_b1_env_field(line, f"{role}_{counter}")
            assert value == DIAGNOSTIC_UNAVAILABLE or int(value) >= 0
    for name in ("gateway_cpu_busy_usec", "gateway_nonrole_busy_cores_estimate",
                 "gateway_cpu_cores_used"):
        assert f"{name}=" in line, name
    assert "cpu_cores_used=" not in line.replace("gateway_cpu_cores_used=", "")
    diagnostic_positions = [
        line.index(f"{name}=") for name in B1_TOPOLOGY_DIAGNOSTIC_PLACEMENT_FIELDS
    ]
    assert diagnostic_positions == sorted(diagnostic_positions), (
        B1_TOPOLOGY_DIAGNOSTIC_PLACEMENT_FIELDS
    )
    usage = _parse_b1_env_field(line, "postgres_usage_usec")
    assert usage == DIAGNOSTIC_UNAVAILABLE or int(usage) >= 0, usage
    # The gateway sibling map appears exactly once on a schema-3 line, in the
    # gating prefix; it is not repeated among the diagnostics.
    assert line.count("gateway_thread_siblings_pct=") == 1, line
    spectre = _parse_b1_env_field(line, "spectre_v2_pct")
    if spectre != DIAGNOSTIC_UNAVAILABLE:
        decoded_spectre = urllib.parse.unquote(spectre)
        assert _percent_encode_diagnostic(decoded_spectre) == spectre, decoded_spectre
        assert decoded_spectre == " ".join(decoded_spectre.split()), decoded_spectre
    # The CI-scale fingerprint carries no product-verdict field.
    for field_name in PRODUCT_VERDICT_FIELDS:
        assert f"{field_name}=" not in line, line


@pytest.mark.b1_live
@pytest.mark.b1_product
def test_b1_product_exclusive_reference_profile(b1_product_run):
    """FP-GC1-3: the product promise, recorded on measured-role-exclusive cores.

    Every placement, accounting and record-integrity assertion here is
    failure-producing. The three product-promise comparisons are not: each is
    evaluated once, serialized as ``met``/``missed``, and then checked only
    for agreement with its own live comparison. A truthful ``missed`` is
    recorded benchmark data, so it leaves this node, ``b1_product`` and
    ``all`` green; a missing, malformed, literalized or inconsistent token
    does not.
    """
    r = b1_product_run["result"]
    committed = b1_product_run["committed"]
    served = r.served
    errors = r.errors
    offered = r.offered
    p99 = r.p99
    served_rate = r.served_rate
    max_in_flight = r.max_in_flight
    line = b1_product_run["fingerprint"]
    assert b1_product_run["placement_ok"] is True, line
    assert offered == PRODUCT_TOTAL_REQUESTS, f"offered={offered}; {line}"
    platform_online = b1_product_run["platform_online"]
    assert platform_online == True  # noqa: E712 — named Eq for FP-IG-19
    assert served + errors == offered, (
        f"served+errors!=offered {served}+{errors}!={offered}; {line}"
    )
    assert committed == served, f"committed={committed} served={served}; {line}"
    assert served_rate >= PRODUCT_SUSTAINED_FLOOR, f"served_rate={served_rate}; {line}"
    assert max_in_flight < PRODUCT_MAX_IN_FLIGHT, (
        f"max_in_flight={max_in_flight} hit ceiling; harness was binding"
    )
    assert b1_product_run["worker_set_ok"], (
        f"worker set changed or under-populated; "
        f"pre={sorted(b1_product_run['workers_pre'])} "
        f"post={sorted(b1_product_run['workers_post'])}"
    )

    # Recorded, not gating: each serialized token must equal the result of its
    # own live comparison. This deliberately does NOT assert any token is
    # `met`.
    live = {
        "product_errors_eq_zero": VERDICT_MET if errors == 0 else VERDICT_MISSED,
        "product_p99_lt_150_ms": VERDICT_MET if p99 < PRODUCT_P99_MS else VERDICT_MISSED,
        "product_served_eq_offered": VERDICT_MET if served == offered else VERDICT_MISSED,
    }
    assert tuple(live) == PRODUCT_VERDICT_FIELDS
    for field_name in PRODUCT_VERDICT_FIELDS:
        assert line.count(f"{field_name}=") == 1, f"{field_name} is not carried exactly once; {line}"
        token = _parse_b1_env_field(line, field_name)
        assert token in (VERDICT_MET, VERDICT_MISSED), f"{field_name}={token!r}; {line}"
        assert token == live[field_name], (
            f"{field_name} serialized {token!r} but its live comparison says "
            f"{live[field_name]!r}; {line}"
        )
        assert b1_product_run["product_verdicts"][field_name] == live[field_name]
    assert line.index("product_errors_eq_zero=") < line.index("product_p99_lt_150_ms=")
    assert line.index("product_p99_lt_150_ms=") < line.index("product_served_eq_offered=")
    assert line.index("product_served_eq_offered=") < line.index("p99_leg_split=")


@pytest.mark.b1_live
@pytest.mark.b1_product
def test_b1_product_fingerprint_proves_exclusive_placement(b1_product_run):
    """FP-GC1-4: four gateway CPUs, exclusive of the other two measured roles."""
    line = b1_product_run["fingerprint"]
    placement = b1_product_run["placement"]
    declaration = b1_product_run["declaration"]
    assert "placement_ok=1" in line, line
    assert _parse_b1_env_field(line, "placement_profile") == PRODUCT_PROFILE_NAME
    assert _parse_b1_env_field(line, "placement_schema") == str(PRODUCT_PLACEMENT_SCHEMA)
    assert _parse_b1_env_field(line, "measurement_authority") == AUTHORITY_PRODUCT_LOCAL
    for role, cardinality in PRODUCT_AFFINITY_CARDINALITY.items():
        effective = placement[role].allowed_cpus
        assert effective == declaration.allowed(role), role
        assert len(effective) == cardinality, (role, sorted(effective))
        assert _parse_b1_env_field(line, f"{role}_allowed_cpus") == b1.format_cpu_list(effective)
        assert b1_product_run["placement_open"][role].allowed_cpus == effective
    gateway_cpus = placement["gateway"].allowed_cpus
    assert len(gateway_cpus) == PRODUCT_GATEWAY_CPU_CARDINALITY, sorted(gateway_cpus)
    assert not gateway_cpus & placement["postgres"].allowed_cpus
    assert not gateway_cpus & placement["driver"].allowed_cpus
    assert not placement["postgres"].allowed_cpus & placement["driver"].allowed_cpus
    assert len(
        gateway_cpus | placement["postgres"].allowed_cpus | placement["driver"].allowed_cpus
    ) == 8
    assert len(placement["gateway"].pids) >= b1.INGEST_GATEWAY_WORKERS + 1
    assert set(b1_product_run["workers_post"]) <= set(placement["gateway"].pids)
    # Reported cgroup values cannot turn a correctly placed run into a
    # placement failure, whatever they say.
    for role in B1_ROLES:
        quota = _parse_b1_env_field(line, f"{role}_quota_cpus")
        assert quota == DIAGNOSTIC_UNAVAILABLE or quota == b1.CPU_QUOTA_MAX or float(quota) > 0


@pytest.mark.b1_live
@pytest.mark.b1_product
def test_gc4_live_postgres_cost_record_is_complete(b1_product_run):
    """FP-GC4-5 diagnostics: the product record publishes them, and decides nothing.

    The quantitative GC-4 outcome is the fused-statement regression
    ``test_gc4_fused_merge_reduces_server_statement_time`` on the
    planning-enabled fixture -- not anything measured here. This node checks
    that the record's harness-owned operands are present and that the six
    reported-only fields are serialized honestly, in either of their two
    admitted representations: real readings, or `unavailable` plus a
    diagnostic note when the test-only sampler was not usable. Sampler
    availability is never an outcome. The node reuses the product route's
    existing module-scoped fixture, so it adds no second 30-second workload.
    """
    assert_complete_postgres_cost_record(b1_product_run)

    line = b1_product_run["fingerprint"]
    result = b1_product_run["result"]
    sample = b1_product_run["postgres_wait_sample"]
    notes = b1_product_run["diagnostic_notes"]

    # (1) All six fields, in their pinned order, AFTER both lateness legs --
    # so no gating field ever moves behind a diagnostic one.
    at = line.index("leg_p99s=")
    for field in B1_POSTGRES_COST_FIELDS:
        position = line.index(f",{field}=")
        assert position > at, f"{field} is not after the lateness legs"
        at = position

    # (2) CPU per served request is numeric and is this run's own quotient.
    rendered = _parse_b1_env_field(line, "postgres_cpu_us_per_req")
    assert rendered != DIAGNOSTIC_UNAVAILABLE, line
    usage = b1_product_run["postgres_usage_usec"]
    assert float(rendered) == pytest.approx(usage / result.served, abs=5e-4)
    assert float(rendered) > 0

    # (3) The wait fields: EITHER this sample's own counters, OR `unavailable`
    # in all five plus a note naming the reason. Never a mixture, and never a
    # fabricated zero.
    reason = postgres_wait_sample_failure(sample)
    wait_fields = {
        field: _parse_b1_env_field(line, field) for field in B1_POSTGRES_COST_FIELDS[1:]
    }
    if reason is None:
        assert wait_fields["postgres_wait_failed"] == "0"
        assert int(wait_fields["postgres_wait_scheduled"]) == sample.scheduled
        assert int(wait_fields["postgres_wait_completed"]) == sample.completed
        assert int(wait_fields["postgres_wait_observations"]) == sample.observations
        assert wait_fields["postgres_wait_events_pct"] == (
            serialize_postgres_wait_histogram(sample.histogram)
        )
        assert sample.observations > 0
        assert sample.completed >= B1_WAIT_MIN_COMPLETION_RATIO * sample.scheduled
    else:
        assert set(wait_fields.values()) == {DIAGNOSTIC_UNAVAILABLE}, wait_fields
        assert any("postgres wait sampler" in note for note in notes), notes

    # (4) Reported-only: not one of these names is a gating placement field, a
    # product verdict or a discovery verdict.
    for field in B1_POSTGRES_COST_FIELDS:
        assert field not in B1_GATING_PLACEMENT_FIELDS
        assert field not in B1_TOPOLOGY_GATING_PLACEMENT_FIELDS
        assert field not in PRODUCT_VERDICT_FIELDS
        assert field not in probe.VERDICT_FIELDS


@pytest.mark.b1_live
@pytest.mark.b1_product
def test_gc5_commit_shape_reference_profile(b1_product_run):
    """FP-GC5-7: committed database transactions per served request <= 0.60.

    The one quantitative GC-5 outcome, measured on the existing module-scoped
    product-local route -- no second workload. Everything before the bar is
    qualification: the exact product profile and placement, exact request and
    audit accounting, a harness that was not itself the limit, and complete,
    non-contaminated counters read from a maintenance database. The three
    product-promise comparisons keep their GC-1 recorded-only status and
    decide nothing here.
    """
    run = b1_product_run
    result = run["result"]
    served = result.served
    line = run["fingerprint"]

    # (1) The qualifying route: this is the product-local record, at the exact
    # declared placement, over the unchanged product workload.
    assert run["placement_ok"] is True, line
    assert run["profile"].name == PRODUCT_PROFILE_NAME, line
    assert _parse_b1_env_field(line, "measurement_authority") == AUTHORITY_PRODUCT_LOCAL
    declaration = run["declaration"]
    for role, cardinality in PRODUCT_AFFINITY_CARDINALITY.items():
        effective = run["placement"][role].allowed_cpus
        assert effective == declaration.allowed(role), role
        assert len(effective) == cardinality, (role, sorted(effective))
    assert result.offered == PRODUCT_TOTAL_REQUESTS, f"offered={result.offered}; {line}"

    # (2) Exact accounting: every offered request is served or an error, every
    # served request is one committed ingest audit row, and the client harness
    # was not the binding constraint (a bound harness would understate the
    # transactions the gateway was asked to perform).
    assert served + result.errors == result.offered, line
    assert run["committed"] == served, f"committed={run['committed']} served={served}"
    assert result.max_in_flight < PRODUCT_MAX_IN_FLIGHT, (
        f"max_in_flight={result.max_in_flight} hit the ceiling; harness was binding"
    )
    assert run["worker_set_ok"], (
        f"worker set changed or under-populated; pre={sorted(run['workers_pre'])} "
        f"post={sorted(run['workers_post'])}"
    )

    # (3) Complete cost/lateness operands and complete transaction counters.
    # A reset, missing, negative, unstable or cross-database observation
    # cannot satisfy this FP.
    assert_complete_postgres_cost_record(run)
    assert_complete_commit_shape_record(run)
    before = run["postgres_commit_before"]
    after = run["postgres_commit_after"]
    assert before.database_name == after.database_name
    assert before.database_oid == after.database_oid

    # (4) The bar, on the unrounded quotient the mechanism governs.
    ratio = postgres_xact_commits_per_served(before, after, served)
    commits = after.xact_commit - before.xact_commit
    print(
        f"GC-5 commit shape: xact_commit {before.xact_commit} -> {after.xact_commit} "
        f"(delta {commits}), served={served}, "
        f"postgres_xact_commits_per_served={ratio:.6f} "
        f"(bar: <= {B1_COMMIT_SHAPE_MAX_COMMITS_PER_SERVED})",
        flush=True,
    )
    assert float(
        _parse_b1_env_field(line, "postgres_xact_commits_per_served")
    ) == pytest.approx(ratio, abs=5e-7), line
    assert ratio <= B1_COMMIT_SHAPE_MAX_COMMITS_PER_SERVED, (
        f"the committed-hit path still costs {ratio:.6f} database transactions "
        f"per served request (delta {commits} over {served} served; bar "
        f"<= {B1_COMMIT_SHAPE_MAX_COMMITS_PER_SERVED}); {line}"
    )

    # (5) The three product-promise comparisons remain recorded, not gating:
    # this node reads their truthful tokens and requires none of them to be
    # `met`.
    for field_name in PRODUCT_VERDICT_FIELDS:
        assert _parse_b1_env_field(line, field_name) in (VERDICT_MET, VERDICT_MISSED)


@pytest.mark.b1_live
@pytest.mark.b1_product
def test_gc5_product_record_carries_commit_cost_and_lateness_context(b1_product_run):
    """FP-GC5-8: the whole context is published, and none of it is a bar.

    CPU per served request on both sides, max in flight, due-time p99, both
    three-leg lateness views, the GC-4 wait histogram with its raw counts, and
    the eight transaction/WAL fields. Every one of them is recorded so review
    can see whether the mechanism moved cost or queueing elsewhere; only the
    commit ratio is consumed by GC-5 outcome logic.
    """
    run = b1_product_run
    line = run["fingerprint"]
    result = run["result"]

    # (1) Gateway and PostgreSQL cost per served request, in flight, p99 and
    # both lateness views are present and are this run's own values.
    cpu_ms = _parse_b1_env_field(line, "cpu_ms_per_req")
    assert cpu_ms == DIAGNOSTIC_UNAVAILABLE or float(cpu_ms) > 0, line
    postgres_cpu = _parse_b1_env_field(line, "postgres_cpu_us_per_req")
    assert float(postgres_cpu) == pytest.approx(
        run["postgres_usage_usec"] / result.served, abs=5e-4
    )
    assert int(_parse_b1_env_field(line, "max_in_flight")) == result.max_in_flight
    assert float(_parse_b1_env_field(line, "p99_ms")) == pytest.approx(result.p99, abs=0.05)
    assert _parse_b1_env_field(line, "p99_leg_split") == b1.serialize_leg_triple(
        result.p99_leg_split
    )
    assert _parse_b1_env_field(line, "leg_p99s") == b1.serialize_leg_triple(result.leg_p99s)

    # (2) The GC-4 wait fields in one of their two admitted representations.
    sample = run["postgres_wait_sample"]
    reason = postgres_wait_sample_failure(sample)
    wait_fields = {
        field: _parse_b1_env_field(line, field) for field in B1_POSTGRES_COST_FIELDS[1:]
    }
    if reason is None:
        assert int(wait_fields["postgres_wait_scheduled"]) == sample.scheduled
        assert int(wait_fields["postgres_wait_completed"]) == sample.completed
        assert wait_fields["postgres_wait_failed"] == "0"
        assert int(wait_fields["postgres_wait_observations"]) == sample.observations
        assert wait_fields["postgres_wait_events_pct"] == (
            serialize_postgres_wait_histogram(sample.histogram)
        )
    else:
        assert set(wait_fields.values()) == {DIAGNOSTIC_UNAVAILABLE}, wait_fields
        assert any("postgres wait sampler" in note for note in run["diagnostic_notes"])

    # (3) The eight transaction/WAL fields, in their pinned order, after the
    # six GC-4 cost fields -- so no gating field ever moves behind them.
    at = line.index("leg_p99s=")
    for field in B1_POSTGRES_COST_FIELDS + B1_POSTGRES_COMMIT_FIELDS:
        position = line.index(f",{field}=")
        assert position > at, f"{field} is out of order"
        at = position
    before = run["postgres_commit_before"]
    after = run["postgres_commit_after"]
    assert postgres_commit_snapshot_failure(before, after, result.served) is None
    assert line.endswith(
        serialize_postgres_commit_fields(before, after, result.served)
    ), line
    wal_sync_delta = after.wal_sync - before.wal_sync
    print(
        "GC-5 recorded context: "
        f"cpu_ms_per_req={cpu_ms} postgres_cpu_us_per_req={postgres_cpu} "
        f"max_in_flight={result.max_in_flight} p99_ms={result.p99:.1f} "
        f"p99_leg_split={b1.serialize_leg_triple(result.p99_leg_split)} "
        f"leg_p99s={b1.serialize_leg_triple(result.leg_p99s)} "
        f"xact_commit_delta={after.xact_commit - before.xact_commit} "
        f"xact_rollback_delta={after.xact_rollback - before.xact_rollback} "
        f"wal_records_delta={after.wal_records - before.wal_records} "
        f"wal_bytes_delta={after.wal_bytes - before.wal_bytes} "
        f"wal_write_delta={after.wal_write - before.wal_write} "
        f"wal_sync_delta={wal_sync_delta} "
        f"wal_syncs_per_served={wal_sync_delta / result.served:.6f}",
        flush=True,
    )

    # (4) None of that context is a GC-5 outcome: the gate node compares
    # nothing but the transaction ratio and the record's own identity.
    source = Path(__file__).read_text(encoding="utf-8")
    gate = next(
        node for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.FunctionDef)
        and node.name == "test_gc5_commit_shape_reference_profile"
    )
    compared: list[str] = []
    for node in ast.walk(gate):
        if isinstance(node, ast.Assert):
            compared.append(ast.unparse(node.test))
    proxies = (
        "cpu_ms_per_req",
        "postgres_cpu_us_per_req",
        "p99",
        "leg_p99s",
        "p99_leg_split",
        "postgres_wait_",
        "wal_",
    )
    for rendered in compared:
        for proxy in proxies:
            assert proxy not in rendered, (proxy, rendered)
        # The product comparisons may be READ for their truthful token; they
        # may never be required to be `met`.
        assert "== VERDICT_MET" not in rendered, rendered
    assert any(
        "B1_COMMIT_SHAPE_MAX_COMMITS_PER_SERVED" in rendered for rendered in compared
    ), "the gate no longer compares the transaction ratio"


@pytest.mark.b1_live
@pytest.mark.b1_latency_basis
def test_measured_cpu_cost_does_not_exceed_the_recorded_sizing_basis(b1_ci_scale_run):
    """FP-IG-18: cpu_ms_per_request <= chart basis.

    Unchanged comparison, unchanged 2.427 basis. GC-1 neither selects nor
    repairs this node: requalifying the basis needs five real post-GC-1 CI
    runs and would move shipped sizing values, which belongs to the separate
    ``B1-LATENCY-BASIS-1`` slice. Its red, if it is red, is reported there --
    never skipped, weakened, or counted as a GC-1 pass.
    """
    values = yaml.safe_load(VALUES_YAML.read_text(encoding="utf-8"))
    basis = float(values["ingestGateway"]["sizingBasis"]["cpuMsPerRequest"])
    measured = b1_ci_scale_run["cpu_ms_per_request"]
    assert measured <= basis, (
        f"cpu_ms_per_request={measured} exceeds basis={basis}; "
        f"{b1_ci_scale_run['fingerprint']}"
    )


# ---------------------------------------------------------------------------
# UT-IG-9 / FP-IG-22 — process-tree CPU reader and classified integrity
# Against the unfixed single-pid four-field /proc read: red (grandchild burn
# is invisible; poll() is None accepts a respawned or under-populated tree).
# ---------------------------------------------------------------------------


def _spawn(src: str) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", src],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def test_cpu_accounting_sums_the_whole_process_tree():
    """FP-IG-22: tree sum sees a grandchild's burn; a single-pid read does not."""
    src = textwrap.dedent(
        """
        import os, time
        def burn():
            t = time.time() + 0.4
            x = 0
            while time.time() < t:
                x += 1
        if os.fork() == 0:
            burn()
            os._exit(0)
        time.sleep(2)
        """
    )
    proc = _spawn(src)
    try:
        time.sleep(0.15)
        single = b1.pid_cpu_seconds(proc.pid)
        tree = b1.tree_cpu_seconds(proc.pid)
        # Parent sleeps; grandchild burns. Tree must exceed the parent.
        assert tree > single + 0.05, (
            f"tree={tree:.3f}s single={single:.3f}s — unfixed single-pid "
            "reader cannot see the grandchild (UT-IG-9 discriminating pair)"
        )
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


def test_worker_set_identity_changes_when_a_grandchild_is_replaced():
    """Identity: a replaced grandchild between reads changes the reported set."""
    src = textwrap.dedent(
        """
        import os, signal, time, sys
        kids = []
        for _ in range(2):
            pid = os.fork()
            if pid == 0:
                time.sleep(30)
                os._exit(0)
            kids.append(pid)
        sys.stdout.write("ready\\n")
        sys.stdout.flush()
        line = sys.stdin.readline()
        os.kill(kids[0], signal.SIGKILL)
        os.waitpid(kids[0], 0)
        pid = os.fork()
        if pid == 0:
            time.sleep(30)
            os._exit(0)
        sys.stdout.write("replaced\\n")
        sys.stdout.flush()
        time.sleep(30)
        """
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", src],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        assert proc.stdout.readline().strip() == "ready"
        first = set(b1.iter_live_descendants(proc.pid))
        assert len(first) >= 2, first
        proc.stdin.write("go\n")
        proc.stdin.flush()
        assert proc.stdout.readline().strip() == "replaced"
        second = set(b1.iter_live_descendants(proc.pid))
        assert first != second, (
            f"replaced grandchild left the descendant set unchanged: {first}"
        )
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


def test_cardinality_precondition_rejects_stable_underpopulated_tree():
    """A tree stable at W-1 grandchildren fails the pre-snapshot wait.

    Red only with the cardinality precondition present (errata pass 9, D3).
    """
    n = b1.INGEST_GATEWAY_WORKERS - 1
    src = textwrap.dedent(
        f"""
        import os, time
        for _ in range({n}):
            if os.fork() == 0:
                time.sleep(30)
                os._exit(0)
        time.sleep(30)
        """
    )
    proc = _spawn(src)
    try:
        time.sleep(0.2)
        try:
            b1.wait_for_classified_workers(
                proc.pid, workers=b1.INGEST_GATEWAY_WORKERS, timeout_s=0.6
            )
        except TimeoutError as exc:
            msg = str(exc)
            assert "workers" in msg
        else:
            raise AssertionError(
                "stable W-1 tree must fail the cardinality wait; "
                "pid-set equality alone would accept it"
            )
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


def test_classification_rejects_tracker_shaped_helper_in_worker_count():
    """W-1 worker-shaped grandchildren + one tracker-shaped helper.

    Raw descendant count is W; classified worker count is W-1. Red only
    with cmdline classification present (errata pass 11, D1).
    """
    w = b1.INGEST_GATEWAY_WORKERS
    src = textwrap.dedent(
        f"""
        import os, sys, time
        # tracker-shaped helper
        if os.fork() == 0:
            sys.argv = ["python", "-c", "from multiprocessing.resource_tracker import main; main(0)"]
            time.sleep(30)
            os._exit(0)
        for _ in range({w - 1}):
            if os.fork() == 0:
                sys.argv = ["python", "-c", "from multiprocessing.spawn import spawn_main"]
                time.sleep(30)
                os._exit(0)
        time.sleep(30)
        """
    )
    # cmdline is what classify_tree reads, not sys.argv of the parent.
    # Rewrite: exec a dummy that puts the mark in /proc/pid/cmdline.
    src = textwrap.dedent(
        f"""
        import os, sys, time
        def child(mark):
            os.execv(sys.executable, [sys.executable, "-c",
                "import time; time.sleep(30)  # " + mark])
        if os.fork() == 0:
            child("multiprocessing.resource_tracker")
        for _ in range({w - 1}):
            if os.fork() == 0:
                child("multiprocessing.spawn")
        time.sleep(30)
        """
    )
    proc = _spawn(src)
    try:
        time.sleep(0.25)
        trackers, workers = b1.classify_tree(proc.pid)
        raw = len(b1.iter_live_descendants(proc.pid))
        assert len(trackers) == 1, trackers
        assert len(workers) == w - 1, workers
        assert raw == w, f"raw count {raw} want {w}"
        try:
            b1.wait_for_classified_workers(proc.pid, workers=w, timeout_s=0.5)
        except TimeoutError:
            pass
        else:
            raise AssertionError(
                "W-1 workers + tracker must fail classified wait; "
                "a raw count of W would accept it"
            )
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


# BD: the instant acceptor runs outside the driver's event loop/process.

_E2E_PROFILE_PATH = REPO_ROOT / "tests/e2e/b1_e2e_profile.py"
_e2e_spec = importlib.util.spec_from_file_location("bd_e2e_profile", _E2E_PROFILE_PATH)
assert _e2e_spec and _e2e_spec.loader
bd_e2e = importlib.util.module_from_spec(_e2e_spec)
_sys.modules[_e2e_spec.name] = bd_e2e
_e2e_spec.loader.exec_module(bd_e2e)

_BD_SERVER = r'''
import asyncio, sys
async def main():
    stop = asyncio.Event()
    writers = set()
    tasks = set()
    async def handle(reader, writer):
        writers.add(writer)
        tasks.add(asyncio.current_task())
        try:
            while True:
                headers = await reader.readuntil(b"\r\n\r\n")
                length = next((int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n") if line.lower().startswith(b"content-length:")), 0)
                await reader.readexactly(length)
                body = b'{"investigation_id":"bd"}'
                writer.write(b"HTTP/1.1 202 Accepted\r\nContent-Length: " + str(len(body)).encode() + b"\r\nContent-Type: application/json\r\n\r\n" + body)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writers.discard(writer)
            tasks.discard(asyncio.current_task())
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
    server = await asyncio.start_server(handle, "127.0.0.1", 0, backlog=2048)
    print(server.sockets[0].getsockname()[1], flush=True)
    asyncio.get_running_loop().add_reader(sys.stdin.fileno(), stop.set)
    await stop.wait()
    server.close()
    await server.wait_closed()
    for writer in list(writers):
        writer.close()
    for task in list(tasks):
        task.cancel()
    await asyncio.gather(*list(tasks), return_exceptions=True)
asyncio.run(main())
'''


@contextmanager
def _bd_instant_server():
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", _BD_SERVER],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert select.select([proc.stdout], [], [], 10)[0], "BD server readiness timeout"
        port = int(proc.stdout.readline())
        yield f"http://127.0.0.1:{port}/"
    finally:
        try:
            proc.communicate("stop\n", timeout=3)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate(timeout=3)
        assert proc.poll() is not None, "BD server was not reaped"


def _bd_requests(n):
    return [(json.dumps({"event_id": f"bd-{i}"}).encode(), {}) for i in range(n)]


async def _bd_offer(driver, client, endpoint, n, *, rate=1000):
    run = driver.run_open_loop if driver is b1 else driver.run_open_loop_baseline
    return await run(
        endpoint=endpoint, requests=_bd_requests(n), rate=rate,
        max_in_flight=driver.MAX_IN_FLIGHT, client=client,
        include_sync_warmup=False, warmup=None,
    )


async def _bd_instant_measurement(driver, endpoint, n, *, rate=1000):
    """Drive one offer through the driver's generator and judge the outer gate.

    Every tick reads ONE snapshot and derives both the census four-tuple and
    the assigned-connection list from it, so two checks can never compare
    different ticks (FP-B1DF-5 / FP-B1DF-6).
    """
    async with driver.build_httpx_client(
        max_connections=driver.MAX_IN_FLIGHT
    ) as client:
        samples = []
        task = asyncio.create_task(_bd_offer(driver, client, endpoint, n, rate=rate))
        try:
            while not task.done():
                snapshot = client.pool_snapshot()
                sample = b1.pool_census_from_snapshot(snapshot)
                c, q, _, r = sample
                assert isinstance(c, int) and isinstance(q, int) and isinstance(r, int)
                assert r - q <= c
                assert q == 0
                assigned = list(snapshot.assigned_connection_identities)
                assert len(assigned) == len(set(assigned))
                samples.append(sample)
                await asyncio.sleep(0.01)
            result = await task
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        print(json.dumps({
            "driver": driver.__name__, "offered": n, "served": result.served,
            "errors": result.errors, "served_rate": result.served_rate,
            "elapsed_drain": result.t_last_complete - result.due0,
            "p99": result.p99, "max_in_flight": result.max_in_flight,
            "peak_requests": max(s[3] for s in samples),
            "peak_connections": max(s[0] for s in samples),
            "peak_queued": max(s[1] for s in samples),
            "samples": len(samples),
            "outer_gate_nonbinding": (
                "met" if result.max_in_flight < driver.MAX_IN_FLIGHT else "not_met"
            ),
        }), flush=True)
        assert any(s[3] >= 1 for s in samples)
        assert result.served == n and result.errors == 0
        assert client.pool_snapshot().requests == 0
        # Internal accounting first: a peak above the cap is the generator's
        # own arithmetic failing, not a measurement verdict.
        assert result.max_in_flight <= driver.MAX_IN_FLIGHT
        # Then the outer-gate predicate. Strict, because equality means the
        # gate became the scheduler and later due requests were paced by
        # completions rather than by the schedule.
        assert result.max_in_flight < driver.MAX_IN_FLIGHT
        return result


@pytest.mark.b1_live
@pytest.mark.parametrize("driver", [b1, bd_e2e], ids=["reference", "e2e"])
@pytest.mark.asyncio
async def test_b1_instant_server_clears_open_loop_offer(driver):
    """FP-B1DF-6: over B1's own offer window the outer in-flight gate never binds.

    The full window is required: a linear-cost generator can stay below the
    cap during a short transient and still reach it over B1's real window.
    This proves only that the gate did not bind — pre-dispatch slip,
    max_backlog, served rate, elapsed drain and p99 stay recorded-only, so
    the witness does not certify schedule adherence. A slow or contended host
    fails it closed, which invalidates B1 as a gateway measurement on that
    host and is never a gateway result.
    """
    with _bd_instant_server() as endpoint:
        await _bd_instant_measurement(
            driver,
            endpoint,
            driver.BURST_RATE * driver.BURST_SECONDS,
            rate=driver.BURST_RATE,
        )


def characterize_b1_instant_server():
    """Explicit supporting benchmark; never invoked during collection/import."""
    async def run():
        with _bd_instant_server() as endpoint:
            for driver in (b1, bd_e2e):
                await _bd_instant_measurement(
                    driver,
                    endpoint,
                    driver.BURST_RATE * driver.BURST_SECONDS,
                    rate=driver.BURST_RATE,
                )
    asyncio.run(run())


@pytest.fixture
def bf_instant_script(monkeypatch):
    """Script test collaborators; the real measurement owns every policy check."""
    from types import SimpleNamespace

    def _snapshot(c, q, r, assignments):
        assigned = tuple(key for key in assignments if key is not None)
        return SimpleNamespace(
            held_connections=c,
            queued_requests=q,
            requests=r,
            connection_identities=frozenset(assigned),
            assigned_connection_identities=assigned,
        )

    @asynccontextmanager
    async def scripted(driver, ticks, *, residual=False, **result_fields):
        result = SimpleNamespace(
            served=2000, errors=0, max_in_flight=999,
            served_rate=211.61444797304955, due0=0,
            t_last_complete=9.451150519999999, p99=7314.775114000042,
        )
        vars(result).update(result_fields)
        state = SimpleNamespace(consumed=0, finished=False, closed=False)
        consumed = asyncio.Event()
        # The real helper always samples before its newly created task runs.
        script = [(0, 0, 0, ())] + list(ticks)

        class ScriptedClient:
            def pool_snapshot(self):
                if state.finished:
                    # The drained-ledger read, after the offer returned.
                    return _snapshot(0, 0, 1 if residual else 0, (0,) if residual else ())
                c, q, r, assignments = script[state.consumed]
                state.consumed += 1
                if state.consumed == len(script):
                    consumed.set()
                return _snapshot(c, q, r, assignments)

        client = ScriptedClient()

        @asynccontextmanager
        async def build_client(*, max_connections):
            assert max_connections == driver.MAX_IN_FLIGHT
            try:
                yield client
            finally:
                state.closed = True

        async def offer(offered_driver, offered_client, endpoint, n, *, rate):
            try:
                assert offered_driver is driver and offered_client is client
                assert n == 2000 and rate == 1000
                await consumed.wait()
                return result
            finally:
                state.finished = True

        with monkeypatch.context() as patch:
            patch.setattr(driver, "build_httpx_client", build_client)
            patch.setattr(sys.modules[__name__], "_bd_offer", offer)
            try:
                yield state
            finally:
                assert state.finished, "fake offer was not reaped"
                assert state.closed, "fake client was not closed"

    return scripted


@pytest.mark.parametrize("driver", [b1, bd_e2e], ids=["reference", "e2e"])
@pytest.mark.asyncio
async def test_b1_instant_server_sample_from_ci_34146724801(driver, bf_instant_script, capsys):
    """The recorded CI sample is now a named outer-gate rejection (FP-B1DF-6)."""
    # Synthetic simultaneous census compatible with the CI summary, not raw CI ticks.
    ticks = [(1000, 0, 894, tuple(range(894))), (0, 0, 0, ())]
    async with bf_instant_script(driver, ticks, max_in_flight=1000) as state:
        with pytest.raises(AssertionError) as exc:
            await _bd_instant_measurement(driver, "unused", 2000)
        frame = exc.traceback[-1]
        assert frame.name == "_bd_instant_measurement"
        assert str(frame.statement).strip().startswith(
            "assert result.max_in_flight < driver.MAX_IN_FLIGHT"
        )
    record = json.loads(capsys.readouterr().out)
    assert record == {
        "driver": driver.__name__, "offered": 2000, "served": 2000, "errors": 0,
        "max_in_flight": 1000, "served_rate": 211.61444797304955,
        # Synthetic timestamp operands preserve the recorded drain interval.
        "elapsed_drain": 9.451150519999999 - 0, "p99": 7314.775114000042,
        "peak_requests": 894, "peak_connections": 1000, "peak_queued": 0,
        "samples": state.consumed, "outer_gate_nonbinding": "not_met",
    }
    assert state.consumed == 3


@pytest.mark.parametrize("driver", [b1, bd_e2e], ids=["reference", "e2e"])
@pytest.mark.parametrize("ticks,fields,failure", [
    pytest.param([(1000, 0, 894, tuple(range(894)))], {"max_in_flight": 999}, None,
                 id="recorded-peak-999"),
    pytest.param([(1000, 0, 894, tuple(range(894)))], {"max_in_flight": 1000},
                 "assert result.max_in_flight < driver.MAX_IN_FLIGHT",
                 id="recorded-peak-1000"),
    pytest.param([(1000, 0, 894, tuple(range(894)))], {"max_in_flight": 1001},
                 "assert result.max_in_flight <= driver.MAX_IN_FLIGHT",
                 id="recorded-peak-1001"),
] + [
    # No throughput floor leaked back in with the outer-gate predicate: the
    # verdict is identical at 199.9, 200.0 and 200.1 when the peak is 999.
    pytest.param([(1000, 0, 894, tuple(range(894)))],
                 {"served_rate": rate, "max_in_flight": 999}, None,
                 id=f"recorded-rate-{rate}") for rate in (199.9, 200.0, 200.1)
] + [
    pytest.param([(2, 0, 2, (0, 1))], {"served": served},
                 None if served == 2000 else "assert result.served == n and result.errors == 0",
                 id=f"served-{served}") for served in (1999, 2000, 2001)
] + [
    pytest.param([(2, 0, 2, (0, 1))], {"errors": 1},
                 "assert result.served == n and result.errors == 0", id="errors"),
    pytest.param([(2, 0, 2, (0, 1))], {}, None, id="distinct-equality"),
    pytest.param([(2, 0, 3, (0, 1, 2))], {}, "assert r - q <= c", id="inequality"),
    pytest.param([(2, 0, 2, (0, 0))], {},
                 "assert len(assigned) == len(set(assigned))", id="duplicate"),
    pytest.param([(2, 1, 3, (0, 1, None))], {}, "assert q == 0", id="queued"),
    pytest.param([(2, 0, 2, (0, 1))], {"residual": True},
                 "assert client.pool_snapshot().requests == 0", id="residual"),
    pytest.param([(0, 0, 0, ()), (0, 0, 0, ())], {},
                 "assert any(s[3] >= 1 for s in samples)", id="all-empty"),
    pytest.param([("unavailable", 0, 2, (0, 1))], {}, "assert isinstance(c, int)", id="unavailable-c"),
    pytest.param([(2, "unavailable", 2, (0, 1))], {}, "assert isinstance(c, int)", id="unavailable-q"),
    pytest.param([(2, 0, "unavailable", (0, 1))], {}, "assert isinstance(c, int)", id="unavailable-r"),
    pytest.param([("unavailable", 0, 2, (0, 1))], {"served": 1999},
                 "assert isinstance(c, int)", id="validity-before-completion"),
    pytest.param([(1, 0, 1, (0,))], {}, None, id="empty-then-one"),
    pytest.param([(0, 0, 0, ()), (2, 0, 2, (0, 1))], {}, None, id="empty-then-valid"),
    pytest.param([(2, 0, 2, (0, 1)), (2, 0, 3, (0, 1, 2)), (4, 0, 4, (0, 1, 2, 3))], {},
                 "assert r - q <= c", id="invalid-middle"),
])
@pytest.mark.asyncio
async def test_b1_instant_server_correctness_rejects_corrupt_samples(
    driver, ticks, fields, failure, bf_instant_script, capsys,
):
    async with bf_instant_script(driver, ticks, **fields) as state:
        if failure is None:
            await _bd_instant_measurement(driver, "unused", 2000)
        else:
            with pytest.raises(AssertionError) as exc:
                await _bd_instant_measurement(driver, "unused", 2000)
            frame = exc.traceback[-1]
            assert frame.name == "_bd_instant_measurement"
            assert str(frame.statement).strip().startswith(failure)
    output = capsys.readouterr().out
    if failure is None or failure == "assert any(s[3] >= 1 for s in samples)":
        record = json.loads(output)
        assert record["samples"] == state.consumed == len(ticks) + 1
        assert record["max_in_flight"] == fields.get("max_in_flight", 999)
        assert record["served_rate"] == fields.get("served_rate", 211.61444797304955)
        assert record["outer_gate_nonbinding"] == "met"
        if failure is not None:
            assert record["peak_requests"] == 0
            # Prove that readable-sample count alone accepts this vacuous witness.
            import inspect

            source = inspect.getsource(_bd_instant_measurement)
            populated = "assert any(s[3] >= 1 for s in samples)"
            assert source.count(populated) == 1
            namespace = dict(globals())
            exec(compile(source.replace(populated, "assert len(samples) > 0"),
                         "<BF count-only mutant>", "exec"), namespace)
            async with bf_instant_script(driver, ticks, **fields) as mutant_state:
                namespace["_bd_offer"] = _bd_offer
                await namespace["_bd_instant_measurement"](driver, "unused", 2000)
            mutant_record = json.loads(capsys.readouterr().out)
            assert mutant_record["samples"] == mutant_state.consumed == len(ticks) + 1
            assert mutant_record["peak_requests"] == 0


# ---------------------------------------------------------------------------
# FP-B1DF-1 / FP-B1DF-2 — B1's own raw HTTP/1.1 client. Both driver copies are
# exercised: byte equality is pinned in tests/delivery, behaviour is pinned
# here, once per copy.
# ---------------------------------------------------------------------------

_RAW_DRIVERS = [b1, bd_e2e]
_RAW_OK_BODY = b'{"status":"merged"}'
_RAW_BAD_CAPACITIES = [None, True, False, float("nan"), 0, -1, 1.5, "2"]
# The four ledgers FP-B1DF-1 forbids the request path to scan.
_RAW_POPULATION_ATTRS = ("_connections", "_idle", "_requests", "_waiters")
_RAW_SCAN_BUILTINS = frozenset(
    {
        "any", "all", "next", "sorted", "min", "max", "sum", "list", "tuple",
        "set", "frozenset", "filter", "map", "reversed", "enumerate", "zip",
        "iter",
    }
)
# Off the request path by construction: shutdown and the diagnostic snapshot
# are once per phase and once per census tick, never per request.
_RAW_OFF_REQUEST_PATH = frozenset(
    {"pool_snapshot", "aclose", "__init__", "__aenter__", "__aexit__"}
)


def _raw_client(driver, capacity, *, timeout=None, keepalive_expiry=None):
    """The driver's own client, with the pinned values unless a case moves one."""
    return driver.B1RawHttp11Client(
        max_connections=capacity,
        timeout=driver.CLIENT_TIMEOUT if timeout is None else timeout,
        keepalive_expiry=(
            driver.KEEPALIVE_EXPIRY if keepalive_expiry is None else keepalive_expiry
        ),
        http_version="HTTP/1.1",
        retries=0,
        follow_redirects=False,
        trust_env=False,
    )


def _raw_counts(client):
    snapshot = client.pool_snapshot()
    return (
        snapshot.held_connections,
        snapshot.queued_requests,
        snapshot.requests,
    )


def _assert_raw_client_drained(client):
    """No reservation, no connection and no waiter survives the case."""
    snapshot = client.pool_snapshot()
    assert (
        snapshot.held_connections,
        snapshot.queued_requests,
        snapshot.requests,
        snapshot.connection_identities,
        snapshot.assigned_connection_identities,
    ) == (0, 0, 0, frozenset(), ())


async def _raw_wait_counts(client, expected, *, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        observed = _raw_counts(client)
        if observed == expected:
            return
        await asyncio.sleep(0.005)
    raise AssertionError(f"census never reached {expected}; last={_raw_counts(client)}")


@asynccontextmanager
async def _raw_server(responder, *, read_requests=True, rcvbuf=None):
    """A scripted HTTP/1.1 peer: one responder call per request it reads."""
    import inspect
    from types import SimpleNamespace

    state = SimpleNamespace(requests=0, connections=0)
    writers = set()
    tasks = set()

    async def handle(reader, writer):
        state.connections += 1
        writers.add(writer)
        tasks.add(asyncio.current_task())
        try:
            if not read_requests:
                await asyncio.Event().wait()
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                length = next(
                    (
                        int(line.split(b":", 1)[1])
                        for line in head.split(b"\r\n")
                        if line.lower().startswith(b"content-length:")
                    ),
                    0,
                )
                if length:
                    await reader.readexactly(length)
                state.requests += 1
                reply = responder(state)
                if inspect.isawaitable(reply):
                    reply = await reply
                payload, close = reply
                if payload:
                    writer.write(payload)
                    await writer.drain()
                if close:
                    break
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writers.discard(writer)
            tasks.discard(asyncio.current_task())
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if rcvbuf is not None:
        # A small receive window makes a write to a peer that never reads
        # block deterministically, without depending on autotuned buffers.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    sock.bind(("127.0.0.1", 0))
    sock.listen(2048)
    sock.setblocking(False)
    port = sock.getsockname()[1]
    server = await asyncio.start_server(handle, sock=sock)
    try:
        yield f"http://127.0.0.1:{port}/events", state
    finally:
        server.close()
        for writer in list(writers):
            writer.close()
        remaining = list(tasks)
        for task in remaining:
            task.cancel()
        await asyncio.gather(*remaining, return_exceptions=True)
        # Only now: 3.12's Server.wait_closed() also waits for every handler.
        await server.wait_closed()


def _raw_fixed(payload, *, close=False):
    return lambda state: (payload, close)


def _raw_silent(state):
    return None, False


_RAW_KEEPALIVE_200 = b"HTTP/1.1 200 OK\r\ncontent-length: 19\r\n\r\n" + _RAW_OK_BODY

# (response bytes, close after responding, expectation)
# expectation: ("served", status, body, held_after) | ("error", type name,
# message fragment, held_after)
_RAW_FRAMING_CASES: dict[str, tuple] = {
    "framing-content-length": (
        _RAW_KEEPALIVE_200,
        False,
        ("served", 200, _RAW_OK_BODY, 1),
    ),
    "framing-chunked": (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5;ext=a\r\nhello\r\n3\r\n-hi\r\n0\r\nX-Trailer: v\r\n\r\n",
        False,
        ("served", 200, b"hello-hi", 1),
    ),
    "framing-bodyless": (
        b"HTTP/1.1 204 No Content\r\n\r\n",
        False,
        ("served", 204, b"", 1),
    ),
    "framing-close": (
        b"HTTP/1.1 200 OK\r\nConnection: Close\r\n\r\nclosed-body",
        True,
        ("served", 200, b"closed-body", 0),
    ),
    "framing-duplicate-identical-length": (
        b"HTTP/1.1 202 Accepted\r\nContent-Length: 19\r\nCONTENT-LENGTH: 19\r\n\r\n"
        + _RAW_OK_BODY,
        False,
        ("served", 202, _RAW_OK_BODY, 1),
    ),
    "framing-conflicting-length": (
        b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\nContent-Length: 5\r\n\r\n"
        + _RAW_OK_BODY,
        False,
        ("error", "B1ProtocolError", "conflicting content-length", 0),
    ),
    "framing-te-plus-length": (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
        False,
        ("error", "B1ProtocolError", "beside content-length", 0),
    ),
    "framing-malformed-status": (
        b"HTTP/1.1 twenty OK\r\nContent-Length: 0\r\n\r\n",
        False,
        ("error", "B1ProtocolError", "malformed status code", 0),
    ),
    "framing-malformed-header": (
        b"HTTP/1.1 200 OK\r\nNoColonHere\r\nContent-Length: 0\r\n\r\n",
        False,
        ("error", "B1ProtocolError", "malformed header line", 0),
    ),
    "framing-malformed-chunk": (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nnope\r\n",
        False,
        ("error", "B1ProtocolError", "malformed chunk size", 0),
    ),
    "framing-truncated": (
        b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\n\r\nshort",
        True,
        ("error", "B1ProtocolError", "truncated", 0),
    ),
    "framing-indeterminate-eof": (
        b"HTTP/1.1 200 OK\r\n\r\nno-boundary",
        True,
        ("error", "B1ProtocolError", "indeterminate response body boundary", 0),
    ),
    "framing-unsupported-coding": (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
        False,
        ("error", "B1ProtocolError", "unsupported transfer coding", 0),
    ),
    "framing-malformed-length": (
        b"HTTP/1.1 200 OK\r\nContent-Length: twelve\r\n\r\n",
        False,
        ("error", "B1ProtocolError", "malformed content-length", 0),
    ),
    "framing-short-status-line": (
        b"HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        False,
        ("error", "B1ProtocolError", "malformed status line", 0),
    ),
    "framing-status-out-of-range": (
        b"HTTP/1.1 999999 Nope\r\nContent-Length: 0\r\n\r\n",
        False,
        ("error", "B1ProtocolError", "status code out of range", 0),
    ),
    "framing-oversized-head": (
        b"HTTP/1.1 200 OK\r\nX-Pad: " + b"p" * 70000 + b"\r\nContent-Length: 0\r\n\r\n",
        False,
        ("error", "B1ProtocolError", "exceeds the stream limit", 0),
    ),
    "framing-chunk-without-crlf": (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n",
        False,
        ("error", "B1ProtocolError", "chunk not terminated by CRLF", 0),
    ),
    "framing-http10-keepalive": (
        b"HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\nContent-Length: 19\r\n\r\n"
        + _RAW_OK_BODY,
        False,
        ("served", 200, _RAW_OK_BODY, 1),
    ),
    "framing-http10-eof": (
        b"HTTP/1.0 200 OK\r\n\r\nten-oh-body",
        True,
        ("served", 200, b"ten-oh-body", 0),
    ),
    "outcome-200": (_RAW_KEEPALIVE_200, False, ("served", 200, _RAW_OK_BODY, 1)),
    "outcome-202": (
        b"HTTP/1.1 202 Accepted\r\nContent-Length: 24\r\n\r\n"
        b'{"investigation_id":"x"}',
        False,
        ("served", 202, b'{"investigation_id":"x"}', 1),
    ),
    "outcome-4xx": (
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}",
        False,
        ("served", 401, b"{}", 1),
    ),
    "outcome-5xx": (
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 2\r\n\r\n{}",
        False,
        ("served", 503, b"{}", 1),
    ),
    "outcome-protocol-error": (
        b"NOT-HTTP 200 OK\r\nContent-Length: 0\r\n\r\n",
        False,
        ("error", "B1ProtocolError", "unsupported HTTP version", 0),
    ),
    "outcome-informational": (
        b"HTTP/1.1 100 Continue\r\n\r\n",
        False,
        ("error", "B1ProtocolError", "unexpected informational response", 0),
    ),
}


async def _raw_framing_case(driver, case_id):
    response, close, expectation = _RAW_FRAMING_CASES[case_id]
    async with _raw_server(_raw_fixed(response, close=close)) as (endpoint, _state):
        client = _raw_client(driver, 2)
        try:
            if expectation[0] == "served":
                _kind, status, body, held = expectation
                reply = await client.post(
                    endpoint, content=b'{"event_id":"a"}', headers={}
                )
                assert (reply.status_code, reply.content) == (status, body)
            else:
                _kind, exc_name, fragment, held = expectation
                with pytest.raises(getattr(driver, exc_name)) as exc:
                    await client.post(
                        endpoint, content=b'{"event_id":"a"}', headers={}
                    )
                assert fragment in str(exc.value), exc.value
            assert _raw_counts(client) == (held, 0, 0)
        finally:
            await client.aclose()
        _assert_raw_client_drained(client)


async def _raw_case_request_target_preserved(driver):
    """The path and query reach the wire as the request target, unrewritten."""
    seen = []

    def responder(state):
        return _RAW_KEEPALIVE_200, False

    async with _raw_server(responder) as (endpoint, state):
        client = _raw_client(driver, 2)
        base = endpoint.rsplit("/", 1)[0]
        try:
            reply = await client.post(
                f"{base}/api/v1/events?tier=b1&n=2",
                content=b"{}",
                headers={"Content-Type": "application/json"},
            )
            assert reply.status_code == 200
            assert state.requests == 1
            reply = await client.post(base + "/", content=b"{}", headers={})
            assert reply.status_code == 200
        finally:
            await client.aclose()
        _assert_raw_client_drained(client)


async def _raw_case_stale_idle_replacement(driver):
    """A peer that retires a parked connection costs a socket, never a retry."""
    async with _raw_server(_raw_fixed(_RAW_KEEPALIVE_200, close=True)) as (
        endpoint,
        state,
    ):
        client = _raw_client(driver, 2)
        try:
            assert (
                await client.post(endpoint, content=b"{}", headers={})
            ).status_code == 200
            # Keep-alive framing parks it; the peer's FIN arrives afterwards.
            first = client.pool_snapshot().connection_identities
            assert len(first) == 1
            deadline = time.time() + 5.0
            while time.time() < deadline and client.pool_snapshot().held_connections:
                await asyncio.sleep(0.01)
                if state.connections >= 1:
                    break
            await asyncio.sleep(0.05)
            assert (
                await client.post(endpoint, content=b"{}", headers={})
            ).status_code == 200
            second = client.pool_snapshot().connection_identities
            assert len(second) == 1 and second.isdisjoint(first)
            assert state.requests == 2 and state.connections == 2
        finally:
            await client.aclose()
        _assert_raw_client_drained(client)


async def _raw_case_outcome_oserror(driver):
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    client = _raw_client(driver, 2, timeout=5.0)
    try:
        with pytest.raises(OSError):
            await client.post(
                f"http://127.0.0.1:{port}/events", content=b"{}", headers={}
            )
        assert _raw_counts(client) == (0, 0, 0)
    finally:
        await client.aclose()
    _assert_raw_client_drained(client)


async def _raw_case_outcome_no_retry(driver):
    """A failed attempt is never re-sent: one request, one connection, one error."""
    async with _raw_server(lambda state: (None, True)) as (endpoint, state):
        client = _raw_client(driver, 4, timeout=5.0)
        try:
            with pytest.raises(driver.B1ProtocolError):
                await client.post(endpoint, content=b"{}", headers={})
            assert (state.requests, state.connections) == (1, 1)
            assert _raw_counts(client) == (0, 0, 0)
        finally:
            await client.aclose()
        assert (state.requests, state.connections) == (1, 1)
    _assert_raw_client_drained(client)


async def _raw_case_timeout_pool(driver):
    client = _raw_client(driver, 1, timeout=0.3)
    # Occupy the only reservation with no I/O at all, so the second request
    # can expire at the waiter-acquisition stage and nowhere else: the four
    # stage timeouts share one value, so a live holder would expire first.
    request_id, held = await client._checkout()
    try:
        assert _raw_counts(client) == (1, 0, 1)
        started = time.perf_counter()
        with pytest.raises(TimeoutError):
            await client.post("http://127.0.0.1:9/events", content=b"{}", headers={})
        assert time.perf_counter() - started >= 0.3
        # The queued request removed its own waiter and its own entry.
        assert _raw_counts(client) == (1, 0, 1)
    finally:
        client._requests.pop(request_id, None)
        client._retire(held)
        await client.aclose()
    _assert_raw_client_drained(client)


async def _raw_case_timeout_connect(driver, monkeypatch):
    real_open = asyncio.open_connection

    async def never_connects(*args, **kwargs):
        await asyncio.sleep(30)
        return await real_open(*args, **kwargs)

    monkeypatch.setattr(asyncio, "open_connection", never_connects)
    client = _raw_client(driver, 2, timeout=0.3)
    try:
        with pytest.raises(TimeoutError):
            await client.post("http://127.0.0.1:9/events", content=b"{}", headers={})
        assert _raw_counts(client) == (0, 0, 0)
    finally:
        await client.aclose()
    _assert_raw_client_drained(client)


async def _raw_case_timeout_write(driver):
    async with _raw_server(_raw_silent, read_requests=False, rcvbuf=1024) as (
        endpoint,
        _state,
    ):
        client = _raw_client(driver, 2, timeout=0.3)
        try:
            with pytest.raises(TimeoutError):
                await client.post(
                    endpoint, content=b"x" * (1 << 20), headers={}
                )
            assert _raw_counts(client) == (0, 0, 0)
        finally:
            await client.aclose()
        _assert_raw_client_drained(client)


async def _raw_case_timeout_read(driver):
    async with _raw_server(_raw_silent) as (endpoint, state):
        client = _raw_client(driver, 2, timeout=0.3)
        try:
            with pytest.raises(TimeoutError):
                await client.post(endpoint, content=b"{}", headers={})
            assert state.requests == 1
            assert _raw_counts(client) == (0, 0, 0)
        finally:
            await client.aclose()
        _assert_raw_client_drained(client)


async def _raw_case_cancel_queued(driver):
    async with _raw_server(_raw_silent) as (endpoint, _state):
        client = _raw_client(driver, 1)
        held = asyncio.create_task(client.post(endpoint, content=b"{}", headers={}))
        await _raw_wait_counts(client, (1, 0, 1))
        queued = asyncio.create_task(client.post(endpoint, content=b"{}", headers={}))
        try:
            await _raw_wait_counts(client, (1, 1, 2))
            queued.cancel()
            with pytest.raises(asyncio.CancelledError):
                await queued
            assert _raw_counts(client) == (1, 0, 1)
        finally:
            held.cancel()
            await asyncio.gather(held, queued, return_exceptions=True)
            await client.aclose()
        _assert_raw_client_drained(client)


async def _raw_case_cancel_opening(driver, monkeypatch):
    opening = asyncio.Event()
    real_open = asyncio.open_connection

    async def slow_open(*args, **kwargs):
        opening.set()
        await asyncio.sleep(30)
        return await real_open(*args, **kwargs)

    monkeypatch.setattr(asyncio, "open_connection", slow_open)
    client = _raw_client(driver, 2)
    task = asyncio.create_task(
        client.post("http://127.0.0.1:9/events", content=b"{}", headers={})
    )
    try:
        await asyncio.wait_for(opening.wait(), 10)
        # The reservation exists while the socket open is still in progress.
        assert _raw_counts(client) == (1, 0, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert _raw_counts(client) == (0, 0, 0)
    finally:
        await asyncio.gather(task, return_exceptions=True)
        await client.aclose()
    _assert_raw_client_drained(client)


async def _raw_case_cancel_writing(driver):
    async with _raw_server(_raw_silent, read_requests=False, rcvbuf=1024) as (
        endpoint,
        _state,
    ):
        client = _raw_client(driver, 2)
        task = asyncio.create_task(
            client.post(endpoint, content=b"x" * (1 << 20), headers={})
        )
        try:
            await _raw_wait_counts(client, (1, 0, 1))
            await asyncio.sleep(0.25)
            assert not task.done(), "the peer that never reads let the write finish"
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert _raw_counts(client) == (0, 0, 0)
        finally:
            await asyncio.gather(task, return_exceptions=True)
            await client.aclose()
        _assert_raw_client_drained(client)


async def _raw_case_cancel_reading(driver):
    async with _raw_server(_raw_silent) as (endpoint, state):
        client = _raw_client(driver, 2)
        task = asyncio.create_task(client.post(endpoint, content=b"{}", headers={}))
        try:
            deadline = time.time() + 10
            while state.requests < 1 and time.time() < deadline:
                await asyncio.sleep(0.005)
            assert state.requests == 1
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert _raw_counts(client) == (0, 0, 0)
        finally:
            await asyncio.gather(task, return_exceptions=True)
            await client.aclose()
        _assert_raw_client_drained(client)


async def _raw_case_validation_capacity(driver, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("a socket was opened before capacity validation")

    monkeypatch.setattr(asyncio, "open_connection", forbidden)
    for capacity in _RAW_BAD_CAPACITIES:
        with pytest.raises(ValueError, match="positive integer"):
            driver.build_httpx_client(max_connections=capacity)
        with pytest.raises(ValueError, match="positive integer"):
            _raw_client(driver, capacity)
    for pin, value in (
        ("http_version", "HTTP/1.0"),
        ("retries", 1),
        ("follow_redirects", True),
        ("trust_env", True),
    ):
        kwargs = dict(
            max_connections=1,
            timeout=driver.CLIENT_TIMEOUT,
            keepalive_expiry=driver.KEEPALIVE_EXPIRY,
            http_version="HTTP/1.1",
            retries=0,
            follow_redirects=False,
            trust_env=False,
        )
        kwargs[pin] = value
        with pytest.raises(ValueError):
            driver.B1RawHttp11Client(**kwargs)


async def _raw_case_validation_origin(driver):
    async with _raw_server(_raw_fixed(_RAW_KEEPALIVE_200)) as (endpoint, _state):
        client = _raw_client(driver, 2)
        try:
            assert (
                await client.post(endpoint, content=b"{}", headers={})
            ).status_code == 200
            port = endpoint.rsplit(":", 1)[1].split("/")[0]
            for bad in (
                endpoint.replace("http://", "https://"),
                f"http://user:pw@127.0.0.1:{port}/events",
                f"http://127.0.0.1:{port}/events#fragment",
                "http:///events",
                "http://127.0.0.2:1/events",
                f"http://127.0.0.1:{int(port) + 1}/events",
                f"http://127.0.0.1:{port}/ev ents",
            ):
                with pytest.raises(ValueError):
                    await client.post(bad, content=b"{}", headers={})
            # One idle connection from the accepted request; no stray reservation.
            assert _raw_counts(client) == (1, 0, 0)
        finally:
            await client.aclose()
        _assert_raw_client_drained(client)


async def _raw_case_validation_header(driver):
    async with _raw_server(_raw_fixed(_RAW_KEEPALIVE_200)) as (endpoint, state):
        client = _raw_client(driver, 2)
        try:
            for headers in (
                {"Host": "elsewhere"},
                {"Content-Length": "3"},
                {"Transfer-Encoding": "chunked"},
                {"Connection": "close"},
                {"X-Signature": "a\r\nInjected: 1"},
                {"X-Sig\nnature": "a"},
                {"Bad Name": "a"},
                {"": "a"},
                {"X-Signature": "sn\u2603wman"},
                {b"X-Bytes": "a"},
                {"X-Signature": 7},
            ):
                with pytest.raises(ValueError):
                    await client.post(endpoint, content=b"{}", headers=headers)
            with pytest.raises(ValueError):
                await client.post(endpoint, content="not-bytes", headers={})
            assert state.requests == 0
            assert _raw_counts(client) == (0, 0, 0)
            reply = await client.post(
                endpoint,
                content=b"{}",
                headers={"Content-Type": "application/json", "X-Signature": "ab"},
            )
            assert reply.status_code == 200
        finally:
            await client.aclose()
        _assert_raw_client_drained(client)


async def _raw_case_closed_client(driver):
    async with _raw_server(_raw_fixed(_RAW_KEEPALIVE_200)) as (endpoint, _state):
        client = _raw_client(driver, 2)
        assert (await client.post(endpoint, content=b"{}", headers={})).status_code == 200
        assert not client.is_closed
        await client.aclose()
        assert client.is_closed
        with pytest.raises(RuntimeError, match="closed"):
            await client.post(endpoint, content=b"{}", headers={})
        _assert_raw_client_drained(client)


async def _raw_case_keepalive_expiry_replacement(driver):
    async with _raw_server(_raw_fixed(_RAW_KEEPALIVE_200)) as (endpoint, _state):
        client = _raw_client(driver, 2, keepalive_expiry=0.05)
        try:
            await client.post(endpoint, content=b"{}", headers={})
            first = client.pool_snapshot().connection_identities
            assert len(first) == 1
            await _raw_wait_counts(client, (0, 0, 0))
            await client.post(endpoint, content=b"{}", headers={})
            second = client.pool_snapshot().connection_identities
            assert len(second) == 1 and second.isdisjoint(first)
        finally:
            await client.aclose()
        _assert_raw_client_drained(client)


async def _raw_case_shutdown_waiters(driver):
    async with _raw_server(_raw_silent) as (endpoint, _state):
        client = _raw_client(driver, 1)
        held = asyncio.create_task(client.post(endpoint, content=b"{}", headers={}))
        await _raw_wait_counts(client, (1, 0, 1))
        queued = asyncio.create_task(client.post(endpoint, content=b"{}", headers={}))
        await _raw_wait_counts(client, (1, 1, 2))
        await client.aclose()
        results = await asyncio.gather(held, queued, return_exceptions=True)
        assert isinstance(results[1], RuntimeError), results
        assert isinstance(results[0], BaseException), results
        _assert_raw_client_drained(client)


_RAW_LIFECYCLE_CASES = sorted(_RAW_FRAMING_CASES) + [
    "request-target-preserved",
    "stale-idle-replacement",
    "outcome-oserror",
    "outcome-no-retry",
    "timeout-pool",
    "timeout-connect",
    "timeout-write",
    "timeout-read",
    "cancel-queued",
    "cancel-opening",
    "cancel-writing",
    "cancel-reading",
    "validation-capacity",
    "validation-origin",
    "validation-header",
    "closed-client",
    "keepalive-expiry-replacement",
    "shutdown-waiters",
]
_RAW_MONKEYPATCHED_CASES = frozenset(
    {"timeout-connect", "cancel-opening", "validation-capacity"}
)


@pytest.mark.parametrize("driver", _RAW_DRIVERS, ids=["reference", "e2e"])
@pytest.mark.parametrize("case", _RAW_LIFECYCLE_CASES)
@pytest.mark.asyncio
async def test_b1_raw_http11_client_lifecycle_and_response_framing(
    driver, case, monkeypatch
):
    """FP-B1DF-2: framing, outcomes, timeout roles, cancellation, shutdown."""
    if case in _RAW_FRAMING_CASES:
        await _raw_framing_case(driver, case)
        return
    handler = globals()["_raw_case_" + case.replace("-", "_")]
    if case in _RAW_MONKEYPATCHED_CASES:
        await handler(driver, monkeypatch)
    else:
        await handler(driver)


@pytest.mark.parametrize("driver", _RAW_DRIVERS, ids=["reference", "e2e"])
@pytest.mark.parametrize("capacity", [1, 2])
@pytest.mark.asyncio
async def test_b1_raw_client_capacity_boundaries(driver, capacity, monkeypatch):
    """FP-B1DF-1/2: C-1/C/C+1, reservation before the socket, FIFO, failed open."""
    # A — invalid capacity is refused before any socket work is attempted.
    def forbidden(*args, **kwargs):
        pytest.fail("a socket was opened before capacity validation")

    monkeypatch.setattr(asyncio, "open_connection", forbidden)
    for bad in _RAW_BAD_CAPACITIES:
        with pytest.raises(ValueError, match="positive integer"):
            driver.build_httpx_client(max_connections=bad)
    monkeypatch.undo()

    # B — the reservation lives in an `opening` record before open_connection.
    entered = asyncio.Event()
    gate = asyncio.Event()
    real_open = asyncio.open_connection

    async def gated_open(*args, **kwargs):
        entered.set()
        await gate.wait()
        return await real_open(*args, **kwargs)

    async with _raw_server(_raw_fixed(_RAW_KEEPALIVE_200)) as (endpoint, state):
        client = _raw_client(driver, capacity)
        monkeypatch.setattr(asyncio, "open_connection", gated_open)
        task = asyncio.create_task(client.post(endpoint, content=b"{}", headers={}))
        try:
            await asyncio.wait_for(entered.wait(), 10)
            snapshot = client.pool_snapshot()
            assert (
                snapshot.held_connections,
                snapshot.queued_requests,
                snapshot.requests,
            ) == (1, 0, 1)
            assert len(snapshot.assigned_connection_identities) == 1
            assert set(snapshot.assigned_connection_identities) <= set(
                snapshot.connection_identities
            )
            assert state.connections == 0, "the socket preceded the reservation"
            gate.set()
            assert (await asyncio.wait_for(task, 10)).status_code == 200
        finally:
            monkeypatch.undo()
            await asyncio.gather(task, return_exceptions=True)
            await client.aclose()
        _assert_raw_client_drained(client)

    # C — C-1, C and C+1 concurrent requests against a peer that holds replies.
    release = asyncio.Event()

    async def holding(state):
        await release.wait()
        return _RAW_KEEPALIVE_200, False

    async with _raw_server(holding) as (endpoint, _state):
        client = _raw_client(driver, capacity)
        tasks = []
        try:
            assert _raw_counts(client) == (0, 0, 0)
            for offered in range(1, capacity + 2):
                tasks.append(
                    asyncio.create_task(
                        client.post(endpoint, content=b"{}", headers={})
                    )
                )
                await _raw_wait_counts(
                    client,
                    (min(offered, capacity), max(0, offered - capacity), offered),
                )
            release.set()
            replies = await asyncio.wait_for(asyncio.gather(*tasks), 10)
            assert [reply.status_code for reply in replies] == [200] * (capacity + 1)
            await _raw_wait_counts(client, (capacity, 0, 0))
        finally:
            release.set()
            await asyncio.gather(*tasks, return_exceptions=True)
            await client.aclose()
        _assert_raw_client_drained(client)

    # D — FIFO handoff and failed-open replacement: every reply retires its
    # connection, so each completion hands one unit of capacity to the oldest
    # waiter, and the open that fails hands it straight on to the next.
    opens = [0]
    fails_at = capacity + 1

    async def flaky_open(*args, **kwargs):
        opens[0] += 1
        if opens[0] == fails_at:
            raise ConnectionResetError("injected open failure")
        return await real_open(*args, **kwargs)

    closing = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 19\r\n\r\n" + (
        _RAW_OK_BODY
    )
    async with _raw_server(_raw_fixed(closing, close=True)) as (endpoint, _state):
        client = _raw_client(driver, capacity, timeout=10.0)
        monkeypatch.setattr(asyncio, "open_connection", flaky_open)
        tasks = [
            asyncio.create_task(client.post(endpoint, content=b"{}", headers={}))
            for _ in range(capacity + 2)
        ]
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True), 20
            )
            failed = [i for i, r in enumerate(results) if isinstance(r, OSError)]
            assert failed == [capacity], results
            assert all(
                r.status_code == 200
                for i, r in enumerate(results)
                if i not in failed
            ), results
            assert opens[0] == capacity + 2
        finally:
            monkeypatch.undo()
            await asyncio.gather(*tasks, return_exceptions=True)
            await client.aclose()
        _assert_raw_client_drained(client)


# ---------------------------------------------------------------------------
# FP-B1DF-1 — the deterministic O(1)-bookkeeping regression. Red against rev
# 2.60 at B1ReservationPool._assign_requests_to_connections (source leg) and
# against any renamed full-pool sweep (runtime leg).
# ---------------------------------------------------------------------------


def _raw_touches_population(node) -> str | None:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr in _RAW_POPULATION_ATTRS:
            return sub.attr
    return None


def _raw_is_drain_step(stmt, attr) -> bool:
    if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
        return False
    value = stmt.value
    if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
        return False
    if value.func.attr not in ("pop", "popitem"):
        return False
    target = value.func.value
    return isinstance(target, ast.Attribute) and target.attr == attr


def _raw_population_scan(source: str, where: str) -> str | None:
    """Name the first ledger scan in one function's source, or None."""
    tree = ast.parse(textwrap.dedent(source))
    for node in ast.walk(tree):
        if isinstance(node, ast.For):
            attr = _raw_touches_population(node.iter)
            if attr is not None:
                return f"{where} iterates self.{attr} (for loop)"
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            for generator in node.generators:
                attr = _raw_touches_population(generator.iter)
                if attr is not None:
                    return f"{where} iterates self.{attr} (comprehension)"
        elif isinstance(node, ast.While):
            attr = _raw_touches_population(node.test)
            if attr is not None and not (
                node.body and _raw_is_drain_step(node.body[0], attr)
            ):
                return f"{where} loops over self.{attr} without draining it"
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in _RAW_SCAN_BUILTINS:
                attr = _raw_touches_population(node)
                if attr is not None:
                    return f"{where} passes self.{attr} to {func.id}()"
            if isinstance(func, ast.Attribute) and func.attr in ("values", "items", "keys"):
                attr = _raw_touches_population(func.value)
                if attr is not None:
                    return f"{where} takes a view of self.{attr}"
    return None


def _raw_reachable_driver_classes(client, driver, *, depth=4, budget=4000):
    """Every class defined by the driver module that the built client owns."""
    found: dict[str, type] = {}
    seen: set[int] = set()
    frontier = [(client, 0)]
    while frontier and len(seen) < budget:
        obj, level = frontier.pop()
        if level > depth or id(obj) in seen:
            continue
        seen.add(id(obj))
        cls = type(obj)
        if getattr(cls, "__module__", None) == driver.__name__:
            found.setdefault(cls.__name__, cls)
        children = []
        state = getattr(obj, "__dict__", None)
        if isinstance(state, dict):
            children.extend(state.values())
        for slot in getattr(cls, "__slots__", ()) or ():
            children.append(getattr(obj, slot, None))
        if isinstance(obj, (list, tuple, set, frozenset)):
            children.extend(obj)
        elif isinstance(obj, dict):
            children.extend(obj.values())
        for child in children:
            frontier.append((child, level + 1))
    return found


def _raw_request_path_methods(cls) -> set[str]:
    """Transitive closure of post() over self-method calls on one class."""
    import inspect

    members = {
        name: member
        for name, member in vars(cls).items()
        if inspect.isfunction(member)
    }
    resolved: set[str] = set()
    pending = ["post"] if "post" in members else []
    while pending:
        name = pending.pop()
        if name in resolved:
            continue
        resolved.add(name)
        tree = ast.parse(textwrap.dedent(inspect.getsource(members[name])))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "self"
                and node.func.attr in members
            ):
                pending.append(node.func.attr)
    return resolved


class _RawAliveReader:
    def at_eof(self):
        return False


class _RawAliveWriter:
    def is_closing(self):
        return False

    def close(self):
        return None

    async def wait_closed(self):
        return None


class _RawCountingConnection:
    """A reusable connection record that records every object inspection."""

    def __init__(self, cid):
        object.__setattr__(
            self,
            "_state",
            {
                "cid": cid,
                "reader": _RawAliveReader(),
                "writer": _RawAliveWriter(),
                "idle_token": 0,
                "expiry_handle": None,
            },
        )
        object.__setattr__(self, "touches", 0)

    def __getattribute__(self, name):
        state = object.__getattribute__(self, "_state")
        if name in state:
            object.__setattr__(
                self, "touches", object.__getattribute__(self, "touches") + 1
            )
            return state[name]
        return object.__getattribute__(self, name)

    def __setattr__(self, name, value):
        state = object.__getattribute__(self, "_state")
        if name in state:
            object.__setattr__(
                self, "touches", object.__getattribute__(self, "touches") + 1
            )
            state[name] = value
            return
        object.__setattr__(self, name, value)


@pytest.mark.parametrize("driver", _RAW_DRIVERS, ids=["reference", "e2e"])
@pytest.mark.asyncio
async def test_b1_client_bookkeeping_does_not_scale_with_capacity(driver):
    """FP-B1DF-1 benchmark: existing connections inspected per acquire/release.

    Metric: how many already-held connection objects one acquire/complete/
    release touches. Bar: the same number at populations 8 and 1,000, and at
    most one. Deterministic, no socket I/O and no elapsed-time threshold.
    """
    import inspect

    # --- leg 1: the source of the client the factory actually returns -------
    client = driver.build_httpx_client(max_connections=driver.MAX_IN_FLIGHT)
    try:
        classes = _raw_reachable_driver_classes(client, driver)
        assert classes, "no driver-defined class is reachable from the built client"
        offences = []
        for cls_name, cls in sorted(classes.items()):
            for name, member in sorted(vars(cls).items()):
                if name in _RAW_OFF_REQUEST_PATH or not inspect.isfunction(member):
                    continue
                found = _raw_population_scan(
                    inspect.getsource(member), f"{cls_name}.{name}"
                )
                if found is not None:
                    offences.append(found)
        assert not offences, "per-request ledger scan: " + "; ".join(offences)
        assert type(client).__module__ == driver.__name__, (
            f"the factory returns {type(client)!r}, not the driver's own client"
        )
        # The O(C + R) diagnostic snapshot must stay off the request path.
        assert "pool_snapshot" not in _raw_request_path_methods(type(client))
    finally:
        await client.aclose()

    # --- leg 2: the same transitions at two populations ---------------------
    touched = {}
    seeded = {}
    for population in (8, 1000):
        client = _raw_client(driver, population + 1)
        probes = [_RawCountingConnection(cid) for cid in range(population)]
        for probe in probes:
            client._connections[probe.cid] = probe
            client._idle[probe.cid] = probe
        client._next_connection_id = population
        for probe in probes:
            probe.touches = 0

        request_id, conn = await client._checkout()
        client._requests.pop(request_id, None)
        client._recycle(conn)

        touched[population] = sum(1 for probe in probes if probe.touches)
        seeded[population] = probes
        await client.aclose()

    assert touched[8] == touched[1000] <= 1, touched

    # The probe discriminates: an explicit sweep of the same seeded pools is
    # counted as 8 and 1,000, so equality above is not equality-by-blindness.
    control = {}
    for population, probes in seeded.items():
        for probe in probes:
            probe.touches = 0
        for probe in probes:
            probe.cid
        control[population] = sum(1 for probe in probes if probe.touches)
    assert control == {8: 8, 1000: 1000}


@pytest.mark.parametrize("values,expected", [([b1.UNAVAILABLE, 3], 3), ([b1.UNAVAILABLE], b1.UNAVAILABLE)])
@pytest.mark.asyncio
async def test_bd_request_peak_uses_sampler(values, expected, monkeypatch):
    samples = iter(values)
    def sample(client):
        value = next(samples, values[-1])
        return 0, 0, set(), value
    monkeypatch.setattr(b1, "read_pool_census_sample", sample)
    with _bd_instant_server() as endpoint:
        async with b1.build_httpx_client(max_connections=1000) as client:
            result = await _bd_offer(b1, client, endpoint, 250)
    assert result.peak_pool_requests == expected


@pytest.mark.parametrize("quantity", [0, 3, b1.UNAVAILABLE])
def test_bd_fingerprint_request_field_renders_phase_value(quantity):
    """Execute the sole fingerprint template, then its named FP-IG-37 check."""
    tree = ast.parse(Path(__file__).read_text())
    template = next(n.value for n in ast.walk(tree) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "fingerprint_line" for t in n.targets))
    result = b1.PhaseResult(0, 0, 0, [], 0.0, 1.0, 0.0, 5, 0,
                            peak_pool_connections=quantity,
                            peak_pool_requests=quantity,
                            peak_pool_queued=quantity,
                            pool_connections_seen=quantity)
    names = {n.id for n in ast.walk(template) if isinstance(n, ast.Name)}
    env = dict.fromkeys(names, 0)
    env.update(b1=b1, result=result, int=int, fp=dict(cpus=4, cpu_model="fixture", image="fixture"),
               workers_pre=[], workers_post=[], peak_pool_conn_str=str(quantity),
               peak_pool_q_str=str(quantity), pool_seen_str=str(quantity))
    line = eval(compile(ast.Expression(template), str(__file__), "eval"), env)
    assert f",peak_pool_connections={quantity},peak_pool_requests={quantity},peak_pool_queued={quantity}," in line
    test_b1_fingerprint_line_locates_the_in_flight_population({"fingerprint": line, "result": result})


if __name__ == "__main__":
    if sys.argv[1:] != ["--characterize-b1-client"]:
        raise SystemExit("usage: test_b1_ingest_burst.py --characterize-b1-client")
    characterize_b1_instant_server()


@pytest.mark.parametrize("payload_length", [65535, 65536, 65537, 2097152])
def test_b1_gateway_output_is_retained_without_pipe_backpressure(tmp_path, payload_length):
    log_path = tmp_path / "gateway.log"
    sentinel = tmp_path / "complete"
    marker = b"\nSTDERR-TAIL\n"
    script = (
        "import pathlib,sys; "
        f"sys.stdout.buffer.write(b'x'*{payload_length}); sys.stdout.flush(); "
        f"sys.stderr.buffer.write({marker!r}); sys.stderr.flush(); "
        f"pathlib.Path({str(sentinel)!r}).touch()"
    )
    with _b1_gateway_process([sys.executable, "-c", script],
                             env=os.environ.copy(), log_path=log_path) as proc:
        try:
            proc.wait(timeout=10)
            assert sentinel.exists()
            assert proc.returncode == 0
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
    assert log_path.read_bytes() == b"x" * payload_length + marker


def test_b1_gateway_log_prefix_count_and_diagnostic_tail(tmp_path):
    log_path = tmp_path / "gateway.log"
    warning = b"WARNING:  Exceeded concurrency limit.\n"
    with _b1_gateway_process([sys.executable, "-c", "pass"],
                             env=os.environ.copy(), log_path=log_path) as proc:
        proc.wait(timeout=10)
        assert _b1_gateway_warning_count(log_path, 0) == 0
        assert _b1_gateway_log_tail(log_path) == ""
        # Independent append descriptor models the child's shared writer offset.
        with log_path.open("ab", buffering=0) as child_writer:
            child_writer.write(b"INITIAL\n" + warning)
            assert _b1_gateway_warning_count(log_path, log_path.stat().st_size) == 1
            child_writer.write(warning + b"unrelated Exceeded concurrency limit.\n" + warning[:-1])
            prefix = log_path.stat().st_size
            assert _b1_gateway_warning_count(log_path, prefix) == 2
            before = log_path.read_bytes()
            offset = child_writer.tell()
            _b1_gateway_log_tail(log_path)
            assert child_writer.tell() == offset
            child_writer.write(b"\n" + warning + b"\xffTAIL")
            assert _b1_gateway_warning_count(log_path, prefix) == 2
            assert _b1_gateway_warning_count(log_path, log_path.stat().st_size) == 4
            assert log_path.read_bytes().startswith(before)
            assert "\ufffdTAIL" in _b1_gateway_log_tail(log_path)
    for length in (1999, 2000, 2001):
        path = tmp_path / str(length)
        payload = "\u00e9" * length
        path.write_text(payload)
        assert _b1_gateway_log_tail(path) == payload[-2000:]
        assert path.read_text() == payload
    with pytest.raises(OSError):
        _b1_gateway_warning_count(tmp_path / "missing", 0)
    with pytest.raises(OSError):
        _b1_gateway_warning_count(tmp_path, 0)
    with pytest.raises(RuntimeError, match="shortened"):
        _b1_gateway_warning_count(log_path, log_path.stat().st_size + 1)

    # Keep the child's non-O_APPEND writer alive across the diagnostic read.
    # Seeking that shared descriptor would overwrite the initial output.
    live_log = tmp_path / "live.log"
    ready, resume = tmp_path / "ready", tmp_path / "resume"
    initial = b"INITIAL-MARKER\n" + b"x" * 70000 + b"\xff\n" + warning
    script = textwrap.dedent(f"""
        import pathlib, sys, time
        sys.stdout.buffer.write({initial!r})
        sys.stdout.flush()
        pathlib.Path({str(ready)!r}).touch()
        while not pathlib.Path({str(resume)!r}).exists(): time.sleep(0.01)
        sys.stdout.buffer.write(b'APPENDED-TAIL')
        sys.stdout.flush()
    """)
    with _b1_gateway_process([sys.executable, "-c", script],
                             env=os.environ.copy(), log_path=live_log) as proc:
        deadline = time.monotonic() + 10
        while not ready.exists():
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert _b1_gateway_log_tail(live_log) == initial.decode(errors="replace")[-2000:]
        assert _b1_gateway_warning_count(live_log, live_log.stat().st_size) == 1
        resume.touch()
        proc.wait(timeout=10)
        assert proc.returncode == 0
    assert live_log.read_bytes() == initial + b"APPENDED-TAIL"

    boundary_log = tmp_path / "chunk-boundaries.log"
    # A UTF-8 whitespace character and warning straddle the parser's chunk boundary.
    boundary_log.write_bytes(b"x" * 65525 + b"\nWARNING:\xc2\xa0Exceeded concurrency limit.\r\n")
    assert _b1_gateway_warning_count(boundary_log, boundary_log.stat().st_size) == 1


@pytest.mark.parametrize("branch", [
    "normal", "early", "startup_timeout", "assertion", "stubborn", "constructor",
    "fake_kill", "fake_orphan", "fake_survivor", "fake_unreapable",
])
def test_b1_gateway_process_reaps_on_failure(tmp_path, monkeypatch, branch):
    log_path = tmp_path / "gateway.log"
    writers = []
    original_popen = subprocess.Popen

    def spawn(*args, **kwargs):
        writers.append(kwargs["stdout"])
        if branch == "constructor":
            raise OSError("constructor failure")
        return original_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", spawn)
    if branch == "constructor":
        with pytest.raises(OSError, match="constructor failure"):
            with _b1_gateway_process([], env={}, log_path=log_path):
                pytest.fail("constructor unexpectedly succeeded")
        assert writers[0].closed
        assert log_path.exists()
        return
    if branch.startswith("fake_"):
        class LifecycleFake:
            pid = 987654321
            returncode = None
            waits = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout):
                self.waits += 1
                if branch == "fake_unreapable" or (branch == "fake_kill" and self.waits == 1):
                    raise subprocess.TimeoutExpired("fake", timeout)
                self.returncode = -9
                return self.returncode

        fake = LifecycleFake()
        def fake_spawn(*args, **kwargs):
            writers.append(kwargs["stdout"])
            return fake
        signals = []
        monkeypatch.setattr(subprocess, "Popen", fake_spawn)
        def send(pid, sig):
            signals.append((pid, sig))
        monkeypatch.setattr(os, "killpg", send)
        if branch in {"fake_orphan", "fake_survivor"}:
            monkeypatch.setitem(globals(), "_b1_gateway_group_alive", lambda pid: (
                branch == "fake_survivor" or (pid, signal.SIGKILL) not in signals
            ))
        if branch == "fake_survivor":
            from types import SimpleNamespace
            ticks = iter((0, 11))
            monkeypatch.setitem(globals(), "time", SimpleNamespace(monotonic=lambda: next(ticks)))
        if branch in {"fake_survivor", "fake_unreapable"}:
            with pytest.raises(RuntimeError, match="gateway log="):
                with _b1_gateway_process([], env={}, log_path=log_path):
                    pass
            assert writers[0].closed
            assert signals[-1] == (fake.pid, signal.SIGKILL)
            return
        with _b1_gateway_process([], env={}, log_path=log_path):
            pass
        if branch == "fake_orphan":
            assert fake.waits == 1 and fake.poll() == -9
            assert signals[-1] == (fake.pid, signal.SIGKILL)
            assert writers[0].closed
            return
        assert fake.waits == 2 and fake.poll() == -9
        assert signals == [(fake.pid, signal.SIGTERM), (fake.pid, signal.SIGKILL)]
        assert writers[0].closed
        return

    ready = tmp_path / "ready"
    script = "import sys; print('RETAINED-TAIL', flush=True); sys.exit(7)"
    if branch in {"startup_timeout", "assertion"}:
        script = f"import time,pathlib; print('RETAINED-TAIL',flush=True); pathlib.Path({str(ready)!r}).touch(); time.sleep(60)"
    elif branch == "stubborn":
        script = textwrap.dedent(f"""
            import os, signal, time, pathlib
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            child = os.fork()
            if child == 0:
                while True: time.sleep(1)
            print('RETAINED-TAIL', flush=True)
            pathlib.Path({str(ready)!r}).write_text(str(child))
            while True: time.sleep(1)
        """)
    elif branch == "normal":
        script = "print('RETAINED-TAIL', flush=True)"

    def exercise():
        with _b1_gateway_process([sys.executable, "-c", script],
                                 env=os.environ.copy(), log_path=log_path) as proc:
            processes.append(proc)
            if branch in {"normal", "early"}:
                proc.wait(timeout=10)
                if branch == "early":
                    raise RuntimeError("gateway exited early")
            else:
                deadline = time.monotonic() + 10
                while not ready.exists():
                    assert time.monotonic() < deadline, "child did not become ready"
                    time.sleep(0.01)
                assert _b1_gateway_group_alive(proc.pid)
                if branch == "startup_timeout":
                    raise RuntimeError("gateway never became healthy")
                if branch == "assertion":
                    raise AssertionError("fixture assertion")
    processes = []
    try:
        if branch in {"early", "startup_timeout", "assertion"}:
            with pytest.raises(RuntimeError, match="RETAINED-TAIL") as error:
                exercise()
            assert str(log_path) in str(error.value)
            assert isinstance(error.value.__cause__, (RuntimeError, AssertionError))
        else:
            exercise()
        assert processes[0].poll() is not None
        assert not _b1_gateway_group_alive(processes[0].pid)
        assert writers[0].closed
        assert b"RETAINED-TAIL" in log_path.read_bytes()
    finally:
        for proc in processes:
            _b1_gateway_signal_group(proc.pid, signal.SIGKILL)
            proc.wait(timeout=10)
        deadline = time.monotonic() + 10
        while any(_b1_gateway_group_alive(p.pid) for p in processes):
            assert time.monotonic() < deadline, "test left live group members"
            time.sleep(0.01)


def test_b1_fingerprint_line_reports_scoped_concurrency_warnings(tmp_path, monkeypatch):
    """Execute the fixture's actual callback, serialization and yielded mapping.

    Container-free: the sibling containers, their cgroup readers and the log
    store are faked, so this exercises the real ``_run_b1_reference`` source --
    including its CI-scale (no product verdict) serialization branch and its
    fail-soft diagnostic path -- inside the traced coverage selection.
    """
    tree = ast.parse(Path(__file__).read_text())
    fixture = next(
        n for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_run_b1_reference"
    )
    collector = next(
        n for n in ast.walk(fixture)
        if isinstance(n, ast.FunctionDef) and n.name == "_collect_cpu_diagnostics"
    )
    callback = next(
        n for n in ast.walk(fixture)
        if isinstance(n, ast.FunctionDef) and n.name == "_after_window"
    )
    prologue_callback = next(
        n for n in ast.walk(fixture)
        if isinstance(n, ast.FunctionDef) and n.name == "_after_prologue"
    )
    warning = b"WARNING:  Exceeded concurrency limit.\n"
    log_path = tmp_path / "gateway.log"
    marks = {}
    cpu_max = "max 100000"
    cpu_stat = (
        "usage_usec 2000000\nnr_periods 300\nnr_throttled 4\nthrottled_usec 900\n"
    )

    class _FakeLogStore:
        def __init__(self, payload):
            self.payload = payload

        def logs(self, stdout=True, stderr=True):
            if self.payload is None:
                raise OSError("log store unavailable")
            return self.payload

    gateway_store = _FakeLogStore(warning * 2)

    def _fake_read_cpu_files(container):
        # Every cgroup read must precede the log snapshot: a CPU interval that
        # closed after the log prefix would not be the measured window.
        assert "log_prefix_bytes" not in marks
        if container is postgres_sentinel:
            raise OSError("cgroup file vanished")  # fail-soft, never gating
        return cpu_max, cpu_stat

    def _fake_busy(allowed):
        assert "log_prefix_bytes" not in marks
        return {cpu: 7 for cpu in sorted(allowed)}

    postgres_sentinel = object()
    roles_open = {"gateway": _role("gateway", (0, 1), pids=(11,))}

    class _FakeWaitSampler:
        """GC-4: records that sampling stops INSIDE the window-complete hook."""

        def __init__(self):
            self.stops = 0
            self.next_sample = B1PostgresWaitSample(
                scheduled=600, completed=600, failed=0, observations=1800,
                histogram={B1_WAIT_ACTIVE_CPU_KEY: 1200, "active/IO/WALSync": 600},
            )

        def stop(self):
            # Sampling must stop before the CPU-after snapshot closes the
            # reported interval, so the sampler's own backend is not in its
            # tail.
            assert "gateway_cpu_stat_after" not in marks
            self.stops += 1
            return self.next_sample

    wait_sampler = _FakeWaitSampler()

    class _FakeStatsReader:
        """GC-5: records WHERE in the callback the post-window snapshot is taken."""

        def __init__(self):
            self.snapshots = 0
            self.published = 0
            self.next_snapshot = _commit_snapshot(xact_commit=9_000)

        def snapshot(self):
            self.snapshots += 1
            return self.next_snapshot

        def published_snapshot(self):
            # The publication wait and the stability rule are the reader's own
            # contract; what this callback owes is ORDER -- the post-window
            # snapshot is taken after the sampler stopped and after the log
            # prefix closed, and before the fixture's post-window audit count.
            assert wait_sampler.stops >= 1
            assert "log_prefix_bytes" in marks
            self.published += 1
            return self.next_snapshot

    stats_reader = _FakeStatsReader()
    namespace = {
        "b1": b1,
        "marks": marks,
        "roles_open": roles_open,
        "gateway": gateway_store,
        "postgres": postgres_sentinel,
        "log_path": log_path,
        "B1_ROLES": B1_ROLES,
        "wait_sampler": wait_sampler,
        "stats_reader": stats_reader,
        "postgres_wait_sample_failure": postgres_wait_sample_failure,
        "_read_cpu_files": _fake_read_cpu_files,
        "_gateway_set_busy_usec": _fake_busy,
        "_try_diagnostic": _try_diagnostic,
        "_snapshot_container_log": _snapshot_container_log,
    }
    exec(compile(ast.Module(body=[collector, callback, prologue_callback],
                            type_ignores=[]),
                 "<fixture-callback>", "exec"), namespace)

    # GC-5: the pre-window collection ORDER, executed rather than described.
    # The transaction snapshot is taken AFTER the unmeasured prologue's own
    # audit-count query -- so the prologue's transactions are outside the
    # measured delta -- and BEFORE the wait sampler opens its connection.
    order: list[str] = []
    namespace["_committed_ingest_rows"] = lambda _dsn: order.append("audit-count") or 7
    namespace["dsn"] = "postgresql://ignored/db"
    stats_reader.snapshot = lambda: (
        order.append("snapshot") or stats_reader.next_snapshot
    )
    wait_sampler.start = lambda: order.append("sampler-start")
    namespace["_after_prologue"]()
    assert order == ["audit-count", "snapshot", "sampler-start"], order
    assert marks["committed_before"] == 7
    assert marks["postgres_commit_before"] is stats_reader.next_snapshot
    marks.clear()
    stats_reader.snapshot = stats_reader.__class__.snapshot.__get__(stats_reader)

    namespace["_after_window"]()
    assert wait_sampler.stops == 1
    assert marks["postgres_wait_sample"].completed == 600
    # A usable sample leaves no sampler note behind...
    assert not any("postgres wait sampler" in note for note in marks["diagnostic_notes"])
    assert marks["gateway_cpu_stat_after"] == cpu_stat
    assert marks["postgres_cpu_stat_after"] is None   # fail-soft, not fatal
    assert marks["busy_after"] == {0: 7, 1: 7}
    assert any("postgres cgroup files" in note for note in marks["diagnostic_notes"])
    assert marks["log_prefix_bytes"] == len(warning) * 2
    # GC-5: the post-window transaction snapshot is taken by the same callback,
    # exactly once, after the log prefix closed.
    assert stats_reader.published == 1
    assert marks["postgres_commit_after"] is stats_reader.next_snapshot

    with log_path.open("ab") as output:
        output.write(warning * 2)  # Later shed-probe phase must not enter the prefix.
    count_assignment = next(
        n for n in ast.walk(fixture)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "concurrency_limit_warnings" for t in n.targets)
    )
    namespace["_b1_gateway_warning_count"] = _b1_gateway_warning_count
    exec(compile(ast.Module(body=[count_assignment], type_ignores=[]), "<fixture-count>", "exec"),
         namespace)
    assert namespace["concurrency_limit_warnings"] == 2
    assert _b1_gateway_warning_count(log_path, log_path.stat().st_size) == 4

    # The real diagnostic rendering: a role whose source was unreadable is
    # `unavailable`, and that does not touch placement.
    diag_assign = next(
        n for n in ast.walk(fixture)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "diagnostics" for t in n.targets)
    )
    namespace["_role_diagnostics"] = _role_diagnostics
    exec(compile(ast.Module(body=[diag_assign], type_ignores=[]), "<fixture-diagnostics>", "exec"),
         namespace)
    rendered = dict(namespace["diagnostics"]["postgres"].rendered())
    assert set(rendered.values()) == {DIAGNOSTIC_UNAVAILABLE}
    assert namespace["diagnostics"]["gateway"].quota_cpus == "max"

    # CI-scale serialization branch: the two real statements that decide
    # whether product verdicts enter the line at all.
    verdict_assign = next(
        n for n in ast.walk(fixture)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "verdicts" for t in n.targets)
    )
    product_assign = next(
        n for n in ast.walk(fixture)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "product_fields" for t in n.targets)
    )
    namespace.update(
        profile=CI_SCALE_PROFILE,
        OrderedDict=OrderedDict,
        PRODUCT_PROFILE_NAME=PRODUCT_PROFILE_NAME,
        _product_promise_verdicts=_product_promise_verdicts,
        serialize_product_verdicts=serialize_product_verdicts,
    )
    exec(
        compile(ast.Module(body=[verdict_assign, product_assign], type_ignores=[]),
                "<fixture-verdicts>", "exec"),
        namespace,
    )
    assert namespace["verdicts"] == OrderedDict()
    assert namespace["product_fields"] == ""

    assignment = next(
        n for n in ast.walk(fixture)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "fingerprint_line" for t in n.targets)
    )
    mapping = next(n.value for n in ast.walk(fixture) if isinstance(n, ast.Yield))
    # Supply unrelated fixture observations; execute its unchanged consumer expressions.
    names = {
        n.id for root in (assignment, mapping) for n in ast.walk(root)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
    }
    for name in names - namespace.keys() - {"int", "float", "str", "dict"}:
        namespace[name] = 1
    namespace.update(
        fp={"cpus": 1, "cpu_model": "test", "image": "test"},
        workers_pre={1}, workers_post={1}, status_histogram="200:3;503:1",
        placement_fields="placement_profile=ci-scale,placement_ok=1,",
        cpu_ms_str="2.345", roles_close=roles_open,
    )
    attrs = {
        n.attr for root in (assignment, mapping) for n in ast.walk(root)
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "result"
    }
    namespace["result"] = SimpleNamespace(**dict.fromkeys(attrs, 1))
    # GC-4: execute the real cost-field serialization statement rather than
    # letting the placeholder loop above invent a value for it.
    cost_assign = next(
        n for n in ast.walk(fixture)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "postgres_cost_fields" for t in n.targets)
    )
    namespace.update(
        serialize_postgres_cost_fields=serialize_postgres_cost_fields,
        postgres_usage_usec=4500,
        wait_sample=marks["postgres_wait_sample"],
    )
    namespace["result"] = SimpleNamespace(**dict.fromkeys(attrs | {"served"}, 1))
    namespace["result"].served = 9
    exec(compile(ast.Module(body=[cost_assign], type_ignores=[]), "<fixture-cost>", "exec"),
         namespace)
    assert namespace["postgres_cost_fields"] == serialize_postgres_cost_fields(
        4500, 9, marks["postgres_wait_sample"]
    )
    # GC-5: the real transaction-field serialization statement, on a window
    # whose two ends are this test's own snapshots.
    commit_assign = next(
        n for n in ast.walk(fixture)
        if isinstance(n, ast.Assign)
        and any(
            isinstance(t, ast.Name) and t.id == "postgres_commit_fields"
            for t in n.targets
        )
    )
    commit_before = _commit_snapshot(xact_commit=1_000, wal_sync=100)
    commit_after = _commit_snapshot(xact_commit=1_003, wal_sync=101)
    namespace.update(
        serialize_postgres_commit_fields=serialize_postgres_commit_fields,
        commit_before=commit_before,
        commit_after=commit_after,
    )
    exec(compile(ast.Module(body=[commit_assign], type_ignores=[]),
                 "<fixture-commit>", "exec"), namespace)
    assert namespace["postgres_commit_fields"] == serialize_postgres_commit_fields(
        commit_before, commit_after, 9
    )
    exec(compile(ast.Module(body=[assignment], type_ignores=[]), "<fixture-line>", "exec"),
         namespace)
    yielded = eval(compile(ast.Expression(mapping), "<fixture-mapping>", "eval"), namespace)
    assert "status_histogram=200:3;503:1,concurrency_limit_warnings=2," in yielded["fingerprint"]
    assert "placement_profile=ci-scale,placement_ok=1," in yielded["fingerprint"]
    for field_name in PRODUCT_VERDICT_FIELDS:
        assert f"{field_name}=" not in yielded["fingerprint"]
    assert yielded["concurrency_limit_warnings"] == 2
    assert yielded["gateway_log_path"] == log_path
    assert yielded["product_verdicts"] == {}
    assert yielded["placement_ok"] is True
    # GC-4: the six reported-only cost fields close the line, after both
    # lateness legs, and the sample travels in the yielded mapping too.
    at = yielded["fingerprint"].index("leg_p99s=")
    for field_name in B1_POSTGRES_COST_FIELDS + B1_POSTGRES_COMMIT_FIELDS:
        position = yielded["fingerprint"].index(f",{field_name}=")
        assert position > at, field_name
        at = position
    assert yielded["fingerprint"].endswith(
        serialize_postgres_commit_fields(commit_before, commit_after, 9)
    )
    assert serialize_postgres_cost_fields(
        4500, 9, marks["postgres_wait_sample"]
    ) in yielded["fingerprint"]
    assert _parse_b1_env_field(yielded["fingerprint"], "postgres_cpu_us_per_req") == "500.000"
    # Three commits over nine served requests, carried unrounded enough to
    # decide the FP-GC5-7 bar.
    assert _parse_b1_env_field(
        yielded["fingerprint"], "postgres_xact_commits_per_served"
    ) == "0.333333"
    assert yielded["postgres_commit_before"] is commit_before
    assert yielded["postgres_commit_after"] is commit_after
    assert commit_shape_record_failures(
        {
            "result": SimpleNamespace(served=9),
            "postgres_commit_before": commit_before,
            "postgres_commit_after": commit_after,
        }
    ) == []
    assert yielded["postgres_wait_sample"] is marks["postgres_wait_sample"]
    assert postgres_cost_record_failures(
        {
            "result": SimpleNamespace(served=9),
            "postgres_usage_usec": 4500,
            "p99_leg_split": (1.0, 2.0, 3.0),
            "leg_p99s": (1.0, 2.0, 3.0),
            "postgres_wait_sample": yielded["postgres_wait_sample"],
        }
    ) == []
    # Pin the real callback registration and its ordering before the probe.
    calls = [n for n in ast.walk(fixture) if isinstance(n, ast.Call)]
    run = next(n for n in calls if isinstance(n.func, ast.Attribute) and n.func.attr == "run_open_loop")
    assert any(
        k.arg == "on_window_complete" and isinstance(k.value, ast.Name)
        and k.value.id == "_after_window" for k in run.keywords
    )
    probe = next(n for n in calls if isinstance(n.func, ast.Attribute) and n.func.attr == "run_shed_probe")
    assert run.lineno < count_assignment.lineno < probe.lineno
    # GC-4 fail-soft: an UNUSABLE sample is recorded as such -- the hook keeps
    # going, the sample still reaches `marks`, and a note names the reason with
    # the raw counts. Nothing about it is fatal.
    marks.clear()
    wait_sampler.next_sample = B1PostgresWaitSample(
        scheduled=600, completed=400, failed=3, observations=0, histogram={},
    )
    namespace["_after_window"]()
    assert wait_sampler.stops == 2
    assert marks["postgres_wait_sample"].failed == 3
    sampler_notes = [n for n in marks["diagnostic_notes"] if "postgres wait sampler" in n]
    assert len(sampler_notes) == 1, marks["diagnostic_notes"]
    assert "3 wait samples failed" in sampler_notes[0]
    for raw in ("scheduled=600", "completed=400", "failed=3", "observations=0"):
        assert raw in sampler_notes[0], (raw, sampler_notes[0])

    # A failed log snapshot cannot yield a zero-valued count/fingerprint.
    marks.clear()
    gateway_store.payload = None
    with pytest.raises(OSError):
        namespace["_after_window"]()
    assert "log_prefix_bytes" not in marks



# ---------------------------------------------------------------------------
# GC-1 unit tests (FP-GC1-1..5) — no container, no live fixture.
#
# Every Docker lifecycle case below uses faked Docker/testcontainers objects
# and temporary cgroup/proc files, so the whole block stays inside the traced
# container-free selection and inside the ordinary Python unit tier.
# ---------------------------------------------------------------------------


_AFFINITY_HELPER_PATH = REPO_ROOT / "scripts" / "b1-affinity-helper.py"


def _load_affinity_helper():
    spec = importlib.util.spec_from_file_location("b1_affinity_helper", _AFFINITY_HELPER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    _sys.modules["b1_affinity_helper"] = module
    spec.loader.exec_module(module)
    return module


class _FakeContainer:
    def __init__(self, name, labels=None, pid=None, image_id="sha256:fake"):
        self.name = name
        self.labels = dict(labels or {})
        self.attrs = {"State": {"Pid": pid}, "Mounts": []}
        self.image = SimpleNamespace(id=image_id)
        self.id = f"id-{name}"

    def with_mount(self, source, destination):
        self.attrs["Mounts"].append({"Source": source, "Destination": destination})
        return self


class _FakeContainers:
    def __init__(self, listing):
        self._listing = listing
        self.calls = []

    def list(self, all=False, filters=None):  # noqa: A002 - docker SDK signature
        self.calls.append((all, dict(filters or {})))
        wanted = set((filters or {}).get("label", []))
        out = []
        for container in self._listing:
            labels = {f"{k}={v}" for k, v in container.labels.items()}
            if wanted <= labels:
                out.append(container)
        return out


class _FakeClient:
    def __init__(self, listing):
        self.containers = _FakeContainers(listing)


def _declaration_payload(profile=CI_SCALE_PROFILE_NAME, **overrides):
    run_id = "0123456789abcdef0123456789abcdef"
    if profile == CI_SCALE_PROFILE_NAME:
        # GC-3 (FP-GC3-4): the ordinary CI-scale contract is the ratified
        # schema-3 document `contract-selected` writes. `gateway-core` over the
        # pairs (0,1)/(2,3) renders the same CPU sets the schema-2 contract
        # carried, so every non-schema assertion below is unchanged -- what
        # changed is that the document now also states the RELATIONSHIP.
        payload = probe.selected_contract("gateway-core", ("0-1", "2-3"), run_id)
    else:
        payload = {
            "schema": 2,
            "runId": run_id,
            "profile": profile,
            "minimumHostLogicalCpus": 8,
            "mechanism": "sched-affinity",
            "roles": {
                "gateway": {"allowedCpus": "0-3"},
                "postgres": {"allowedCpus": "4-6"},
                "driver": {"allowedCpus": "7"},
            },
        }
    payload.update(overrides)
    return payload


def _role(role, cpus, pids=(11,)):
    return B1RolePlacement(role=role, allowed_cpus=frozenset(cpus), pids=tuple(pids))


def _ci_scale_roles():
    return {
        "gateway": _role("gateway", (0, 1), pids=(11, 12, 13, 14, 15)),
        "postgres": _role("postgres", (2,)),
        "driver": _role("driver", (3,)),
    }


def _product_roles():
    return {
        "gateway": _role("gateway", (0, 1, 2, 3), pids=(11, 12, 13, 14, 15)),
        "postgres": _role("postgres", (4, 5, 6)),
        "driver": _role("driver", (7,)),
    }


def test_b1_cpu_list_parser_accepts_canonical_kernel_forms():
    """FP-GC1-3/4: canonical list syntax in, canonical list syntax out."""
    assert b1.parse_cpu_list("0-3") == frozenset({0, 1, 2, 3})
    assert b1.parse_cpu_list("0-3,8") == frozenset({0, 1, 2, 3, 8})
    assert b1.parse_cpu_list("7") == frozenset({7})
    assert b1.parse_cpu_list(" 0-1,4 \n") == frozenset({0, 1, 4})
    assert b1.parse_cpu_list("3-3") == frozenset({3})
    # Normalization is a round trip on every canonical form.
    for text in ("0", "0-3", "0-3,8", "1,3,5", "0-1,4-6,9"):
        assert b1.format_cpu_list(b1.parse_cpu_list(text)) == text
    assert b1.format_cpu_list({8, 0, 1, 2, 3}) == "0-3,8"
    assert b1.format_cpu_list([5]) == "5"
    for bad in ("", "   ", "0 1", "a", "3-1", "0,0", "0-2,1", "0-", "-1", "1--2", "0,,1"):
        with pytest.raises(b1.B1PlacementParseError):
            b1.parse_cpu_list(bad)
    with pytest.raises(b1.B1PlacementParseError):
        b1.parse_cpu_list(None)
    with pytest.raises(b1.B1PlacementParseError):
        b1.format_cpu_list([])
    with pytest.raises(b1.B1PlacementParseError):
        b1.format_cpu_list([-1])
    with pytest.raises(b1.B1PlacementParseError):
        b1.format_cpu_list([True])


def test_b1_env_field_parser_reads_comma_bearing_cpu_lists():
    """FP-GC1-4/FP-GC3-5: a `,` opens a new field only before a new `key=`.

    Regression for the CI-scale topology witness. `format_cpu_list` renders
    canonical Linux list syntax, so a non-contiguous role set carries a raw
    comma -- `gateway-split` puts the gateway on `{0,2}`, which is spelled
    `0,2`. Splitting the line on every comma truncated such a value at its
    first range, and `test_b1_ci_scale_fingerprint_proves_reference_topology`
    failed with `assert '0' == '0,2'` on the first live `gateway-split` run
    while the placement itself was correct and the producer had written the
    whole set. Values never carry a raw `=`, so a fragment without one
    continues the value before it; an empty fragment ends the line.
    """
    # (a) The shape that failed in CI, and the four-CPU non-contiguous
    # reference set that would fail the same way, parsed directly.
    line = (
        "B1 env=placement_ok=1,gateway_allowed_cpus=0,2,postgres_allowed_cpus=1,"
        "driver_allowed_cpus=3,reference_cpus=0-1,8-9,end=x"
    )
    assert _parse_b1_env_field(line, "gateway_allowed_cpus") == "0,2"
    assert _parse_b1_env_field(line, "postgres_allowed_cpus") == "1"
    assert _parse_b1_env_field(line, "driver_allowed_cpus") == "3"
    assert _parse_b1_env_field(line, "reference_cpus") == "0-1,8-9"
    assert _parse_b1_env_field(line, "end") == "x"
    # A comma-bearing value neither swallows the next field nor invents one.
    with pytest.raises(KeyError):
        _parse_b1_env_field(line, "unassigned_cpus")
    # The producer's trailing comma terminates the last value, it does not
    # extend it.
    assert _parse_b1_env_field("a=1,b=0,2,", "b") == "0,2"

    # (b) The producer's own round trip, on the topology that exposed this.
    declaration = B1PlacementDeclaration.from_contract(
        probe.selected_contract(
            "gateway-split", ("0-1", "2-3"), "0123456789abcdef0123456789abcdef"
        )
    )
    assert declaration.topology == "gateway-split"
    split_roles = {
        "gateway": _role("gateway", (0, 2), pids=(11, 12, 13, 14, 15)),
        "postgres": _role("postgres", (1,)),
        "driver": _role("driver", (3,)),
    }
    for role in B1_ROLES:
        assert declaration.allowed(role) == split_roles[role].allowed_cpus, role
    complete = (
        "usage_usec 12\nuser_usec 7\nsystem_usec 5\nnr_periods 3\n"
        "nr_throttled 1\nthrottled_usec 9\nnr_bursts 0\n"
    )
    later = complete.replace("usage_usec 12", "usage_usec 4012")
    line = _serialize_topology_placement_fields(
        declaration,
        AUTHORITY_CI_SCALE_REFERENCE,
        split_roles,
        {role: _role_diagnostics(role, "max 100000", complete, later) for role in B1_ROLES},
        {0: 10, 2: 20},
        0.5,
        1.5,
        role_thread_siblings={
            "gateway": "0:0,8+8:0,8", "postgres": "1:1,9", "driver": "3:3,11",
        },
    )
    assert "gateway_allowed_cpus=0,2," in line
    for role, cpus in (("gateway", {0, 2}), ("postgres", {1}), ("driver", {3})):
        assert _parse_b1_env_field(line, f"{role}_allowed_cpus") == b1.format_cpu_list(
            split_roles[role].allowed_cpus
        ) == b1.format_cpu_list(cpus), role
    assert _parse_b1_env_field(line, "gateway_allowed_cpus") == "0,2"
    assert _parse_b1_env_field(line, "reference_cpus") == b1.format_cpu_list({0, 1, 2, 3})
    assert _parse_b1_env_field(line, "unassigned_cpus") == B1_UNASSIGNED_NONE
    # Free-form diagnostics keep their own contract: their commas are escaped
    # at the source, so the continuation rule never sees one.
    assert _parse_b1_env_field(line, "gateway_thread_siblings_pct") == "0:0%2C8+8:0%2C8"
    assert _parse_b1_env_field(line, "postgres_thread_siblings_pct") == "1:1%2C9"
    assert _parse_b1_env_field(line, "spectre_v2_pct") == DIAGNOSTIC_UNAVAILABLE
    # Every schema-3 field still reads back, in the pinned order.
    for field_name in B1_TOPOLOGY_PLACEMENT_FIELDS:
        assert _parse_b1_env_field(line, field_name) != "", field_name
    positions = [line.index(f"{name}=") for name in B1_TOPOLOGY_PLACEMENT_FIELDS]
    assert positions == sorted(positions), B1_TOPOLOGY_PLACEMENT_FIELDS


def test_b1_cpu_diagnostic_parsers_report_without_gating():
    """FP-GC1-4: cgroup and /proc/stat readings are reported, never an oracle.

    This replaces rev 0.4's ``test_b1_cpu_max_and_stat_parsers_require_complete_v2_counters``,
    which asserted the opposite: it made an unquotaed ``cpu.max`` a hard
    failure. Under scheduler-affinity allocation ``max`` is the *expected*
    reading, and every one of these sources is a diagnostic whose loss must
    surface as ``unavailable`` rather than as a placement verdict.
    """
    # `max` is a first-class reading now, not an error.
    assert b1.parse_cpu_max("max 100000") == (None, 100000)
    assert b1.format_quota_cpus(None, 100000) == "max"
    assert b1.parse_cpu_max("200000 100000") == (200000, 100000)
    assert b1.format_quota_cpus(200000, 100000) == "2.00"
    assert b1.format_quota_cpus(50000, 100000) == "0.50"
    assert b1.parse_cpu_max(" 50000 100000\n") == (50000, 100000)
    for bad in ("", "200000", "200000 100000 1", "0 100000", "200000 0",
                "-1 100000", "abc 100000", "200000 abc", "max", "max max"):
        with pytest.raises(b1.B1PlacementParseError):
            b1.parse_cpu_max(bad)
    with pytest.raises(b1.B1PlacementParseError):
        b1.parse_cpu_max(None)
    with pytest.raises(b1.B1PlacementParseError):
        b1.format_quota_cpus(100, 0)

    complete = (
        "usage_usec 12\nuser_usec 7\nsystem_usec 5\nnr_periods 3\n"
        "nr_throttled 1\nthrottled_usec 9\nnr_bursts 0\n"
    )
    parsed = b1.parse_cpu_stat(complete)
    assert parsed == {"usage_usec": 12, "nr_periods": 3, "nr_throttled": 1, "throttled_usec": 9}
    for missing in b1.CPU_STAT_REQUIRED_KEYS:
        text = "".join(ln + "\n" for ln in complete.splitlines() if not ln.startswith(missing + " "))
        with pytest.raises(b1.B1PlacementParseError):
            b1.parse_cpu_stat(text)
    with pytest.raises(b1.B1PlacementParseError):
        b1.parse_cpu_stat(complete + "usage_usec 13\n")
    with pytest.raises(b1.B1PlacementParseError):
        b1.parse_cpu_stat("usage_usec\n")
    before = b1.parse_cpu_stat(complete)
    after = b1.parse_cpu_stat(complete.replace("usage_usec 12", "usage_usec 30"))
    assert b1.cpu_stat_delta(before, after)["usage_usec"] == 18
    with pytest.raises(b1.B1PlacementParseError):
        b1.cpu_stat_delta(after, before)  # counter decreased

    stat = "cpu  1 2 3 4 5\ncpu0 10 0 10 70 10 0 0 0 0 0\ncpu1 20 0 20 40 20 0 0 0 0 0\nintr 9\n"
    busy = b1.parse_proc_stat_busy_usec(stat, clock_ticks=100)
    assert busy == {0: 200000, 1: 400000}
    assert b1.serialize_cpu_busy({1: 4, 0: 3}) == "0:3+1:4"
    for bad in ("intr 9\n", "cpuX 1 2 3 4 5\n", "cpu0 1 2\n", "cpu0 a b c d e\n"):
        with pytest.raises(b1.B1PlacementParseError):
            b1.parse_proc_stat_busy_usec(bad, clock_ticks=100)

    # Every one of those failures reaches the fingerprint as `unavailable`,
    # carries a role/source-specific note, and touches no gating field.
    unlimited = _role_diagnostics("gateway", "max 100000", complete,
                                  complete.replace("usage_usec 12", "usage_usec 30"))
    assert unlimited.quota_cpus == "max"
    assert unlimited.cpu_period_us == "100000"
    assert unlimited.usage_usec_delta == 18
    assert unlimited.notes == ()
    assert dict(unlimited.rendered()) == {
        "gateway_quota_cpus": "max", "gateway_cpu_period_us": "100000",
        "gateway_nr_periods": "0", "gateway_nr_throttled": "0", "gateway_throttled_usec": "0",
    }
    for label, cpu_max, stat_before, stat_after in (
        ("missing cpu.max", None, complete, complete),
        ("malformed cpu.max", "garbage", complete, complete),
        ("missing cpu.stat", "max 100000", None, complete),
        ("incomplete cpu.stat", "max 100000", "usage_usec 1\n", complete),
        ("decreasing counter", "max 100000",
         complete.replace("usage_usec 12", "usage_usec 30"), complete),
    ):
        diag = _role_diagnostics("postgres", cpu_max, stat_before, stat_after)
        rendered = dict(diag.rendered())
        assert DIAGNOSTIC_UNAVAILABLE in rendered.values(), (label, rendered)
        if "cpu.stat" in label or "counter" in label:
            assert diag.usage_usec_delta is None, label
            assert rendered["postgres_nr_throttled"] == DIAGNOSTIC_UNAVAILABLE, label
        if "cpu.max" in label:
            assert rendered["postgres_quota_cpus"] == DIAGNOSTIC_UNAVAILABLE, label
            assert rendered["postgres_cpu_period_us"] == DIAGNOSTIC_UNAVAILABLE, label
        assert diag.notes, label
        assert diag.role in diag.notes[0], label

    # A wholly unavailable role still renders all five keys, never a zero.
    blank = _role_diagnostics("driver", None, None, None)
    assert set(dict(blank.rendered()).values()) == {DIAGNOSTIC_UNAVAILABLE}
    # And the serializer keeps them out of the gating prefix entirely.
    declaration = B1PlacementDeclaration.from_contract(_declaration_payload())
    line = _serialize_placement_fields(
        declaration, AUTHORITY_CI_SCALE_REFERENCE, _ci_scale_roles(),
        {role: _role_diagnostics(role, None, None, None) for role in B1_ROLES},
        None, None, None,
    )
    for field_name in B1_GATING_PLACEMENT_FIELDS:
        assert f"{field_name}=" in line
        assert f"{field_name}={DIAGNOSTIC_UNAVAILABLE}" not in line
    for field_name in B1_DIAGNOSTIC_PLACEMENT_FIELDS:
        assert f"{field_name}={DIAGNOSTIC_UNAVAILABLE}" in line, field_name
    assert "placement_ok=1" in line


def test_gc2_host_diagnostics_encode_round_trip_and_fail_soft(tmp_path):
    """FP-GC2-5: canonical map, exact encoding, whitespace, and honest misses.

    Every source is a temporary tree supplied here; production uses the
    defaults. Nothing below can change a placement or a performance verdict --
    the closing assertions prove exactly that.
    """
    # (a) The encoder: uppercase hex, the pinned safe set, exact round trip.
    assert _percent_encode_diagnostic("0:0-1+1:0-1") == "0:0-1+1:0-1"
    assert _percent_encode_diagnostic("0:0,8+8:0,8") == "0:0%2C8+8:0%2C8"
    assert _percent_encode_diagnostic("Mitigation: Enhanced / Automatic IBRS") == (
        "Mitigation:%20Enhanced%20%2F%20Automatic%20IBRS"
    )
    assert _percent_encode_diagnostic("100%") == "100%25"
    assert _percent_encode_diagnostic("a=b") == "a%3Db"
    assert _percent_encode_diagnostic("") == ""
    for raw in (
        "0:0-1+1:0-1", "0:0,8+8:0,8", "Mitigation: Enhanced IBRS, IBPB: conditional",
        "100%", "a=b", "weird\u00e9 value", "tabs\tand\nnewlines",
    ):
        assert urllib.parse.unquote(_percent_encode_diagnostic(raw)) == raw, raw
    encoded = _percent_encode_diagnostic("Mitigation: IBRS, IBPB: conditional")
    assert "," not in encoded and " " not in encoded, encoded
    # Every escape is uppercase hex, so two harnesses cannot spell the same
    # value two ways.
    for escape in re.findall(r"%(..)", encoded):
        assert escape == escape.upper() and all(
            c in "0123456789ABCDEF" for c in escape
        ), escape
    assert set(encoded) <= B1_DIAGNOSTIC_SAFE_CHARACTERS | {"%"}
    with pytest.raises(b1.B1PlacementParseError):
        _percent_encode_diagnostic(None)

    # (b) The sibling reader: canonical, CPU-id sorted, whole-field failure.
    cpu_root = tmp_path / "cpu"

    def _write_siblings(cpu: int, value: str) -> None:
        # The kernel's own directory name, `cpu<id>` — the reader must look
        # there and nowhere else.
        target = cpu_root / f"cpu{cpu}" / "topology"
        target.mkdir(parents=True, exist_ok=True)
        (target / "thread_siblings_list").write_text(value, encoding="utf-8")

    # A tree that omits the `cpu` prefix is not a sysfs tree: the reader must
    # fail rather than quietly report a partial or empty map.
    unprefixed = tmp_path / "unprefixed"
    (unprefixed / "0" / "topology").mkdir(parents=True)
    (unprefixed / "0" / "topology" / "thread_siblings_list").write_text(
        "0-1\n", encoding="utf-8"
    )
    with pytest.raises(OSError):
        _read_gateway_thread_siblings(frozenset({0}), cpu_root=unprefixed)

    _write_siblings(0, "0-1\n")
    _write_siblings(1, "0-1\n")
    assert _read_gateway_thread_siblings(
        frozenset({1, 0}), cpu_root=cpu_root
    ) == "0:0-1+1:0-1"
    # A comma-bearing kernel list survives canonicalization and is escaped only
    # at the encoder, never dropped.
    _write_siblings(8, "0,8\n")
    _write_siblings(0, "0,8\n")
    raw_map = _read_gateway_thread_siblings(frozenset({8, 0}), cpu_root=cpu_root)
    assert raw_map == "0:0,8+8:0,8"
    assert _percent_encode_diagnostic(raw_map) == "0:0%2C8+8:0%2C8"
    # Non-canonical but legal kernel spelling is canonicalized, not echoed.
    _write_siblings(2, "3,2\n")
    _write_siblings(3, "2-3\n")
    assert _read_gateway_thread_siblings(
        frozenset({2, 3}), cpu_root=cpu_root
    ) == "2:2-3+3:2-3"
    # A missing CPU, an unreadable file, an empty file, a malformed list and an
    # empty CPU set are each a whole-field failure -- never a partial map.
    for bad_cpus, label in (
        (frozenset({0, 99}), "missing cpu"),
        (frozenset(), "no gateway cpu"),
    ):
        with pytest.raises((OSError, b1.B1PlacementParseError)):
            _read_gateway_thread_siblings(bad_cpus, cpu_root=cpu_root)
    for bad_value, label in ((" ", "empty"), ("0--1\n", "malformed range"),
                             ("x\n", "non-decimal"), ("0,0\n", "duplicate")):
        _write_siblings(4, bad_value)
        with pytest.raises(b1.B1PlacementParseError):
            _read_gateway_thread_siblings(frozenset({4}), cpu_root=cpu_root)

    # (c) The spectre reader: whitespace collapsed, empty and missing refused.
    vuln_root = tmp_path / "vulnerabilities"
    vuln_root.mkdir()
    (vuln_root / "spectre_v2").write_text(
        "  Mitigation:  Enhanced / Automatic IBRS,\n IBPB: conditional \n", encoding="utf-8"
    )
    assert _read_spectre_v2(vulnerabilities_root=vuln_root) == (
        "Mitigation: Enhanced / Automatic IBRS, IBPB: conditional"
    )
    (vuln_root / "spectre_v2").write_text("   \n\t ", encoding="utf-8")
    with pytest.raises(b1.B1PlacementParseError):
        _read_spectre_v2(vulnerabilities_root=vuln_root)
    with pytest.raises(OSError):
        _read_spectre_v2(vulnerabilities_root=tmp_path / "absent")

    # (d) Every one of those failures reaches the record as `unavailable`,
    # with a note, through the one fail-soft boundary.
    notes: list[str] = []
    assert _try_diagnostic(
        "gateway thread_siblings_list", notes,
        lambda: _read_gateway_thread_siblings(frozenset({99}), cpu_root=cpu_root),
    ) is None
    assert _try_diagnostic(
        "spectre_v2", notes, lambda: _read_spectre_v2(vulnerabilities_root=vuln_root)
    ) is None
    assert len(notes) == 2 and all(note for note in notes)

    # (e) Rendering: present values are encoded in the pinned order; absent
    # ones are `unavailable`; the gating prefix is untouched either way.
    complete = (
        "usage_usec 12\nuser_usec 7\nsystem_usec 5\nnr_periods 3\n"
        "nr_throttled 1\nthrottled_usec 9\nnr_bursts 0\n"
    )
    later = complete.replace("usage_usec 12", "usage_usec 4012")
    rendered_roles = {
        role: _role_diagnostics(role, "max 100000", complete, later) for role in B1_ROLES
    }
    declaration = B1PlacementDeclaration.from_contract(_declaration_payload())
    line = _serialize_placement_fields(
        declaration, AUTHORITY_CI_SCALE_REFERENCE, _ci_scale_roles(), rendered_roles,
        {0: 10, 1: 20}, 0.5, 1.5,
        gateway_thread_siblings="0:0,8+8:0,8",
        spectre_v2="Mitigation: Enhanced IBRS, IBPB: conditional",
    )
    assert _parse_b1_env_field(line, "postgres_usage_usec") == "4000"
    assert _parse_b1_env_field(line, "gateway_thread_siblings_pct") == "0:0%2C8+8:0%2C8"
    spectre_field = _parse_b1_env_field(line, "spectre_v2_pct")
    assert urllib.parse.unquote(spectre_field) == (
        "Mitigation: Enhanced IBRS, IBPB: conditional"
    )
    # The escaping is what keeps the grammar intact: the two free-form values
    # carry commas, and the line still parses into its declared fields.
    for field_name in B1_PLACEMENT_FIELDS:
        assert _parse_b1_env_field(line, field_name) != ""
    positions = [line.index(f"{name}=") for name in B1_PLACEMENT_FIELDS]
    assert positions == sorted(positions), B1_PLACEMENT_FIELDS

    # Absent values render `unavailable`, and never a zero that would read like
    # a measurement.
    blank = _serialize_placement_fields(
        declaration, AUTHORITY_CI_SCALE_REFERENCE, _ci_scale_roles(),
        {role: _role_diagnostics(role, None, None, None) for role in B1_ROLES},
        None, None, None,
    )
    for field_name in ("postgres_usage_usec", "gateway_thread_siblings_pct",
                       "spectre_v2_pct"):
        assert f"{field_name}={DIAGNOSTIC_UNAVAILABLE}" in blank, field_name
        assert field_name in B1_DIAGNOSTIC_PLACEMENT_FIELDS
        assert field_name not in B1_GATING_PLACEMENT_FIELDS
    # Availability changes no gating field and no verdict.
    for field_name in B1_GATING_PLACEMENT_FIELDS:
        assert _parse_b1_env_field(line, field_name) == _parse_b1_env_field(
            blank, field_name
        ), field_name
    assert "placement_ok=1" in blank


def test_b1_placement_declarations_are_closed_and_pinned(tmp_path):
    """FP-GC1-1/2/3/4: both schema-2 declarations, closed against every drift."""
    # The Python constants are authoritative; the module bar literals and the
    # profile constants must agree, or a "green" run would be measuring a
    # different profile than the one the manifest advertises.
    assert CI_SCALE_PROFILE.rate == b1.CI_SCALE_BURST_RATE == 500
    assert CI_SCALE_PROFILE.seconds == b1.CI_SCALE_BURST_SECONDS == 30
    assert CI_SCALE_PROFILE.total_requests == CI_SCALE_TOTAL_REQUESTS == 15000
    assert CI_SCALE_PROFILE.total_requests == CI_SCALE_PROFILE.rate * CI_SCALE_PROFILE.seconds
    assert CI_SCALE_PROFILE.p99_ms == CI_SCALE_P99_MS == 150.0
    assert CI_SCALE_PROFILE.sustained_floor == CI_SCALE_SUSTAINED_FLOOR == 450
    assert CI_SCALE_PROFILE.max_in_flight == CI_SCALE_MAX_IN_FLIGHT == 500
    assert CI_SCALE_PROFILE.max_in_flight == CI_SCALE_PROFILE.rate  # one second of offer
    assert CI_SCALE_PROFILE.prologue_requests == 75 == int(500 * 150 / 1000)
    assert PRODUCT_PROFILE.rate == b1.BURST_RATE == 1000
    assert PRODUCT_PROFILE.total_requests == PRODUCT_TOTAL_REQUESTS == 30000
    assert PRODUCT_PROFILE.p99_ms == PRODUCT_P99_MS == 150.0
    assert PRODUCT_PROFILE.sustained_floor == PRODUCT_SUSTAINED_FLOOR == 200
    assert PRODUCT_PROFILE.max_in_flight == PRODUCT_MAX_IN_FLIGHT == 1000
    assert PRODUCT_PROFILE.prologue_requests == b1.PROLOGUE_REQUESTS == 150
    # The allocation is affinity cardinality, not a CPU quota. GC-3 (FP-GC3-4)
    # moved the CI-scale cardinality out of the profile: it is derived from the
    # ratified topology on the parsed contract, so the profile refuses to
    # answer at all rather than hand back a fixed 2/1/1 default.
    with pytest.raises(B1PlacementError, match="topology-derived"):
        CI_SCALE_PROFILE.affinity_cardinality
    assert PRODUCT_PROFILE.affinity_cardinality == {"gateway": 4, "postgres": 3, "driver": 1}
    assert PRODUCT_PROFILE.declared_cpu_total == 8

    ci = B1PlacementDeclaration.from_contract(_declaration_payload())
    assert ci.profile == CI_SCALE_PROFILE_NAME
    assert ci.schema == B1_TOPOLOGY_PLACEMENT_SCHEMA == 3 and ci.mechanism == "sched-affinity"
    assert ci.cardinality == {"gateway": 2, "postgres": 1, "driver": 1}
    assert ci.declared_cpu_total == 4
    assert ci.reference_logical_cpus == 4 and ci.minimum_host_logical_cpus is None
    assert ci.allowed("gateway") == frozenset({0, 1})
    assert ci.allowed("postgres") == frozenset({2})
    assert ci.allowed("driver") == frozenset({3})
    assert ci.declared_union == frozenset({0, 1, 2, 3})
    assert ci.driver_name == "dbagent-b1-driver-0123456789abcdef0123456789abcdef"
    assert ci.run_label == "dbagent.b1.run=0123456789abcdef0123456789abcdef"
    assert ci.role_label("gateway") == "dbagent.b1.role=gateway"
    assert ci.labels("driver") == {
        "dbagent.b1.run": "0123456789abcdef0123456789abcdef",
        "dbagent.b1.role": "driver",
    }
    prod = B1PlacementDeclaration.from_contract(_declaration_payload(PRODUCT_PROFILE_NAME))
    assert prod.minimum_host_logical_cpus == 8 and prod.reference_logical_cpus is None
    assert prod.allowed("gateway") == frozenset({0, 1, 2, 3})
    assert prod.allowed("driver") == frozenset({7})
    assert prod.declared_union == frozenset(range(8))
    # A many-core replica keeps the RELATIONSHIP, only the CPU identities move:
    # `gateway-core` over the sibling pairs (4,5) and (6,9) is the same class.
    shifted = probe.selected_contract(
        "gateway-core", ("4-5", "6,9"), "0123456789abcdef0123456789abcdef"
    )
    shifted_decl = B1PlacementDeclaration.from_contract(shifted)
    assert shifted_decl.allowed("driver") == frozenset({9})
    assert shifted_decl.allowed("gateway") == frozenset({4, 5})
    assert shifted_decl.topology == "gateway-core"

    def refuse(payload):
        with pytest.raises(B1PlacementError):
            B1PlacementDeclaration.from_contract(payload)

    refuse("not-an-object")
    refuse(_declaration_payload(profile="other"))
    # Schema 1 is rejected outright; nothing is migrated. So is the retired
    # schema-2 CI-scale document: this profile is schema 3 now, and there is no
    # compatibility reader for the allocation it used to carry.
    refuse(_declaration_payload(schema=1))
    refuse(_declaration_payload(schema=2))
    refuse(_declaration_payload(PRODUCT_PROFILE_NAME, schema=3))
    refuse(_declaration_payload(mechanism="cfs-quota"))
    refuse(_declaration_payload(mechanism="cpuset"))
    refuse(_declaration_payload(referenceLogicalCpus=8))
    refuse(_declaration_payload(PRODUCT_PROFILE_NAME, minimumHostLogicalCpus=4))
    for bad_id in ("", "0123456789ABCDEF0123456789ABCDEF", "0123",
                   "0123456789abcdef0123456789abcdeg", 7):
        refuse(_declaration_payload(runId=bad_id))
    extra = _declaration_payload()
    extra["unexpected"] = 1
    refuse(extra)
    # A reintroduced bandwidth key cannot enter through the contract.
    quota_key = _declaration_payload()
    quota_key["cpuPeriodUs"] = 100000
    refuse(quota_key)
    short = _declaration_payload()
    del short["mechanism"]
    refuse(short)
    wrong_capacity = _declaration_payload()
    del wrong_capacity["referenceLogicalCpus"]
    wrong_capacity["minimumHostLogicalCpus"] = 8
    refuse(wrong_capacity)
    for role in B1_ROLES:
        widened = _declaration_payload()
        widened["roles"][role]["quotaCpus"] = 2.0
        refuse(widened)
        missing_cpus = _declaration_payload()
        missing_cpus["roles"][role]["allowedCpus"] = None
        refuse(missing_cpus)
        noncanonical = _declaration_payload(PRODUCT_PROFILE_NAME)
        noncanonical["roles"][role]["allowedCpus"] = {
            "gateway": "0,1,2,3", "postgres": "4,5,6", "driver": "7",
        }[role] if role != "driver" else "07"
        refuse(noncanonical)
    dropped = _declaration_payload()
    del dropped["roles"]["driver"]
    refuse(dropped)
    # Cardinality, disjointness and union size, one at a time, both profiles.
    for profile, role, bad_list in (
        (CI_SCALE_PROFILE_NAME, "gateway", "0-2"),
        (CI_SCALE_PROFILE_NAME, "gateway", "0"),
        (CI_SCALE_PROFILE_NAME, "postgres", "2-3"),
        (CI_SCALE_PROFILE_NAME, "driver", "3-4"),
        (PRODUCT_PROFILE_NAME, "gateway", "0-4"),
        (PRODUCT_PROFILE_NAME, "postgres", "4-5"),
        (PRODUCT_PROFILE_NAME, "driver", "7-8"),
    ):
        drift = _declaration_payload(profile)
        drift["roles"][role]["allowedCpus"] = bad_list
        refuse(drift)
    for profile, role, overlapping in (
        (CI_SCALE_PROFILE_NAME, "postgres", "1"),
        (CI_SCALE_PROFILE_NAME, "driver", "0"),
        (PRODUCT_PROFILE_NAME, "postgres", "3-5"),
        (PRODUCT_PROFILE_NAME, "driver", "6"),
    ):
        overlap = _declaration_payload(profile)
        overlap["roles"][role]["allowedCpus"] = overlapping
        refuse(overlap)

    # The contract is read from the run mount, never invented.
    contract = tmp_path / "placement.json"
    contract.write_text(json.dumps(_declaration_payload()), encoding="utf-8")
    assert B1PlacementDeclaration.from_contract(_read_launch_contract(contract)).profile == "ci-scale"
    with pytest.raises(B1PlacementError):
        _read_launch_contract(tmp_path / "absent.json")
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    with pytest.raises(B1PlacementError):
        _read_launch_contract(broken)


def test_b1_driver_identity_requires_one_matching_name_and_label_pair():
    """FP-GC1-2: the two-label query is the identity; hostname never is."""
    declaration = B1PlacementDeclaration.from_contract(_declaration_payload())
    run_id = declaration.run_id
    good = _FakeContainer(declaration.driver_name,
                          {B1_RUN_LABEL_KEY: run_id, B1_ROLE_LABEL_KEY: "driver"})
    unrelated = _FakeContainer("someone-elses-container", {"app": "other"})
    other_run = _FakeContainer("dbagent-b1-driver-" + "f" * 32,
                               {B1_RUN_LABEL_KEY: "f" * 32, B1_ROLE_LABEL_KEY: "driver"})
    sibling = _FakeContainer("gw", {B1_RUN_LABEL_KEY: run_id, B1_ROLE_LABEL_KEY: "gateway"})

    client = _FakeClient([good, unrelated, other_run, sibling])
    assert _resolve_driver_container(client, declaration) is good
    assert client.containers.calls[-1][1]["label"] == [
        declaration.run_label, declaration.role_label("driver")
    ]

    with pytest.raises(B1PlacementError):  # zero matches
        _resolve_driver_container(_FakeClient([unrelated, other_run]), declaration)
    twin = _FakeContainer(declaration.driver_name,
                          {B1_RUN_LABEL_KEY: run_id, B1_ROLE_LABEL_KEY: "driver"})
    with pytest.raises(B1PlacementError):  # more than one match
        _resolve_driver_container(_FakeClient([good, twin]), declaration)
    misnamed = _FakeContainer("dbagent-b1-driver-something-else",
                              {B1_RUN_LABEL_KEY: run_id, B1_ROLE_LABEL_KEY: "driver"})
    with pytest.raises(B1PlacementError):  # label matches, derived name does not
        _resolve_driver_container(_FakeClient([misnamed]), declaration)

    mounted = good.with_mount("/host/repo", B1_WORKSPACE_MOUNT).with_mount(
        "/host/run", str(B1_RUN_MOUNT)
    ).with_mount("/var/run/docker.sock", B1_DOCKER_SOCKET)
    assert _driver_mount_source(mounted, B1_WORKSPACE_MOUNT) == "/host/repo"
    assert _driver_mount_source(mounted, str(B1_RUN_MOUNT)) == "/host/run"
    assert _driver_mount_source(mounted, B1_DOCKER_SOCKET) == "/var/run/docker.sock"
    with pytest.raises(B1PlacementError):
        _driver_mount_source(mounted, "/not-mounted")
    duplicated = _FakeContainer("d").with_mount("/a", "/workspace").with_mount("/b", "/workspace")
    with pytest.raises(B1PlacementError):
        _driver_mount_source(duplicated, B1_WORKSPACE_MOUNT)


def test_b1_placement_validator_rejects_each_role_drift():
    """FP-GC1-4: every affinity drift is named, one at a time, open and close."""
    ci_decl = B1PlacementDeclaration.from_contract(_declaration_payload())
    host = frozenset(range(4))
    # GC-3: the ordinary CI-scale declaration is schema 3, so the physical
    # sibling reading is GATING and the witness is given the observed groups.
    witness = B1PlacementWitness(
        ci_decl, host_cpus=host, sibling_groups=_gc3_sibling_groups()
    )
    workers = {12, 13, 14, 15}
    roles = _ci_scale_roles()
    assert witness.failures(roles, gateway_worker_pids=workers) == []
    assert witness.failures(roles, gateway_worker_pids=workers, when="close") == []

    # Authority is derived, never supplied.
    assert witness.authority(4) == AUTHORITY_CI_SCALE_REFERENCE
    assert witness.authority(16) == AUTHORITY_LOCAL_REPLICA
    assert witness.authority(3) == AUTHORITY_LOCAL_REPLICA

    # Role-by-role set mismatch, both directions of cardinality.
    for role, wrong in (
        ("gateway", (0, 2)),
        ("gateway", (0, 1, 2)),
        ("gateway", (0,)),
        ("postgres", (1,)),
        ("driver", (2,)),
    ):
        drifted = dict(roles)
        drifted[role] = _role(role, wrong, pids=roles[role].pids)
        found = witness.failures(drifted, gateway_worker_pids=workers)
        assert any(f.startswith(f"open: {role}: effective CPUs") for f in found), (role, found)
    for role, wrong in (("gateway", (0,)), ("postgres", (2, 3)), ("driver", (0, 3))):
        drifted = dict(roles)
        drifted[role] = _role(role, wrong, pids=roles[role].pids)
        found = witness.failures(drifted, gateway_worker_pids=workers)
        assert any("effective CPUs, profile" in f for f in found), (role, found)

    # Each of the three pairwise overlaps, independently.
    for left, right, shared in (
        ("gateway", "postgres", (0,)),
        ("gateway", "driver", (1,)),
        ("postgres", "driver", (2,)),
    ):
        overlapping = dict(roles)
        overlapping[right] = _role(right, shared, pids=roles[right].pids)
        found = witness.failures(overlapping, gateway_worker_pids=workers)
        assert any(f"{left}/{right}: measured roles share CPUs" in f for f in found), found

    # A CPU outside the host-visible inventory.
    outside = dict(roles)
    outside["driver"] = _role("driver", (99,))
    found = witness.failures(outside, gateway_worker_pids=workers)
    assert any("not a subset of the host-visible" in f for f in found), found

    for role in B1_ROLES:
        absent = {k: v for k, v in roles.items() if k != role}
        found = witness.failures(absent, gateway_worker_pids=workers)
        assert any(f == f"open: {role}: no effective placement reading" for f in found), found
        empty = dict(roles)
        empty[role] = B1RolePlacement(role=role, allowed_cpus=roles[role].allowed_cpus, pids=())
        found = witness.failures(empty, gateway_worker_pids=workers)
        assert any("no live process observed" in f for f in found), found

    found = witness.failures(roles, gateway_worker_pids={12, 13, 14})
    assert any("classified workers" in f for f in found), found
    found = witness.failures(roles, gateway_worker_pids={12, 13, 14, 99})
    assert any("carry no placement reading" in f for f in found), found
    tiny_host = B1PlacementWitness(ci_decl, host_cpus=frozenset({0, 1}))
    found = tiny_host.failures(roles, gateway_worker_pids=workers)
    assert any("needs at least 4" in f for f in found), found
    # The closing probe names its own phase, so drift is attributable.
    closing = witness.failures(
        {**roles, "gateway": _role("gateway", (0, 2), pids=roles["gateway"].pids)},
        gateway_worker_pids=workers, when="close",
    )
    assert any(f.startswith("close: gateway: effective CPUs") for f in closing), closing

    prod_decl = B1PlacementDeclaration.from_contract(_declaration_payload(PRODUCT_PROFILE_NAME))
    prod_host = frozenset(range(8))
    prod_witness = B1PlacementWitness(prod_decl, host_cpus=prod_host)
    assert prod_witness.authority(16) == AUTHORITY_PRODUCT_LOCAL
    prod_roles = _product_roles()
    assert prod_witness.failures(prod_roles, gateway_worker_pids={12, 13, 14, 15}) == []
    shared = dict(prod_roles)
    shared["postgres"] = _role("postgres", (3, 4, 5))
    found = prod_witness.failures(shared, gateway_worker_pids={12, 13, 14, 15})
    assert any("measured roles share CPUs" in f for f in found), found
    narrow = dict(prod_roles)
    narrow["gateway"] = _role("gateway", (0, 1, 2), pids=prod_roles["gateway"].pids)
    found = prod_witness.failures(narrow, gateway_worker_pids={12, 13, 14, 15})
    assert any("exclusive CPUs, product declares 4" in f for f in found), found
    moved = dict(prod_roles)
    moved["driver"] = _role("driver", (6,))
    found = prod_witness.failures(moved, gateway_worker_pids={12, 13, 14, 15})
    assert any("declared 7" in f for f in found), found
    small_host = B1PlacementWitness(prod_decl, host_cpus=frozenset(range(7)))
    found = small_host.failures(prod_roles, gateway_worker_pids={12, 13, 14, 15})
    assert any("needs at least 8" in f for f in found), found

    line = _placement_fingerprint(ci_decl, AUTHORITY_CI_SCALE_REFERENCE, roles, ["gateway: bad"])
    assert "placement_ok=0" in line and "failures=gateway: bad" in line
    assert "gateway_allowed_cpus=0-1" in line
    partial = _placement_fingerprint(
        ci_decl, AUTHORITY_LOCAL_REPLICA, {"gateway": roles["gateway"]}, ["driver: missing"]
    )
    assert "postgres_allowed_cpus=missing" in partial


def test_b1_container_cleanup_is_label_scoped_and_verified():
    """FP-GC1-2: reverse teardown, exact label scope, survivor failure."""
    declaration = B1PlacementDeclaration.from_contract(_declaration_payload())
    run_id = declaration.run_id
    driver = _FakeContainer(declaration.driver_name,
                            {B1_RUN_LABEL_KEY: run_id, B1_ROLE_LABEL_KEY: "driver"})
    unrelated = _FakeContainer("unrelated", {"app": "other"})
    other_run = _FakeContainer("old-gateway", {B1_RUN_LABEL_KEY: "e" * 32,
                                               B1_ROLE_LABEL_KEY: "gateway"})
    client = _FakeClient([driver, unrelated, other_run])
    _verify_no_survivors(client, declaration)  # the driver itself is not a survivor
    assert client.containers.calls[-1] == (True, {"label": [declaration.run_label]})
    # Unrelated containers and other runs are neither listed nor removed.
    assert unrelated in client.containers._listing and other_run in client.containers._listing

    survivor = _FakeContainer("gw", {B1_RUN_LABEL_KEY: run_id, B1_ROLE_LABEL_KEY: "gateway"})
    with pytest.raises(B1PlacementError, match="left containers behind"):
        _verify_no_survivors(_FakeClient([driver, survivor]), declaration)

    # Source-level ordering: the survivor check is registered first so it runs
    # last, and postgres is entered before the gateway so the gateway is
    # stopped first (reverse order).
    src = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    fixture = next(n for n in tree.body
                   if isinstance(n, ast.FunctionDef) and n.name == "_run_b1_reference")
    calls = [n for n in ast.walk(fixture) if isinstance(n, ast.Call)]

    def line_of(predicate):
        return next(n.lineno for n in calls if predicate(n))

    verify_at = line_of(lambda n: isinstance(n.func, ast.Attribute)
                        and n.func.attr == "callback"
                        and n.args and isinstance(n.args[0], ast.Name)
                        and n.args[0].id == "_verify_no_survivors")
    enters = [n.lineno for n in calls if isinstance(n.func, ast.Attribute)
              and n.func.attr == "enter_context"]
    assert verify_at < min(enters)
    postgres_enter = line_of(lambda n: isinstance(n.func, ast.Attribute)
                             and n.func.attr == "enter_context"
                             and n.args and isinstance(n.args[0], ast.Name)
                             and n.args[0].id == "postgres")
    gateway_enter = line_of(lambda n: isinstance(n.func, ast.Attribute)
                            and n.func.attr == "enter_context"
                            and n.args and isinstance(n.args[0], ast.Name)
                            and n.args[0].id == "gateway")
    assert postgres_enter < gateway_enter

    # The scoped Ryuk lifecycle: disabled for the sibling lifetime only, and
    # its prior value restored through the same stack.
    fixture_src = ast.get_source_segment(src, fixture)
    assert "previous_ryuk = testcontainers_config.ryuk_disabled" in fixture_src
    assert "testcontainers_config.ryuk_disabled = True" in fixture_src
    assert "stack.callback(_restore_ryuk, testcontainers_config, previous_ryuk)" in fixture_src
    config = SimpleNamespace(ryuk_disabled=False)
    _restore_ryuk(config, True)
    assert config.ryuk_disabled is True
    _restore_ryuk(config, False)
    assert config.ryuk_disabled is False


def test_b1_postgres_affinity_helper_is_closed_and_fails_partial_pin(tmp_path):
    """FP-GC1-3/4: label/PID resolution, tree walk, readback, closed interface."""
    helper = _load_affinity_helper()
    run_id = "0123456789abcdef0123456789abcdef"
    assert helper.parse_run_label(f"dbagent.b1.run={run_id}") == run_id
    for bad in ("dbagent.b1.role=postgres", run_id, f"dbagent.b1.run={run_id[:31]}",
                f"dbagent.b1.run={run_id.upper()}", "dbagent.b1.run="):
        with pytest.raises(helper.PinError):
            helper.parse_run_label(bad)
    # Both profiles' declared PostgreSQL lists go through the same helper.
    ci_decl = B1PlacementDeclaration.from_contract(_declaration_payload())
    prod_decl = B1PlacementDeclaration.from_contract(_declaration_payload(PRODUCT_PROFILE_NAME))
    assert helper.parse_cpu_list(b1.format_cpu_list(ci_decl.allowed("postgres"))) == [2]
    assert helper.parse_cpu_list(b1.format_cpu_list(prod_decl.allowed("postgres"))) == [4, 5, 6]
    assert helper.parse_cpu_list("4-6") == [4, 5, 6]
    assert helper.parse_cpu_list("0-1,7") == [0, 1, 7]
    for bad in ("", "a", "3-1", "0,0", "0 1", "1--2"):
        with pytest.raises(helper.PinError):
            helper.parse_cpu_list(bad)

    container = _FakeContainer("pg", {B1_RUN_LABEL_KEY: run_id, B1_ROLE_LABEL_KEY: "postgres"},
                               pid=4242)

    class _Getter:
        def __init__(self, found):
            self._found = found

        def get(self, _id):
            return self._found

    client = SimpleNamespace(containers=_Getter(container))
    assert helper.resolve_postgres_root_pid("pg", run_id, client=client) == 4242
    stale = _FakeContainer("pg", {B1_RUN_LABEL_KEY: "f" * 32, B1_ROLE_LABEL_KEY: "postgres"},
                           pid=1)
    with pytest.raises(helper.PinError):
        helper.resolve_postgres_root_pid("pg", run_id, client=SimpleNamespace(containers=_Getter(stale)))
    wrong_role = _FakeContainer("pg", {B1_RUN_LABEL_KEY: run_id, B1_ROLE_LABEL_KEY: "gateway"},
                                pid=1)
    with pytest.raises(helper.PinError):
        helper.resolve_postgres_root_pid("pg", run_id,
                                         client=SimpleNamespace(containers=_Getter(wrong_role)))
    dead = _FakeContainer("pg", {B1_RUN_LABEL_KEY: run_id, B1_ROLE_LABEL_KEY: "postgres"}, pid=0)
    with pytest.raises(helper.PinError):
        helper.resolve_postgres_root_pid("pg", run_id,
                                         client=SimpleNamespace(containers=_Getter(dead)))

    # Fake /proc: 100 -> {101, 102}; 102 -> {103}
    def write_tree(root, mapping):
        for pid, children in mapping.items():
            task = root / str(pid) / "task" / str(pid)
            task.mkdir(parents=True)
            (task / "children").write_text(" ".join(str(c) for c in children))

    proc = tmp_path / "proc"
    write_tree(proc, {100: [101, 102], 101: [], 102: [103], 103: []})
    assert helper.walk_process_tree(100, proc_root=proc) == [100, 101, 102, 103]
    assert helper.walk_process_tree(999, proc_root=proc) == []

    applied: dict[int, set[int]] = {}

    def setter(pid, cpus):
        if pid == 103:
            raise ProcessLookupError  # vanished mid-walk: not a live member
        applied[pid] = set(cpus)

    def getter(pid):
        return applied[pid]

    pinned = helper.pin_tree(100, [4, 5, 6], proc_root=proc,
                             set_affinity=setter, get_affinity=getter)
    assert pinned == [100, 101, 102]
    assert applied == {100: {4, 5, 6}, 101: {4, 5, 6}, 102: {4, 5, 6}}

    def refusing(pid, cpus):
        if pid == 102:
            raise OSError("EPERM")
        applied[pid] = set(cpus)

    with pytest.raises(helper.PinError, match="cannot set affinity"):
        helper.pin_tree(100, [4, 5, 6], proc_root=proc,
                        set_affinity=refusing, get_affinity=getter)

    def lying(pid):
        return {0} if pid == 101 else applied[pid]

    with pytest.raises(helper.PinError, match="read back"):
        helper.pin_tree(100, [4, 5, 6], proc_root=proc,
                        set_affinity=setter, get_affinity=lying)
    with pytest.raises(helper.PinError, match="not live"):
        helper.pin_tree(999, [4], proc_root=proc, set_affinity=setter, get_affinity=getter)

    # Closed interface: one subcommand, three positional operands, no escape
    # hatch for an arbitrary pid or command.
    assert helper.main(["pin-postgres", "pg", "4-6", f"dbagent.b1.run={run_id}"],
                       client=SimpleNamespace(containers=_Getter(dead))) == 1
    with pytest.raises(SystemExit):
        helper.main([])
    with pytest.raises(SystemExit):
        helper.main(["pin-pid", "1", "0"])
    with pytest.raises(SystemExit):
        helper.main(["pin-postgres", "pg", "4-6"])
    source = _AFFINITY_HELPER_PATH.read_text(encoding="utf-8")
    for forbidden in ("subprocess", "os.system", "eval(", "exec("):
        assert forbidden not in source, forbidden

    # The live fixture invokes the pin unconditionally -- there is no
    # per-profile branch that could leave a CI-scale PostgreSQL unpinned.
    fixture_src = ast.get_source_segment(
        Path(__file__).read_text(encoding="utf-8"),
        next(
            n for n in ast.parse(Path(__file__).read_text(encoding="utf-8")).body
            if isinstance(n, ast.FunctionDef) and n.name == "_run_b1_reference"
        ),
    )
    assert "_pin_postgres_tree(" in fixture_src
    calls = [
        n for n in ast.walk(ast.parse(textwrap.dedent(fixture_src)))
        if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "_pin_postgres_tree"
    ]
    assert len(calls) == 1, "the PostgreSQL pin must be applied exactly once, for both profiles"
    guarded = [
        n for n in ast.walk(ast.parse(textwrap.dedent(fixture_src)))
        if isinstance(n, ast.If)
        and any(isinstance(c, ast.Call) and getattr(c.func, "id", None) == "_pin_postgres_tree"
                for c in ast.walk(n))
    ]
    assert not guarded, "the PostgreSQL pin must not sit behind a profile condition"


def _fake_ci_scale_run(**overrides):
    values = {
        "offered": CI_SCALE_TOTAL_REQUESTS,
        "served": CI_SCALE_TOTAL_REQUESTS,
        "errors": 0,
        "p99": 100.0,
        "served_rate": 500.0,
        "max_in_flight": 499,
    }
    values.update(overrides)
    result = SimpleNamespace(**values)
    return {
        "result": result,
        "committed": overrides.get("committed", result.served),
        "placement_ok": overrides.get("placement_ok", True),
        "platform_online": overrides.get("platform_online", True),
        "worker_set_ok": overrides.get("worker_set_ok", True),
        "workers_pre": {1, 2, 3, 4},
        "workers_post": {1, 2, 3, 4},
        "fingerprint": "B1 env=placement_ok=1,",
    }


def test_b1_ci_scale_bar_boundaries():
    """FP-GC1-1: the gating CI-scale node is red on each boundary miss."""
    test_b1_ci_scale_reference_profile(_fake_ci_scale_run())
    # served rate: 450 passes, one ulp below it does not.
    test_b1_ci_scale_reference_profile(_fake_ci_scale_run(served_rate=450.0))
    with pytest.raises(AssertionError, match="served_rate"):
        test_b1_ci_scale_reference_profile(_fake_ci_scale_run(served_rate=449.999))
    # p99: strictly below 150 ms.
    test_b1_ci_scale_reference_profile(_fake_ci_scale_run(p99=149.999))
    with pytest.raises(AssertionError, match="p99"):
        test_b1_ci_scale_reference_profile(_fake_ci_scale_run(p99=150.0))
    # errors, offer completeness, accounting.
    with pytest.raises(AssertionError, match="errors"):
        test_b1_ci_scale_reference_profile(
            _fake_ci_scale_run(errors=1, served=CI_SCALE_TOTAL_REQUESTS - 1,
                               committed=CI_SCALE_TOTAL_REQUESTS - 1)
        )
    with pytest.raises(AssertionError, match="offered"):
        test_b1_ci_scale_reference_profile(
            _fake_ci_scale_run(offered=14999, served=14999, committed=14999)
        )
    with pytest.raises(AssertionError, match="served"):
        test_b1_ci_scale_reference_profile(
            _fake_ci_scale_run(served=14999, committed=14999)
        )
    with pytest.raises(AssertionError, match="committed"):
        test_b1_ci_scale_reference_profile(_fake_ci_scale_run(committed=14999))
    # the nonbinding outer gate at 500
    test_b1_ci_scale_reference_profile(_fake_ci_scale_run(max_in_flight=499))
    with pytest.raises(AssertionError, match="ceiling"):
        test_b1_ci_scale_reference_profile(_fake_ci_scale_run(max_in_flight=500))
    # placement, platform and worker-set preconditions
    with pytest.raises(AssertionError):
        test_b1_ci_scale_reference_profile(_fake_ci_scale_run(placement_ok=False))
    with pytest.raises(AssertionError):
        test_b1_ci_scale_reference_profile(_fake_ci_scale_run(platform_online=False))
    with pytest.raises(AssertionError, match="worker set"):
        test_b1_ci_scale_reference_profile(_fake_ci_scale_run(worker_set_ok=False))


def _fake_product_run(*, errors=0, p99=100.0, served=None, offered=PRODUCT_TOTAL_REQUESTS,
                      tokens=None, extra="", **overrides):
    served = offered - errors if served is None else served
    result = SimpleNamespace(
        offered=offered, served=served, errors=errors, p99=p99,
        served_rate=overrides.get("served_rate", 999.0),
        max_in_flight=overrides.get("max_in_flight", 999),
    )
    verdicts = _product_promise_verdicts(result)
    if tokens is not None:
        verdicts = OrderedDict(tokens)
    rendered = "".join(f"{k}={v}," for k, v in verdicts.items())
    line = (
        "B1 env=placement_ok=1,p99_ms=%.1f," % p99
        + rendered
        + extra
        + "p99_leg_split=0.000/0.000/0.000,leg_p99s=0.000/0.000/0.000"
    )
    return {
        "result": result,
        "committed": overrides.get("committed", served),
        "placement_ok": overrides.get("placement_ok", True),
        "platform_online": overrides.get("platform_online", True),
        "worker_set_ok": overrides.get("worker_set_ok", True),
        "workers_pre": {1, 2, 3, 4},
        "workers_post": {1, 2, 3, 4},
        "product_verdicts": dict(verdicts),
        "fingerprint": line,
    }


def test_b1_product_verdicts_record_met_and_missed_without_truth_gating():
    """FP-GC1-3/5: the three statuses are recorded data, not a bar.

    Positive controls first: a truthful ``missed`` for each comparison, one at
    a time, must leave the node green. Then every way of making the record
    dishonest -- a corrupted token, a literalized token that disagrees with its
    own operands, an absent field, a duplicated field, an unknown token -- must
    make it red.
    """
    # The evaluator itself, at the equality boundary of each operand.
    assert _product_promise_verdicts(
        SimpleNamespace(errors=0, p99=149.999, served=10, offered=10)
    ) == OrderedDict([
        ("product_errors_eq_zero", "met"),
        ("product_p99_lt_150_ms", "met"),
        ("product_served_eq_offered", "met"),
    ])
    assert _product_promise_verdicts(
        SimpleNamespace(errors=1, p99=150.0, served=9, offered=10)
    ) == OrderedDict([
        ("product_errors_eq_zero", "missed"),
        ("product_p99_lt_150_ms", "missed"),
        ("product_served_eq_offered", "missed"),
    ])
    assert tuple(_product_promise_verdicts(
        SimpleNamespace(errors=0, p99=1.0, served=1, offered=1)
    )) == PRODUCT_VERDICT_FIELDS

    # Positive controls: truthfully missed, one comparison at a time, green.
    test_b1_product_exclusive_reference_profile(_fake_product_run())
    test_b1_product_exclusive_reference_profile(
        _fake_product_run(errors=5, committed=PRODUCT_TOTAL_REQUESTS - 5)
    )
    test_b1_product_exclusive_reference_profile(_fake_product_run(p99=3000.0))
    # `served == offered` can only miss when an offer errored: the gating
    # identity served + errors == offered forbids an isolated shortfall, so
    # this control necessarily misses the error comparison too.
    shortfall = _fake_product_run(errors=1, committed=PRODUCT_TOTAL_REQUESTS - 1)
    assert shortfall["product_verdicts"]["product_served_eq_offered"] == "missed"
    assert shortfall["product_verdicts"]["product_p99_lt_150_ms"] == "met"
    test_b1_product_exclusive_reference_profile(shortfall)
    # ... and all three missed at once is still a valid record.
    run = _fake_product_run(errors=7, p99=9000.0,
                            committed=PRODUCT_TOTAL_REQUESTS - 7)
    assert set(run["product_verdicts"].values()) == {"missed"}
    test_b1_product_exclusive_reference_profile(run)

    # Corrupted token: serialized value disagrees with its live comparison.
    for field_name in PRODUCT_VERDICT_FIELDS:
        tokens = dict.fromkeys(PRODUCT_VERDICT_FIELDS, "met")
        tokens[field_name] = "missed"
        with pytest.raises(AssertionError, match=field_name):
            test_b1_product_exclusive_reference_profile(_fake_product_run(tokens=tokens))
    # Literalized token: p99 is genuinely missed but the record claims met.
    tokens = dict.fromkeys(PRODUCT_VERDICT_FIELDS, "met")
    with pytest.raises(AssertionError, match="product_p99_lt_150_ms"):
        test_b1_product_exclusive_reference_profile(
            _fake_product_run(p99=9000.0, tokens=tokens)
        )
    # Unknown token, absent field, duplicated field.
    with pytest.raises(AssertionError, match="product_errors_eq_zero"):
        test_b1_product_exclusive_reference_profile(
            _fake_product_run(tokens={**dict.fromkeys(PRODUCT_VERDICT_FIELDS, "met"),
                                      "product_errors_eq_zero": "unknown"})
        )
    for field_name in PRODUCT_VERDICT_FIELDS:
        tokens = {k: "met" for k in PRODUCT_VERDICT_FIELDS if k != field_name}
        with pytest.raises(AssertionError, match=field_name):
            test_b1_product_exclusive_reference_profile(_fake_product_run(tokens=tokens))
        with pytest.raises(AssertionError, match=field_name):
            test_b1_product_exclusive_reference_profile(
                _fake_product_run(extra=f"{field_name}=met,")
            )
    # Gating assertions are untouched by the recorded boundary.
    with pytest.raises(AssertionError):
        test_b1_product_exclusive_reference_profile(_fake_product_run(placement_ok=False))
    with pytest.raises(AssertionError, match="committed"):
        test_b1_product_exclusive_reference_profile(_fake_product_run(committed=17))
    with pytest.raises(AssertionError, match="served_rate"):
        test_b1_product_exclusive_reference_profile(_fake_product_run(served_rate=199.0))
    with pytest.raises(AssertionError, match="ceiling"):
        test_b1_product_exclusive_reference_profile(_fake_product_run(max_in_flight=1000))
    with pytest.raises(AssertionError, match="offered"):
        test_b1_product_exclusive_reference_profile(
            _fake_product_run(offered=29999, served=29999, committed=29999)
        )

    # The serializer is closed over the exact ordered field set and token set.
    assert serialize_product_verdicts({}) == ""
    assert serialize_product_verdicts(
        OrderedDict((name, "met") for name in PRODUCT_VERDICT_FIELDS)
    ) == "product_errors_eq_zero=met,product_p99_lt_150_ms=met,product_served_eq_offered=met,"
    with pytest.raises(B1PlacementError):
        serialize_product_verdicts({"product_errors_eq_zero": "met"})
    with pytest.raises(B1PlacementError):
        serialize_product_verdicts(
            OrderedDict((name, "yes") for name in PRODUCT_VERDICT_FIELDS)
        )
    reordered = OrderedDict((name, "met") for name in reversed(PRODUCT_VERDICT_FIELDS))
    with pytest.raises(B1PlacementError):
        serialize_product_verdicts(reordered)


# ---------------------------------------------------------------------------
# GC-3 (UT) — the closed candidate space, the schema-3 contract, the discovery
# artifact and the immutable selector.
#
# Every case here is deterministic and container-free: sysfs is a temporary
# directory, records are dictionaries, and no test needs the host to expose SMT
# or Docker. That is deliberate -- this is the code that decides which
# measurement is admissible, so it must be provable without a measurement.
# ---------------------------------------------------------------------------

_GC3_PAIRS = ((0, 1), (2, 3))
_GC3_REFERENCE = "0-3"
_GC3_SHA = "a" * 40
# Two exact model strings used as FIXTURE DATA, and DELIBERATELY FICTIONAL.
# Nothing in `b1_topology_probe` compares a model against a literal -- the pair
# admission rule is "both artifacts carry the same validated model" -- so a
# real SKU here would only invite a reader to think one was privileged, and
# would make a grep for a real SKU in this file ambiguous. They still satisfy
# `validate_cpu_model`'s closed text rules (nonempty, not the `unknown`
# sentinel, within the code-point ceiling, no control character,
# whitespace-canonical), because the tests below depend on them being
# decision-eligible; and they carry mixed case and a trailing size suffix so
# the no-fallback cases can build a genuine case-fold variant and a genuine
# proper prefix out of them.
_GC3_MODEL = "TEST-MODEL-A Fictional 4-Core Processor"
_GC3_OTHER_MODEL = "TEST-MODEL-B Fictional 8-Core Processor"


def _gc3_sysfs(tmp_path: Path, groups: "dict[int, str]") -> Path:
    root = tmp_path / "cpu"
    for cpu, rendered in groups.items():
        target = root / f"cpu{cpu}" / "topology"
        target.mkdir(parents=True, exist_ok=True)
        (target / "thread_siblings_list").write_text(rendered + "\n", encoding="utf-8")
    return root


def _gc3_sibling_groups(pairs=_GC3_PAIRS) -> "dict[int, frozenset[int]]":
    out: dict[int, frozenset[int]] = {}
    for pair in pairs:
        for cpu in pair:
            out[cpu] = frozenset(pair)
    return out


def _gc3_run_id(index: int, salt: int = 0) -> str:
    return f"{index:02d}{salt:02d}" + "f" * 28


def _gc3_operands(**overrides) -> dict:
    operands = {
        "offered": 15000,
        "served": 15000,
        "errors": 0,
        "committed": 15000,
        "p99Ms": 12.5,
        "servedRate": 500.0,
        "maxInFlight": 42,
        "platformOnline": True,
        "workerSetStable": True,
    }
    operands.update(overrides)
    return operands


def _gc3_record(index: int, *, salt: int = 0, pairs=_GC3_PAIRS, operands=None,
                cpu_model: str = _GC3_MODEL, head: str = _GC3_SHA, **overrides) -> dict:
    arm = probe.enumerate_arms(*pairs)[index]
    groups = _gc3_sibling_groups(pairs)
    values = _gc3_operands() if operands is None else dict(operands)
    roles = dict(arm["roles"])
    record = {
        "index": index,
        "runId": _gc3_run_id(index, salt),
        "topology": arm["topology"],
        "round": arm["round"],
        "orientation": arm["orientation"],
        "profile": probe.PROBE_PROFILE_NAME,
        "referenceCpus": arm["referenceCpus"],
        "declaredRoles": roles,
        "effectiveRoles": dict(roles),
        "unassignedCpus": arm["unassignedCpus"],
        "siblingMap": {
            role: probe.serialize_sibling_map(probe.parse_cpu_list(roles[role]), groups)
            for role in probe.ROLES
        },
        "referenceSiblingMap": probe.serialize_sibling_map(sorted(groups), groups),
        "fingerprint": "B1 env=cpus=4,...",
        "operands": values,
        "verdicts": probe.evaluate_verdicts(values),
        "verdictLine": probe.serialize_verdicts(probe.evaluate_verdicts(values)),
        "spanSeconds": 30.0,
        "postgresUsageUsec": 14220078,
        "gatewayCpuCoresUsed": 0.38,
        "measurementAuthority": AUTHORITY_CI_SCALE_REFERENCE,
        "cpuModel": cpu_model,
        "logicalCpuCount": 4,
        "siblingPairs": [probe.format_cpu_list(pair) for pair in pairs],
        "headSha": head,
        "githubRunId": "1",
        "githubRunAttempt": "1",
        "githubJob": probe.PROBE_JOB,
        "notes": [],
    }
    record.update(overrides)
    return record


def _gc3_plan(run_id: str = "1", *, cpu_model: str = _GC3_MODEL,
              head: str = _GC3_SHA) -> dict:
    return {
        "topologySetVersion": probe.TOPOLOGY_SET_VERSION,
        "identity": {
            "headSha": head,
            "githubRunId": run_id,
            "githubRunAttempt": "1",
            "githubJob": probe.PROBE_JOB,
            "cpuModel": cpu_model,
            "logicalCpuCount": 4,
            "referenceCpus": _GC3_REFERENCE,
            "siblingPairs": [probe.format_cpu_list(pair) for pair in _GC3_PAIRS],
        },
        "siblingPairs": [list(pair) for pair in _GC3_PAIRS],
        "arms": list(probe.enumerate_arms(*_GC3_PAIRS)),
    }


def _gc3_artifact(run_id: str = "1", *, per_arm=None, cpu_model: str = _GC3_MODEL,
                  head: str = _GC3_SHA) -> dict:
    records = []
    for index in range(probe.ARMS_PER_ARTIFACT):
        operands = per_arm(index) if per_arm else None
        record = _gc3_record(
            index, salt=int(run_id), operands=operands, cpu_model=cpu_model, head=head
        )
        record["githubRunId"] = run_id
        records.append(record)
    return probe.collect_artifact(
        _gc3_plan(run_id, cpu_model=cpu_model, head=head), records
    )


def _gc3_wrapper(artifact: dict, path: Path) -> dict:
    """One embedded evidence wrapper, computed test-side from public helpers."""
    return {
        "sourceUrl": (
            f"https://github.com/yabinma/dbagent/actions/runs/{artifact['githubRunId']}"
        ),
        "sha256": hashlib.sha256(
            probe.canonical_json(artifact).encode("utf-8")
        ).hexdigest(),
        "artifact": artifact,
    }


def _gc3_seed_carrier(path: Path, *pairs) -> Path:
    """A valid schema-3 base carrier, assembled HERE from the real selector.

    `decide` requires `--base`: rev 0.8 deliberately exposes no no-base
    initialisation path, because omitting the base could construct a
    one-model replacement that looked valid while discarding every other
    model and every history. A fixture that needs a starting carrier therefore
    builds one out of the selector's own result and proves it valid -- the
    module itself never offers that route.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    models: dict[str, dict] = {}
    for first, second in pairs:
        first, second = sorted(
            (first, second), key=lambda artifact: int(artifact["githubRunId"])
        )
        first_path = path.parent / f"seed-{first['githubRunId']}.json"
        second_path = path.parent / f"seed-{second['githubRunId']}.json"
        probe.write_artifact(first_path, first)
        probe.write_artifact(second_path, second)
        model = probe.admit_evidence(first, second)
        entry = probe.select_topology(first, second)
        entry["artifacts"] = [
            _gc3_wrapper(first, first_path), _gc3_wrapper(second, second_path)
        ]
        entry["superseded"] = []
        models[model] = entry
    carrier = {
        "schema": probe.DECISION_SCHEMA,
        "topologySetVersion": probe.TOPOLOGY_SET_VERSION,
        "models": models,
    }
    probe.validate_decision(carrier)
    probe.write_canonical(path, carrier)
    return path


def _gc3_carrier(tmp_path: Path, *pairs, out_name: str = "b1_topology_decision.json") -> Path:
    """A model-keyed carrier: one seeded model, then one `--pair` per model.

    Every merge step writes to its OWN output: `--out` and `--base` must
    resolve to different paths, so a base is read and never rewritten.
    """
    tmp_path = Path(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    out = tmp_path / out_name
    first_pair, *rest = pairs
    base = _gc3_seed_carrier(tmp_path / f"seed-{out_name}", first_pair)
    for index, (first, second) in enumerate(rest):
        first_path = tmp_path / f"artifact-{index}-a.json"
        second_path = tmp_path / f"artifact-{index}-b.json"
        probe.write_artifact(first_path, first)
        probe.write_artifact(second_path, second)
        step = tmp_path / f"merged-{index}.json"
        assert probe.main([
            "decide", "--out", str(step), "--base", str(base),
            "--pair", str(first_path), str(second_path),
        ]) == 0
        base = step
    out.write_text(Path(base).read_text(encoding="utf-8"), encoding="utf-8")
    return out


def test_gc3_thread_sibling_reader_accepts_only_two_symmetric_pairs(tmp_path):
    """FP-GC3-1/5: the physical reading is exact, or it is not a pair at all."""
    # Sparse, non-contiguous ids: the i7 replica's (0,8) and (1,9) shape.
    root = _gc3_sysfs(tmp_path, {0: "0,8", 8: "0,8", 1: "1,9", 9: "1,9"})
    assert probe.read_thread_siblings(0, cpu_root=root) == frozenset({0, 8})
    assert probe.complete_sibling_pairs([0, 1, 8, 9], cpu_root=root) == ((0, 8), (1, 9))
    assert probe.reference_pairs([9, 1, 8, 0], cpu_root=root) == ((0, 8), (1, 9))
    # The pair order is by minimum id, regardless of the order asked for.
    assert probe.complete_sibling_pairs([9, 8, 1, 0], cpu_root=root) == ((0, 8), (1, 9))
    # A member outside the allowed set is not a complete pair.
    assert probe.complete_sibling_pairs([0, 1, 9], cpu_root=root) == ((1, 9),)
    with pytest.raises(probe.TopologyProbeError, match="complete two-thread sibling pair"):
        probe.reference_pairs([0, 1, 9], cpu_root=root)

    # Asymmetric: cpu 2 claims 2-3, cpu 3 claims only itself.
    asym = _gc3_sysfs(tmp_path / "asym", {2: "2-3", 3: "3"})
    assert probe.complete_sibling_pairs([2, 3], cpu_root=asym) == ()
    # Singleton (SMT disabled) is not a pair.
    single = _gc3_sysfs(tmp_path / "single", {0: "0", 1: "1", 2: "2", 3: "3"})
    assert probe.complete_sibling_pairs([0, 1, 2, 3], cpu_root=single) == ()
    with pytest.raises(probe.TopologyProbeError):
        probe.reference_pairs([0, 1, 2, 3], cpu_root=single)
    # Three-way group (not two threads) is not a pair either.
    triple = _gc3_sysfs(tmp_path / "triple", {0: "0-2", 1: "0-2", 2: "0-2"})
    assert probe.complete_sibling_pairs([0, 1, 2], cpu_root=triple) == ()
    # Missing file, non-canonical text, and a list excluding its own cpu.
    missing = _gc3_sysfs(tmp_path / "missing", {0: "0-1"})
    with pytest.raises(probe.TopologyProbeError, match="cannot read"):
        probe.read_thread_siblings(7, cpu_root=missing)
    noncanonical = _gc3_sysfs(tmp_path / "noncanon", {0: "0,1"})
    with pytest.raises(probe.TopologyProbeError, match="non-canonical"):
        probe.read_thread_siblings(0, cpu_root=noncanonical)
    foreign = _gc3_sysfs(tmp_path / "foreign", {0: "4-5"})
    with pytest.raises(probe.TopologyProbeError, match="excludes cpu 0"):
        probe.read_thread_siblings(0, cpu_root=foreign)

    # The rendered map round-trips exactly, and refuses every other shape.
    groups = _gc3_sibling_groups()
    rendered = probe.serialize_sibling_map([0, 1], groups)
    assert rendered == "0:0-1+1:0-1"
    assert probe.parse_sibling_map(rendered) == {0: frozenset({0, 1}), 1: frozenset({0, 1})}
    for bad in ("1:0-1+0:0-1", "0:0-1+0:0-1", "x:0-1", "0:", "0:2-3", ""):
        with pytest.raises(probe.TopologyProbeError):
            probe.parse_sibling_map(bad)
    with pytest.raises(probe.TopologyProbeError, match="no sibling reading"):
        probe.serialize_sibling_map([7], groups)
    with pytest.raises(probe.TopologyProbeError, match="no CPU"):
        probe.serialize_sibling_map([], groups)

    # The opening/closing witness: drift, asymmetry and a missing reading all
    # prevent a verdict rather than downgrading the check.
    contract = probe.arm_contract(probe.enumerate_arms(*_GC3_PAIRS)[2], _gc3_run_id(2))
    declaration = B1PlacementDeclaration.from_contract(contract)
    observed = {role: declaration.allowed(role) for role in B1_ROLES}
    witness = B1PlacementWitness(
        declaration, host_cpus=frozenset(range(4)), sibling_groups=groups
    )
    assert witness._topology_failures(observed, when="open") == []
    blind = B1PlacementWitness(declaration, host_cpus=frozenset(range(4)))
    assert any("no thread_siblings_list" in f for f in blind._topology_failures(observed, when="open"))
    partial = B1PlacementWitness(
        declaration, host_cpus=frozenset(range(4)),
        sibling_groups={0: frozenset({0, 1}), 1: frozenset({0, 1})},
    )
    assert any("sibling reading covers" in f for f in partial._topology_failures(observed, when="open"))
    lonely = dict(groups)
    lonely[2] = frozenset({2})
    lone_witness = B1PlacementWitness(
        declaration, host_cpus=frozenset(range(4)), sibling_groups=lonely
    )
    assert any("thread sibling" in f for f in lone_witness._topology_failures(observed, when="open"))
    crossed = {0: frozenset({0, 2}), 2: frozenset({0, 2}), 1: frozenset({1, 3}), 3: frozenset({1, 3})}
    crossed_witness = B1PlacementWitness(
        declaration, host_cpus=frozenset(range(4)), sibling_groups=crossed
    )
    # gateway-core over the (0,2)/(1,3) pairing is a different relationship.
    assert any("topology:" in f for f in crossed_witness._topology_failures(observed, when="close"))
    # An effective set that is not the declared one is caught too.
    moved = dict(observed)
    moved["gateway"] = frozenset({0, 2})
    moved["postgres"] = frozenset({1})
    assert witness._topology_failures(moved, when="close") != []


def test_gc3_topology_enumerator_is_closed_and_complete():
    """FP-GC3-1: seven classes, two orientations, two reversed rounds, 28 arms."""
    assert probe.TOPOLOGY_IDS == tuple(sorted(probe.TOPOLOGY_CLASSES))
    assert len(probe.TOPOLOGY_IDS) == 7
    assert probe.ARMS_PER_ARTIFACT == 28

    expected_cardinalities = {
        "gateway-core": {"gateway": 2, "postgres": 1, "driver": 1},
        "gateway-split": {"gateway": 2, "postgres": 1, "driver": 1},
        "postgres-core": {"gateway": 1, "postgres": 2, "driver": 1},
        "postgres-split": {"gateway": 1, "postgres": 2, "driver": 1},
        "postgres-isolated": {"gateway": 1, "postgres": 1, "driver": 1},
        "driver-isolated": {"gateway": 1, "postgres": 1, "driver": 1},
        "gateway-isolated": {"gateway": 1, "postgres": 1, "driver": 1},
    }
    for topology, cardinality in expected_cardinalities.items():
        assert probe.topology_cardinality(topology) == cardinality, topology
        idle = probe.topology_unassigned_cardinality(topology)
        assert idle == (0 if sum(cardinality.values()) == 4 else 1), topology
        assert sum(cardinality.values()) + idle == 4, topology
    with pytest.raises(probe.TopologyProbeError, match="unknown topology"):
        probe.topology_cardinality("gateway-hyperthread")

    # The same 28 relationships on two different physical hosts.
    for pairs in (_GC3_PAIRS, ((0, 8), (1, 9))):
        arms = probe.enumerate_arms(*pairs)
        assert len(arms) == 28
        keys = [(a["topology"], a["round"], a["orientation"]) for a in arms]
        assert len(set(keys)) == 28
        assert keys[:2] == [(probe.TOPOLOGY_IDS[0], 0, 0), (probe.TOPOLOGY_IDS[0], 0, 1)]
        assert keys[14:16] == [(probe.TOPOLOGY_IDS[-1], 1, 1), (probe.TOPOLOGY_IDS[-1], 1, 0)]
        # Round 1 reverses the class order, so no class owns only late arms.
        assert [k[0] for k in keys[:14:2]] == list(probe.TOPOLOGY_IDS)
        assert [k[0] for k in keys[14::2]] == list(reversed(probe.TOPOLOGY_IDS))
        reference = frozenset(cpu for pair in pairs for cpu in pair)
        for arm in arms:
            roles = {r: probe.parse_cpu_list(arm["roles"][r]) for r in probe.ROLES}
            assert len(roles["driver"]) == 1, arm
            assert 1 <= len(roles["gateway"]) <= 2 and 1 <= len(roles["postgres"]) <= 2
            union = roles["gateway"] | roles["postgres"] | roles["driver"]
            assert len(union) == sum(len(v) for v in roles.values()), arm
            assert union <= reference
            idle = reference - union
            assert len(idle) <= 1
            assert arm["unassignedCpus"] == (probe.format_cpu_list(idle) if idle else "none")
            assert arm["referenceCpus"] == probe.format_cpu_list(reference)

    # Orientation 1 is the (a,b,c,d) -> (d,c,b,a) renaming, both core order and
    # sibling-thread order.
    zero = probe.orientation_positions(*_GC3_PAIRS, 0)
    one = probe.orientation_positions(*_GC3_PAIRS, 1)
    assert zero == {"a": 0, "b": 1, "c": 2, "d": 3}
    assert one == {"a": 3, "b": 2, "c": 1, "d": 0}
    assert probe.topology_mapping("gateway-core", *_GC3_PAIRS, 0)["gateway"] == frozenset({0, 1})
    assert probe.topology_mapping("gateway-core", *_GC3_PAIRS, 1)["gateway"] == frozenset({2, 3})
    for bad in (2, -1, "0"):
        with pytest.raises(probe.TopologyProbeError, match="orientation"):
            probe.orientation_positions(*_GC3_PAIRS, bad)
    with pytest.raises(probe.TopologyProbeError, match="2-tuple"):
        probe.orientation_positions((0, 1, 2), (2, 3), 0)
    with pytest.raises(probe.TopologyProbeError, match="internally ordered"):
        probe.orientation_positions((1, 0), (2, 3), 0)
    with pytest.raises(probe.TopologyProbeError, match="disjoint"):
        probe.orientation_positions((0, 1), (1, 2), 0)

    # No caller-supplied value can widen the set: a class that gives the driver
    # two CPUs, or overlaps two measured roles, is refused by the same checker
    # the enumerator runs on every arm.
    with pytest.raises(probe.TopologyProbeError, match="driver must hold exactly one"):
        probe._check_mapping(
            "gateway-core",
            {"gateway": frozenset({0}), "postgres": frozenset({1}),
             "driver": frozenset({2, 3}), "unassigned": frozenset()},
            frozenset(range(4)),
        )
    with pytest.raises(probe.TopologyProbeError, match="overlap"):
        probe._check_mapping(
            "postgres-isolated",
            {"gateway": frozenset({0}), "postgres": frozenset({0}),
             "driver": frozenset({1}), "unassigned": frozenset({2})},
            frozenset(range(4)),
        )

    # The CPU-list codec agrees with the harness's own, on every shape either
    # accepts -- the planner cannot import the driver's third-party stack.
    for rendered in ("0", "0-3", "0,8", "0-1,8-9", "2-3", "0,2,8"):
        assert probe.parse_cpu_list(rendered) == b1.parse_cpu_list(rendered)
        assert probe.format_cpu_list(probe.parse_cpu_list(rendered)) == rendered
    for bad in ("", " 0 , 1", "1-0", "0,0", "a", "0--1", 7):
        with pytest.raises(probe.TopologyProbeError):
            probe.parse_cpu_list(bad)
    for bad_set in (set(), {-1}, {True}):
        with pytest.raises(probe.TopologyProbeError):
            probe.format_cpu_list(bad_set)


def test_gc3_schema3_contract_rejects_mapping_and_topology_drift():
    """FP-GC3-1/4/5: the closed contract, and the schema-2 profiles beside it."""
    arm = probe.enumerate_arms(*_GC3_PAIRS)[2]
    run_id = _gc3_run_id(2)
    contract = probe.arm_contract(arm, run_id)
    assert set(contract) == probe.PROBE_CONTRACT_KEYS
    assert contract["schema"] == 3 and contract["profile"] == probe.PROBE_PROFILE_NAME
    parsed = probe.parse_arm_contract(contract, pairs=_GC3_PAIRS)
    assert parsed["roles"]["gateway"] == frozenset({0, 1})
    assert parsed["unassigned"] == frozenset()
    with pytest.raises(probe.TopologyProbeError, match="32 lowercase hex"):
        probe.arm_contract(arm, "short")

    def mutate(**changes):
        payload = json.loads(json.dumps(contract))
        for key, value in changes.items():
            if value is _GC3_DROP:
                payload.pop(key)
            else:
                payload[key] = value
        return payload

    for changes, pattern in (
        ({"schema": 2}, "schema"),
        ({"profile": "ci-scale"}, "profile"),
        ({"mechanism": "cfs-quota"}, "mechanism"),
        ({"referenceLogicalCpus": 8}, "referenceLogicalCpus"),
        ({"runId": "Z" * 32}, "runId"),
        ({"topology": "gateway-hyperthread"}, "unknown topology"),
        ({"round": 2}, "round"),
        ({"round": True}, "round"),
        ({"orientation": 3}, "orientation"),
        ({"referenceCpus": "0,1,2,3"}, "canonical"),
        ({"referenceCpus": "0-2"}, "not 4"),
        ({"extra": 1}, "closed schema-3"),
        ({"roles": _GC3_DROP}, "closed schema-3"),
    ):
        with pytest.raises(probe.TopologyProbeError, match=pattern):
            probe.parse_arm_contract(mutate(**changes))
    with pytest.raises(probe.TopologyProbeError, match="not a JSON object"):
        probe.parse_arm_contract(["nope"])
    with pytest.raises(probe.TopologyProbeError, match="exactly"):
        probe.parse_arm_contract(mutate(roles={"gateway": {"allowedCpus": "0"}}))
    with pytest.raises(probe.TopologyProbeError, match="allowedCpus"):
        probe.parse_arm_contract(
            mutate(roles={**contract["roles"], "driver": {"cpus": "3"}})
        )
    with pytest.raises(probe.TopologyProbeError, match="canonical"):
        probe.parse_arm_contract(
            mutate(roles={**contract["roles"], "gateway": {"allowedCpus": "0,1"}})
        )
    with pytest.raises(probe.TopologyProbeError, match="inside referenceCpus"):
        probe.parse_arm_contract(
            mutate(roles={**contract["roles"], "driver": {"allowedCpus": "9"}})
        )
    # Right cardinalities, wrong relationship: gateway-core demands the two
    # threads of ONE core, and over the (0,1)/(2,3) pairing `0,2` is not that.
    swapped = mutate(roles={
        "gateway": {"allowedCpus": "0,2"},
        "postgres": {"allowedCpus": "1"},
        "driver": {"allowedCpus": "3"},
    })
    with pytest.raises(probe.TopologyProbeError, match="enumerator derives"):
        probe.parse_arm_contract(swapped, pairs=_GC3_PAIRS)
    # Overlap and a second unassigned CPU are refused by the shared checker.
    with pytest.raises(probe.TopologyProbeError, match="overlap"):
        probe.parse_arm_contract(mutate(roles={
            "gateway": {"allowedCpus": "0-1"},
            "postgres": {"allowedCpus": "1"},
            "driver": {"allowedCpus": "3"},
        }), pairs=_GC3_PAIRS)

    # The declaration the harness speaks, built from that same parse.
    declaration = B1PlacementDeclaration.from_contract(contract)
    assert declaration.carries_topology
    assert declaration.schema == B1_TOPOLOGY_PLACEMENT_SCHEMA == 3
    assert declaration.topology == "gateway-core"
    assert declaration.cardinality == {"gateway": 2, "postgres": 1, "driver": 1}
    assert declaration.declared_cpu_total == 4
    assert declaration.reference_cpus == frozenset(range(4))
    assert declaration.unassigned_cpus == frozenset()
    assert declaration.run_id == run_id
    # An isolated class leaves exactly one reference CPU outside every role.
    isolated = probe.arm_contract(probe.enumerate_arms(*_GC3_PAIRS)[0], _gc3_run_id(0))
    isolated_decl = B1PlacementDeclaration.from_contract(isolated)
    assert isolated_decl.topology == "driver-isolated"
    assert isolated_decl.unassigned_cpus == frozenset({3})
    assert isolated_decl.declared_cpu_total == 3
    with pytest.raises(B1PlacementError, match="unknown topology"):
        B1PlacementDeclaration.from_contract(
            {**contract, "topology": "gateway-hyperthread"}
        )

    # --- the ordinary ratified gate's contract (FP-GC3-4) ------------------
    # `contract-selected` renders one class over the OBSERVED pairs at the
    # fixed orientation 0, writes the ordinary `ci-scale` schema-3 document
    # (no round, no orientation) and prints only the driver CPU list.
    selected = probe.selected_contract("postgres-core", ("0-1", "2-3"), _gc3_run_id(7))
    assert set(selected) == probe.SELECTED_CONTRACT_KEYS
    assert "round" not in selected and "orientation" not in selected
    assert selected["schema"] == 3 and selected["profile"] == probe.SELECTED_PROFILE_NAME
    expected_map = probe.topology_mapping("postgres-core", (0, 1), (2, 3), 0)
    for role in probe.ROLES:
        assert selected["roles"][role]["allowedCpus"] == probe.format_cpu_list(
            expected_map[role]
        )
    reparsed = probe.parse_selected_contract(selected, pairs=("0-1", "2-3"))
    assert reparsed["topology"] == "postgres-core"
    assert reparsed["round"] is None and reparsed["orientation"] is None
    assert probe.parse_contract(selected, pairs=("0-1", "2-3"))["roles"] == reparsed["roles"]
    # Sparse, non-contiguous sibling ids -- the i7 replica shape -- render the
    # same RELATIONSHIP over different CPU ids.
    sparse = probe.selected_contract("gateway-core", ("1,9", "0,8"), _gc3_run_id(8))
    assert sparse["referenceCpus"] == "0-1,8-9"
    assert sparse["roles"]["gateway"]["allowedCpus"] == "0,8"
    probe.parse_selected_contract(sparse, pairs=("0,8", "1,9"))
    # It authors nothing else: an unknown class, a bad run id, overlapping or
    # single-CPU pairs are refused rather than repaired.
    for topology, pairs, run_id, pattern in (
        ("gateway-hyperthread", ("0-1", "2-3"), _gc3_run_id(9), "unknown topology"),
        ("gateway-core", ("0-1", "2-3"), "short", "32 lowercase hex"),
        ("gateway-core", ("0-1", "1-2"), _gc3_run_id(9), "not disjoint"),
        ("gateway-core", ("0", "2-3"), _gc3_run_id(9), "not two CPUs"),
        ("gateway-core", ("0-1",), _gc3_run_id(9), "exactly two sibling pairs"),
    ):
        with pytest.raises(probe.TopologyProbeError, match=pattern):
            probe.selected_contract(topology, pairs, run_id)
    # A selected contract that carries an arm position is not this document.
    with pytest.raises(probe.TopologyProbeError, match="closed schema-3"):
        probe.parse_selected_contract({**selected, "round": 0, "orientation": 0})
    # ...and an arm contract is not the gate's document either.
    with pytest.raises(probe.TopologyProbeError, match="profile"):
        probe.parse_selected_contract(contract)
    # The declaration the harness builds from it is the ordinary CI-scale one,
    # at schema 3, with a topology-derived cardinality and no fixed default.
    selected_decl = B1PlacementDeclaration.from_contract(selected)
    assert selected_decl.profile == CI_SCALE_PROFILE_NAME
    assert selected_decl.schema == B1_TOPOLOGY_PLACEMENT_SCHEMA == 3
    assert selected_decl.carries_topology
    assert selected_decl.topology == "postgres-core"
    assert selected_decl.cardinality == {"gateway": 1, "postgres": 2, "driver": 1}
    assert selected_decl.probe_round is None and selected_decl.orientation is None
    assert selected_decl.reference_cpus == frozenset(range(4))

    # --- product-local schema-2 separation ---------------------------------
    product = B1PlacementDeclaration.from_contract(
        _declaration_payload(
            profile=PRODUCT_PROFILE_NAME,
            minimumHostLogicalCpus=8,
            roles={
                "gateway": {"allowedCpus": "0-3"},
                "postgres": {"allowedCpus": "4-6"},
                "driver": {"allowedCpus": "7"},
            },
        )
    )
    assert product.schema == PRODUCT_PLACEMENT_SCHEMA == 2
    assert not product.carries_topology
    assert product.cardinality == PRODUCT_AFFINITY_CARDINALITY
    assert product.topology is None and product.unassigned_cpus == frozenset()
    # Neither CI-scale profile answers for a fixed cardinality any more: both
    # read it from the parsed contract's topology.
    for ci_profile in (CI_SCALE_PROFILE, CI_SCALE_PROBE_PROFILE):
        with pytest.raises(B1PlacementError, match="topology-derived"):
            ci_profile.affinity_cardinality
    # The RETIRED schema-2 CI-scale document -- the fixed 2/1/1 over the first
    # four allowed CPUs GC-1 shipped -- is refused outright. There is no
    # compatibility reader and no migration.
    with pytest.raises(B1PlacementError):
        B1PlacementDeclaration.from_contract({
            "schema": PRODUCT_PLACEMENT_SCHEMA,
            "runId": "0123456789abcdef0123456789abcdef",
            "profile": CI_SCALE_PROFILE_NAME,
            "referenceLogicalCpus": 4,
            "mechanism": B1_PLACEMENT_MECHANISM,
            "roles": {
                "gateway": {"allowedCpus": "0-1"},
                "postgres": {"allowedCpus": "2"},
                "driver": {"allowedCpus": "3"},
            },
        })
    # ...and its workload is the CI-scale workload, copied, not restated.
    for field in ("rate", "seconds", "total_requests", "prologue_requests",
                  "max_in_flight", "p99_ms", "sustained_floor"):
        assert getattr(CI_SCALE_PROBE_PROFILE, field) == getattr(CI_SCALE_PROFILE, field)


_GC3_DROP = object()


def test_gc3_probe_verdicts_are_truthful_without_truth_gating():
    """FP-GC3-2: every operand boundary, and a truthful miss that stays green."""
    assert probe.VERDICT_FIELDS == (
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
    assert set(probe.INTEGRITY_VERDICT_FIELDS) | set(probe.PERFORMANCE_VERDICT_FIELDS) == set(
        probe.VERDICT_FIELDS
    )
    assert not set(probe.INTEGRITY_VERDICT_FIELDS) & set(probe.PERFORMANCE_VERDICT_FIELDS)

    met = probe.evaluate_verdicts(_gc3_operands())
    assert set(met.values()) == {probe.VERDICT_MET}
    assert tuple(met) == probe.VERDICT_FIELDS

    # Exact boundaries, one operand at a time.
    for overrides, field in (
        ({"offered": 14999, "served": 14999, "committed": 14999}, "offered_eq_15000"),
        ({"served": 14000, "errors": 0}, "served_plus_errors_eq_offered"),
        ({"served": 14000, "errors": 1000, "committed": 14000}, "errors_eq_zero"),
        ({"p99Ms": 150.0}, "p99_lt_150_ms"),
        ({"committed": 14999}, "committed_eq_served"),
        ({"servedRate": 449.9}, "served_rate_gte_450"),
        ({"maxInFlight": 500}, "max_in_flight_lt_500"),
        ({"platformOnline": False}, "platform_online"),
        ({"workerSetStable": False}, "worker_set_stable"),
    ):
        verdicts = probe.evaluate_verdicts(_gc3_operands(**overrides))
        assert verdicts[field] == probe.VERDICT_MISSED, (field, overrides)
    # ...and the just-passing side of each ordering comparison.
    assert probe.evaluate_verdicts(_gc3_operands(p99Ms=149.999))["p99_lt_150_ms"] == "met"
    assert probe.evaluate_verdicts(_gc3_operands(servedRate=450.0))["served_rate_gte_450"] == "met"
    assert probe.evaluate_verdicts(_gc3_operands(maxInFlight=499))["max_in_flight_lt_500"] == "met"

    with pytest.raises(probe.TopologyProbeError, match="incomplete"):
        probe.evaluate_verdicts({"offered": 15000})
    with pytest.raises(probe.TopologyProbeError, match="unknown verdict operands"):
        probe.evaluate_verdicts(_gc3_operands(**{}) | {"cpuMs": 1.0})

    assert probe.serialize_verdicts(met).startswith("offered_eq_15000=met,")
    assert probe.serialize_verdicts(met).count("=") == 10
    with pytest.raises(probe.TopologyProbeError, match="closed ordered set"):
        probe.serialize_verdicts({field: "met" for field in reversed(probe.VERDICT_FIELDS)})
    with pytest.raises(probe.TopologyProbeError, match="neither"):
        probe.serialize_verdicts({field: "yes" for field in probe.VERDICT_FIELDS})

    # A truthful performance MISS is admissible data: the record validates.
    slow = _gc3_operands(p99Ms=2387.1, maxInFlight=500, served=14000, errors=1000,
                         committed=14000, servedRate=440.0)
    record = _gc3_record(2, operands=slow)
    assert probe.validate_record(record)["verdicts"]["p99_lt_150_ms"] == "missed"
    assert record["verdicts"]["errors_eq_zero"] == "missed"
    # A truthful INTEGRITY miss is not: the measurement is undefined.
    for overrides in (
        {"offered": 14999, "served": 14999, "committed": 14999},
        {"committed": 14999},
        {"platformOnline": False},
        {"workerSetStable": False},
    ):
        with pytest.raises(probe.TopologyProbeError, match="integrity status"):
            probe.validate_record(_gc3_record(2, operands=_gc3_operands(**overrides)))
    # A literalised or deleted verdict disagrees with its own operands.
    literalised = _gc3_record(2, operands=slow)
    literalised["verdicts"] = dict(literalised["verdicts"])
    literalised["verdicts"]["p99_lt_150_ms"] = probe.VERDICT_MET
    with pytest.raises(probe.TopologyProbeError, match="disagrees with its own"):
        probe.validate_record(literalised)
    dropped = _gc3_record(2)
    dropped["verdicts"] = {k: v for k, v in dropped["verdicts"].items() if k != "errors_eq_zero"}
    with pytest.raises(probe.TopologyProbeError, match="closed set"):
        probe.validate_record(dropped)
    renamed = _gc3_record(2)
    renamed["verdicts"] = {
        ("p99_under_150_ms" if k == "p99_lt_150_ms" else k): v
        for k, v in renamed["verdicts"].items()
    }
    with pytest.raises(probe.TopologyProbeError, match="closed set"):
        probe.validate_record(renamed)
    # The ORDER lives on the serialized line, because a canonically key-sorted
    # JSON object cannot carry it. Reordering or literalising there is red.
    reordered = _gc3_record(2)
    reordered["verdictLine"] = probe.serialize_verdicts(
        {field: reordered["verdicts"][field] for field in probe.VERDICT_FIELDS}
    ).replace("offered_eq_15000=met,", "", 1)
    with pytest.raises(probe.TopologyProbeError, match="closed ordered serialization"):
        probe.validate_record(reordered)
    mislined = _gc3_record(2, operands=slow)
    mislined["verdictLine"] = mislined["verdictLine"].replace(
        "p99_lt_150_ms=missed", "p99_lt_150_ms=met", 1
    )
    with pytest.raises(probe.TopologyProbeError, match="closed ordered serialization"):
        probe.validate_record(mislined)
    illegal = _gc3_record(2)
    illegal["verdicts"] = dict(illegal["verdicts"])
    illegal["verdicts"]["errors_eq_zero"] = "unknown"
    with pytest.raises(probe.TopologyProbeError):
        probe.validate_record(illegal)


def test_gc3_probe_collector_rejects_partial_or_mixed_artifacts(tmp_path):
    """FP-GC3-2: no partial, duplicated or mixed artifact may read as evidence."""
    plan = _gc3_plan()
    records = [_gc3_record(index) for index in range(probe.ARMS_PER_ARTIFACT)]
    artifact = probe.collect_artifact(plan, records)
    assert artifact["status"] == probe.ARTIFACT_COMPLETE
    assert len(artifact["arms"]) == 28
    assert probe.validate_artifact(artifact) is artifact
    assert artifact["cpuModel"] == _GC3_MODEL
    assert artifact["siblingPairs"] == ["0-1", "2-3"]

    # FP-GC3-3/4: an artifact whose own model string cannot key a decision is
    # `invalid` with its own named code, never a complete record under the
    # `unknown` sentinel. There is no allowlist here -- only the closed
    # validity rules -- so any OTHER exact model is complete and admissible.
    for illegal_model in (probe.CPU_MODEL_UNKNOWN, "", "x" * 300, "bad\x01model"):
        broken = probe.collect_artifact(
            _gc3_plan(cpu_model=illegal_model),
            [_gc3_record(index, cpu_model=illegal_model)
             for index in range(probe.ARMS_PER_ARTIFACT)],
        )
        assert broken["status"] == probe.ARTIFACT_INVALID, illegal_model
        assert broken["failureCode"] == "cpu_model_unavailable", illegal_model
    other_model = probe.collect_artifact(
        _gc3_plan(cpu_model=_GC3_OTHER_MODEL),
        [_gc3_record(index, cpu_model=_GC3_OTHER_MODEL)
         for index in range(probe.ARMS_PER_ARTIFACT)],
    )
    assert other_model["status"] == probe.ARTIFACT_COMPLETE
    assert other_model["cpuModel"] == _GC3_OTHER_MODEL

    # Canonical, sorted, newline-terminated, and byte-reproducible on disk.
    path = tmp_path / "artifact.json"
    probe.write_artifact(path, artifact)
    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert json.loads(text) == artifact
    assert text == probe.canonical_json(artifact)

    # A missing arm is `invalid`, names the arm, and is never a short artifact
    # that reads like evidence.
    partial = probe.collect_artifact(plan, records[:-1])
    assert partial["status"] == probe.ARTIFACT_INVALID
    assert partial["failureCode"] == "missing_arm"
    assert partial["missingArms"] == [27]
    with pytest.raises(probe.TopologyProbeError, match="only a complete artifact"):
        probe.validate_artifact(partial)

    # A failing arm carries its own closed code and stops the sweep.
    failed = probe.collect_artifact(
        plan, records[:5], failure={"armIndex": 5, "exitCode": 1, "failureCode": "arm_failed"}
    )
    assert failed["status"] == probe.ARTIFACT_INVALID
    assert failed["failureCode"] == "arm_failed"
    assert failed["missingArms"][0] == 5
    assert any("exit status 1" in detail for detail in failed["failureDetail"])

    # Duplicate arm index, duplicate run id, identity drift, unknown record key.
    duplicated = records + [_gc3_record(0, salt=9)]
    assert probe.collect_artifact(plan, duplicated)["failureCode"] == "duplicate_arm"
    reused = [_gc3_record(index, salt=0) for index in range(2)]
    reused[1]["runId"] = reused[0]["runId"]
    assert probe.collect_artifact(plan, reused)["failureCode"] == "duplicate_run_id"
    drifted = [dict(record) for record in records]
    drifted[3] = {**drifted[3], "headSha": "b" * 40}
    assert probe.collect_artifact(plan, drifted)["failureCode"] == "identity_drift"
    host_drift = [dict(record) for record in records]
    host_drift[4] = {**host_drift[4], "cpuModel": "Intel(R) Core(TM) i7-11800H"}
    assert probe.collect_artifact(plan, host_drift)["failureCode"] == "identity_drift"
    unknown_key = [dict(record) for record in records]
    unknown_key[2] = {**unknown_key[2], "surprise": 1}
    assert probe.collect_artifact(plan, unknown_key)["failureCode"] == "record_invalid"
    assert probe.collect_artifact(plan, ["not-a-record"])["failureCode"] == "record_invalid"

    # Record-level integrity: the mapping, the sibling maps and the plan index.
    for mutate, pattern in (
        (lambda r: r.update(effectiveRoles={**r["declaredRoles"], "driver": "0"}), "effective"),
        (lambda r: r.update(unassignedCpus="3"), "unassignedCpus"),
        (lambda r: r.update(index=27), "the plan enumerates"),
        (lambda r: r.update(index=99), "outside"),
        (lambda r: r.update(spanSeconds=0), "span"),
        (lambda r: r.update(headSha="short"), "headSha"),
        (lambda r: r.update(githubRunId="x"), "decimal"),
        (lambda r: r.update(githubJob="benchmark"), "githubJob"),
        (lambda r: r.update(logicalCpuCount=8), "logicalCpuCount"),
        (lambda r: r.update(siblingMap={"gateway": "0:0-1"}), "siblingMap must cover"),
        (lambda r: r.update(referenceSiblingMap="0:0-1+1:0-1"), "referenceSiblingMap covers"),
        (lambda r: r.update(siblingPairs=["0,2", "1,3"]), "enumerator derives"),
    ):
        record = _gc3_record(2)
        mutate(record)
        with pytest.raises(probe.TopologyProbeError, match=pattern):
            probe.validate_record(record)
    # A role sibling map that contradicts the reference reading.
    record = _gc3_record(2)
    record["siblingMap"] = {**record["siblingMap"], "postgres": "2:2-3"}
    probe.validate_record(record)
    record["siblingMap"] = {**record["siblingMap"], "postgres": "2:0-3"}
    with pytest.raises(probe.TopologyProbeError):
        probe.validate_record(record)

    # Artifact-level: the schema, the topology-set version, the job and the
    # arm inventory are all closed.
    for changes, pattern in (
        ({"schema": 2}, "artifact schema"),
        ({"topologySetVersion": 2}, "topologySetVersion"),
        ({"githubJob": "benchmark"}, "githubJob"),
        ({"arms": artifact["arms"][:27]}, "carries 28 arms"),
        ({"arms": "nope"}, "carries 28 arms"),
    ):
        with pytest.raises(probe.TopologyProbeError, match=pattern):
            probe.validate_artifact({**artifact, **changes})
    with pytest.raises(probe.TopologyProbeError, match="not an object"):
        probe.validate_artifact([])
    with pytest.raises(probe.TopologyProbeError, match="keys drift"):
        probe.validate_artifact({**artifact, "extra": 1})
    repeated = {**artifact, "arms": artifact["arms"][:-1] + [artifact["arms"][0]]}
    with pytest.raises(probe.TopologyProbeError, match="repeats arm index"):
        probe.validate_artifact(repeated)
    disagreeing = json.loads(json.dumps(artifact))
    disagreeing["headSha"] = "c" * 40
    with pytest.raises(probe.TopologyProbeError, match="disagrees with the artifact"):
        probe.validate_artifact(disagreeing)

    # The collector CLI writes the artifact and returns nonzero when invalid.
    records_dir = tmp_path / "records"
    records_dir.mkdir()
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(probe.canonical_json(plan), encoding="utf-8")
    for index, record in enumerate(records):
        (records_dir / f"record-{index:02d}.json").write_text(
            probe.canonical_json(record), encoding="utf-8"
        )
    out = tmp_path / "complete.json"
    assert probe.main([
        "collect", "--plan", str(plan_path), "--records", str(records_dir), "--out", str(out)
    ]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["status"] == "complete"
    (records_dir / "record-27.json").unlink()
    broken = tmp_path / "invalid.json"
    assert probe.main([
        "collect", "--plan", str(plan_path), "--records", str(records_dir),
        "--out", str(broken), "--failed-arm", "27", "--exit-code", "2",
    ]) == 1
    assert json.loads(broken.read_text(encoding="utf-8"))["failureCode"] == "arm_failed"
    empty = tmp_path / "empty.json"
    assert probe.main([
        "collect", "--plan", str(plan_path), "--records", str(tmp_path / "absent"),
        "--out", str(empty),
    ]) == 1

    # The contract CLI writes one arm's contract and prints its driver CPU.
    contract_path = tmp_path / "placement.json"
    context_path = tmp_path / "probe-context.json"
    assert probe.main([
        "contract", "--plan", str(plan_path), "--arm", "2", "--run-id", _gc3_run_id(2),
        "--out", str(contract_path), "--context", str(context_path),
    ]) == 0
    written = json.loads(contract_path.read_text(encoding="utf-8"))
    assert written["topology"] == "gateway-core" and written["roles"]["driver"]["allowedCpus"] == "3"
    context = read_probe_context(context_path)
    assert context["index"] == 2 and context["cpuModel"] == _GC3_MODEL
    assert probe.main([
        "contract", "--plan", str(plan_path), "--arm", "99", "--run-id", _gc3_run_id(2),
        "--out", str(contract_path), "--context", str(context_path),
    ]) == 1
    # A hand-edited plan is not a second topology author.
    tampered = json.loads(plan_path.read_text(encoding="utf-8"))
    tampered["arms"][2]["roles"]["gateway"] = "0,2"
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(probe.canonical_json(tampered), encoding="utf-8")
    assert probe.main([
        "contract", "--plan", str(tampered_path), "--arm", "2", "--run-id", _gc3_run_id(2),
        "--out", str(contract_path), "--context", str(context_path),
    ]) == 1

    # The probe context is closed, and a drifted one is refused.
    bad_context = tmp_path / "bad-context.json"
    bad_context.write_text('{"index": 0}', encoding="utf-8")
    with pytest.raises(B1PlacementError, match="keys drift"):
        read_probe_context(bad_context)
    bad_context.write_text("[]", encoding="utf-8")
    with pytest.raises(B1PlacementError, match="not an object"):
        read_probe_context(bad_context)
    bad_context.write_text("{", encoding="utf-8")
    with pytest.raises(B1PlacementError, match="not JSON"):
        read_probe_context(bad_context)
    with pytest.raises(B1PlacementError, match="no probe context"):
        read_probe_context(tmp_path / "absent.json")


def test_gc3_selector_partitions_artifacts_by_cpu_model(tmp_path):
    """FP-GC3-3: each exact model earns its own decision, from its own evidence.

    Eight integrity-green records across two distinct-run, same-head artifacts
    OF ONE EXACT MODEL, or that model gets nothing. Evidence never crosses a
    model key: model X cannot satisfy, outrank, unblock or block model Y, and
    an unpaired model neither delays nor contaminates a paired one.
    """
    first = _gc3_artifact("11")
    second = _gc3_artifact("22")
    assert probe.admit_evidence(first, second) == _GC3_MODEL

    # Every class is green in this fixture, so every class is ratifiable and
    # the fixed ranking decides -- here by lexical id, the last tie-break.
    entry = probe.select_topology(first, second)
    assert entry["status"] == probe.DECISION_SELECTED
    assert list(entry["ratifiable"]) == list(probe.TOPOLOGY_IDS)
    assert entry["selected"] == probe.TOPOLOGY_IDS[0]
    assert entry["evidenceHeadSha"] == _GC3_SHA
    assert entry["cardinality"] == probe.topology_cardinality(entry["selected"])
    assert entry["placementSchema"] == probe.CONTRACT_SCHEMA == 3

    # One missed performance status in ONE arm of ONE artifact removes the whole
    # class: eight green records, not seven.
    def one_slow(index):
        arm = probe.enumerate_arms(*_GC3_PAIRS)[index]
        if arm["topology"] == "gateway-core" and arm["round"] == 1:
            return _gc3_operands(p99Ms=2387.1)
        return None

    handicapped = _gc3_artifact("33", per_arm=one_slow)
    assert "gateway-core" not in probe.eligible_topologies(handicapped)
    assert "gateway-core" in probe.eligible_topologies(first)
    assert "gateway-core" not in probe.select_topology(first, handicapped)["ratifiable"]

    # The ranking, in order: lowest max p99, then lowest max in-flight, then
    # highest min served rate, then lexical id.
    def ranked(p99_by_class, in_flight_by_class=None, rate_by_class=None,
               cpu_model=_GC3_MODEL, runs=("44", "55")):
        def per_arm(index):
            arm = probe.enumerate_arms(*_GC3_PAIRS)[index]
            return _gc3_operands(
                p99Ms=p99_by_class.get(arm["topology"], 10.0),
                maxInFlight=(in_flight_by_class or {}).get(arm["topology"], 40),
                servedRate=(rate_by_class or {}).get(arm["topology"], 500.0),
            )
        left = _gc3_artifact(runs[0], per_arm=per_arm, cpu_model=cpu_model)
        right = _gc3_artifact(runs[1], per_arm=per_arm, cpu_model=cpu_model)
        return probe.select_topology(left, right)

    assert ranked({"postgres-core": 5.0})["selected"] == "postgres-core"
    assert ranked({}, {"postgres-split": 10})["selected"] == "postgres-split"
    assert ranked({}, {}, {"gateway-split": 600.0})["selected"] == "gateway-split"
    # A CPU diagnostic cannot move the ranking: the same arms with a wildly
    # different PostgreSQL cost still select on the bar operands.
    same = ranked({"postgres-core": 5.0})
    assert same["selected"] == "postgres-core"

    # Unhostable: no class is green in both artifacts. Every derived field is
    # null and nothing is ratified -- for THIS model only.
    def all_slow(index):
        return _gc3_operands(p99Ms=2387.1, maxInFlight=500)

    lost = _gc3_artifact("66", per_arm=all_slow)
    unhostable = probe.select_topology(lost, _gc3_artifact("77", per_arm=all_slow))
    assert unhostable["status"] == probe.DECISION_UNHOSTABLE
    assert unhostable["ratifiable"] == []
    for null_field in ("selected", "cardinality", "placementSchema", "score"):
        assert unhostable[null_field] is None, null_field

    # Admission: two distinct runs, one head, ONE MODEL SHARED BY BOTH, one
    # physical topology, and the pinned discovery job.
    with pytest.raises(probe.TopologyProbeError, match="two independent runs"):
        probe.admit_evidence(first, _gc3_artifact("11"))
    other_head = json.loads(json.dumps(second))
    other_head["headSha"] = "b" * 40
    for arm in other_head["arms"]:
        arm["headSha"] = "b" * 40
    with pytest.raises(probe.TopologyProbeError, match="different heads"):
        probe.admit_evidence(first, other_head)
    other_model = _gc3_artifact("88", cpu_model=_GC3_OTHER_MODEL)
    with pytest.raises(probe.TopologyProbeError, match="different CPU models"):
        probe.admit_evidence(first, other_model)
    # ...and the model itself must be decision eligible. There is no allowlist:
    # any exact, canonical, nonsentinel string is a key.
    assert probe.validate_cpu_model(_GC3_OTHER_MODEL) == _GC3_OTHER_MODEL
    assert probe.is_decision_eligible_cpu_model("Totally Made Up CPU 9000")
    for bad in (probe.CPU_MODEL_UNKNOWN, "", "x" * 300, "two  spaces", " padded",
                "carriage\rreturn", 7, None):
        assert not probe.is_decision_eligible_cpu_model(bad), bad
        with pytest.raises(probe.TopologyProbeError):
            probe.validate_cpu_model(bad)
    wrong_count = {**second, "logicalCpuCount": 8}
    with pytest.raises(probe.TopologyProbeError):
        probe.admit_evidence(first, wrong_count)
    with pytest.raises(probe.TopologyProbeError, match="githubJob"):
        probe.admit_evidence(first, {**second, "githubJob": "benchmark"})
    for pairs, pattern in (
        (["0-1"], "not two pairs"),
        (["0-2", "0-1"], "overlap"),
        (["0-1", "4-5"], "referenceCpus"),
        (["0-2", "1,3"], "not two CPUs"),
    ):
        with pytest.raises(probe.TopologyProbeError):
            probe.admit_evidence(first, {**second, "siblingPairs": pairs})

    # --- the model-keyed carrier (FP-GC3-3) --------------------------------
    carrier_path = _gc3_carrier(tmp_path, (first, second))
    carrier = json.loads(carrier_path.read_text(encoding="utf-8"))
    assert carrier_path.read_text(encoding="utf-8") == probe.canonical_json(carrier)
    assert carrier["schema"] == probe.DECISION_SCHEMA == 3
    assert carrier["topologySetVersion"] == probe.TOPOLOGY_SET_VERSION
    assert list(carrier["models"]) == [_GC3_MODEL]
    stored = carrier["models"][_GC3_MODEL]
    assert stored["status"] == probe.DECISION_SELECTED
    assert stored["selected"] == entry["selected"]
    assert len(stored["artifacts"]) == 2
    for wrapper in stored["artifacts"]:
        assert set(wrapper) == {"sourceUrl", "sha256", "artifact"}
        assert wrapper["sourceUrl"].startswith("https://github.com/")
        assert str(wrapper["artifact"]["githubRunId"]) in wrapper["sourceUrl"]
        assert wrapper["sha256"] == hashlib.sha256(
            probe.canonical_json(wrapper["artifact"]).encode("utf-8")
        ).hexdigest()
    # The pair is embedded in run-id order, whichever order the CLI was given.
    assert [w["artifact"]["githubRunId"] for w in stored["artifacts"]] == ["11", "22"]
    # A first decision is additive and starts with an empty history.
    assert stored["superseded"] == []
    assert set(stored) == set(probe.DECISION_ENTRY_KEYS)
    probe.validate_decision(carrier)
    assert probe.recompute_decision(carrier)[_GC3_MODEL] == stored

    probe.write_artifact(tmp_path / "first.json", first)
    probe.write_artifact(tmp_path / "second.json", second)

    # A second model merges through --base without touching the first entry.
    third = _gc3_artifact("99", per_arm=all_slow, cpu_model=_GC3_OTHER_MODEL)
    fourth = _gc3_artifact("12", per_arm=all_slow, cpu_model=_GC3_OTHER_MODEL)
    merged_path = _gc3_carrier(
        tmp_path / "merged", (first, second), (third, fourth)
    )
    merged = json.loads(merged_path.read_text(encoding="utf-8"))
    assert sorted(merged["models"]) == sorted([_GC3_MODEL, _GC3_OTHER_MODEL])
    assert merged["models"][_GC3_MODEL] == stored, "model X's entry was rewritten"
    assert merged["models"][_GC3_OTHER_MODEL]["status"] == probe.DECISION_UNHOSTABLE
    probe.validate_decision(merged)
    # One model's unhostable result neither weakens nor erases the other's.
    assert merged["models"][_GC3_MODEL]["status"] == probe.DECISION_SELECTED

    # A rejected model-X invocation leaves a valid model-Y carrier untouched.
    unpaired = tmp_path / "unpaired.json"
    probe.write_artifact(unpaired, other_model)
    before = merged_path.read_text(encoding="utf-8")
    rejected = tmp_path / "rejected.json"
    assert probe.main([
        "decide", "--out", str(rejected), "--base", str(merged_path),
        "--pair", str(unpaired), str(unpaired),
    ]) == 1
    assert merged_path.read_text(encoding="utf-8") == before
    assert not rejected.exists()
    # ...and an aliased base/output is refused before anything is read.
    assert probe.main([
        "decide", "--out", str(merged_path), "--base", str(merged_path),
        "--pair", str(tmp_path / "first.json"), str(tmp_path / "second.json"),
    ]) == 1
    assert merged_path.read_text(encoding="utf-8") == before

    # A second, DIFFERENT decision for an already decided model is refused.
    faster = tmp_path / "faster"
    faster.mkdir()
    left = _gc3_artifact("13", per_arm=lambda i: _gc3_operands(p99Ms=1.0))
    right = _gc3_artifact("14", per_arm=lambda i: _gc3_operands(p99Ms=1.0))
    probe.write_artifact(faster / "a.json", left)
    probe.write_artifact(faster / "b.json", right)
    assert probe.main([
        "decide", "--out", str(faster / "out.json"), "--base", str(merged_path),
        "--pair", str(faster / "a.json"), str(faster / "b.json"),
    ]) == 1
    assert not (faster / "out.json").exists()

    # ...while re-deriving the SAME decision is idempotent.
    again = tmp_path / "again.json"
    assert probe.main([
        "decide", "--out", str(again), "--base", str(merged_path),
        "--pair", str(tmp_path / "first.json"), str(tmp_path / "second.json"),
    ]) == 0
    assert json.loads(again.read_text(encoding="utf-8")) == merged

    # Tampering: a forged result, a forged digest, a forged model key and a
    # cross-model embedded artifact are all refused by recomputation.
    tampered = json.loads(json.dumps(carrier))
    tampered["models"][_GC3_MODEL]["artifacts"][0]["artifact"]["arms"][0]["operands"][
        "p99Ms"
    ] = 1.0
    with pytest.raises(probe.TopologyProbeError, match="does not match its digest"):
        probe.validate_decision(tampered)
    forged = json.loads(json.dumps(carrier))
    forged["models"][_GC3_MODEL]["selected"] = "postgres-core"
    with pytest.raises(probe.TopologyProbeError, match="not what the selector derives"):
        probe.validate_decision(forged)
    handmade = json.loads(json.dumps(carrier))
    handmade["models"][_GC3_MODEL]["cardinality"] = {"gateway": 3, "postgres": 1, "driver": 1}
    with pytest.raises(probe.TopologyProbeError):
        probe.validate_decision(handmade)
    rekeyed = json.loads(json.dumps(carrier))
    rekeyed["models"] = {_GC3_OTHER_MODEL: rekeyed["models"][_GC3_MODEL]}
    with pytest.raises(probe.TopologyProbeError, match="a model key is the artifacts' own model"):
        probe.validate_decision(rekeyed)
    halved = json.loads(json.dumps(carrier))
    halved["models"][_GC3_MODEL]["artifacts"] = halved["models"][_GC3_MODEL]["artifacts"][:1]
    with pytest.raises(probe.TopologyProbeError, match="exactly two"):
        probe.validate_decision(halved)
    duplicated = json.loads(json.dumps(carrier))
    duplicated["models"][_GC3_MODEL]["artifacts"][1] = json.loads(
        json.dumps(duplicated["models"][_GC3_MODEL]["artifacts"][0])
    )
    with pytest.raises(probe.TopologyProbeError, match="duplicate evidence"):
        probe.validate_decision(duplicated)
    unhttps = json.loads(json.dumps(carrier))
    unhttps["models"][_GC3_MODEL]["artifacts"][0]["sourceUrl"] = "http://example.invalid/runs/11"
    with pytest.raises(probe.TopologyProbeError, match="https GitHub run URL"):
        probe.validate_decision(unhttps)
    for broken, pattern in (
        ({**carrier, "schema": 1}, "unsupported decision schema"),
        ({**carrier, "topologySetVersion": 2}, "topologySetVersion"),
        ({**carrier, "models": {}}, "nonempty models map"),
        ({"schema": 2, "models": carrier["models"]}, "closed decision keys"),
    ):
        with pytest.raises(probe.TopologyProbeError, match=pattern):
            probe.validate_decision(broken)
    shaped = json.loads(json.dumps(carrier))
    shaped["models"][_GC3_MODEL].pop("score")
    with pytest.raises(probe.TopologyProbeError):
        probe.validate_decision(shaped)
    # The retired flat schema-1 shape is not a carrier at all.
    with pytest.raises(probe.TopologyProbeError):
        probe.validate_decision({
            "schema": 1, "topologySetVersion": 1, "status": "selected",
            "headSha": _GC3_SHA, "ratifiable": [], "selected": "gateway-core",
            "evidence": [], "artifacts": [],
        })

    # Scoring refuses a class it has fewer than eight records for.
    with pytest.raises(probe.TopologyProbeError, match="need 8"):
        probe.score_topology((first,), "gateway-core")
    # The CLI reports an invalid pair rather than writing a decision.
    missing_out = tmp_path / "never-written.json"
    assert probe.main([
        "decide", "--out", str(missing_out), "--base", str(merged_path),
        "--pair", str(tmp_path / "first.json"), str(tmp_path / "first.json"),
    ]) == 1
    assert not missing_out.exists()
    # ...and `--base` is required: there is no no-base initialisation path, so
    # a missing carrier is restored from version control, never rebuilt here.
    with pytest.raises(SystemExit) as raised:
        probe.main([
            "decide", "--out", str(missing_out),
            "--pair", str(tmp_path / "first.json"), str(tmp_path / "second.json"),
        ])
    assert raised.value.code == 2
    assert not missing_out.exists()


def _gc3_git_repo(tmp_path: Path) -> "tuple[Path, dict[str, str]]":
    """A real, tiny repository: the linear chain a -> b -> c, plus divergent d.

    The strict-descendant proof is local Git history, never a field an artifact
    supplies, so the only honest fixture for it is a real object database.
    """
    root = Path(tmp_path) / "repo"
    root.mkdir(parents=True, exist_ok=True)

    def git(*arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, check=True,
        )
        return result.stdout.strip()

    git("init", "-q", "-b", "main")
    git("config", "user.email", "gc3@example.invalid")
    git("config", "user.name", "GC-3 fixture")
    git("config", "commit.gpgsign", "false")
    heads: dict[str, str] = {}
    for name in ("c1", "c2", "c3", "c4"):
        (root / f"{name}.txt").write_text(name, encoding="utf-8")
        git("add", "-A")
        git("commit", "-q", "-m", name)
        heads[name] = git("rev-parse", "HEAD")
    # A head that descends from c1 but NOT from c2: divergent, never older.
    git("checkout", "-q", "-b", "divergent", heads["c1"])
    (root / "side.txt").write_text("side", encoding="utf-8")
    git("add", "-A")
    git("commit", "-q", "-m", "side")
    heads["side"] = git("rev-parse", "HEAD")
    git("checkout", "-q", "main")
    return root, heads


def test_gc3_selector_supersedes_only_descendant_head_and_preserves_history(
    tmp_path, monkeypatch
):
    """FP-GC3-7: a decided model changes only at a strictly newer product head.

    Everything here is synthetic and offline: a real temporary repository
    supplies the ancestry and the artifacts are fabricated records AT those
    exact heads. Nothing in this test claims, or could claim, a measured
    outcome for a real CPU model -- it proves the mechanism by which a later
    complete pair may replace an entry, and the many ways it may not.
    """
    repo, heads = _gc3_git_repo(tmp_path)
    monkeypatch.setattr(probe, "REPO_ROOT", repo)

    def slow(index):
        return _gc3_operands(p99Ms=2387.1, maxInFlight=500)

    def make_pair(run_ids, *, head, cpu_model=_GC3_MODEL, per_arm=None):
        return tuple(
            _gc3_artifact(run_id, head=head, cpu_model=cpu_model, per_arm=per_arm)
            for run_id in run_ids
        )

    def paths(artifacts, folder):
        written = []
        for artifact in artifacts:
            path = tmp_path / folder / f"artifact-{artifact['githubRunId']}.json"
            probe.write_artifact(path, artifact)
            written.append(str(path))
        return written

    at_c2 = make_pair(("11", "12"), head=heads["c2"])
    at_c3 = make_pair(("21", "22"), head=heads["c3"], per_arm=slow)
    at_c4 = make_pair(("31", "32"), head=heads["c4"])
    at_c1 = make_pair(("41", "42"), head=heads["c1"], per_arm=slow)
    at_side = make_pair(("71", "72"), head=heads["side"], per_arm=slow)
    other_at_c2 = make_pair(("51", "52"), head=heads["c2"], cpu_model=_GC3_OTHER_MODEL)
    c3_paths = paths(at_c3, "pair-c3")
    c4_paths = paths(at_c4, "pair-c4")
    c1_paths = paths(at_c1, "pair-c1")
    side_paths = paths(at_side, "pair-side")

    # The base carrier: two models decided at head c2, both with no history.
    base = _gc3_seed_carrier(tmp_path / "base" / "carrier.json", at_c2, other_at_c2)
    original = base.read_text(encoding="utf-8")
    carrier = json.loads(original)
    assert carrier["schema"] == probe.DECISION_SCHEMA == 3
    assert carrier["models"][_GC3_MODEL]["status"] == probe.DECISION_SELECTED
    assert carrier["models"][_GC3_MODEL]["evidenceHeadSha"] == heads["c2"]
    for entry in carrier["models"].values():
        assert entry["superseded"] == []
        assert set(entry) == set(probe.DECISION_ENTRY_KEYS)
    # An empty history has no edge to prove, so no Git call is needed for it.
    assert probe.verify_carrier_ancestry(carrier) == 0

    def decide(pair_paths, *, base_path=None, out, supersede=None):
        destination = tmp_path / "out" / out
        destination.parent.mkdir(parents=True, exist_ok=True)
        argv = [
            "decide", "--out", str(destination),
            "--base", str(base if base_path is None else base_path),
            "--pair", *pair_paths,
        ]
        if supersede is not None:
            argv += ["--supersede", supersede]
        return probe.main(argv), destination

    # (1) A nonidentical decision for a decided model is refused without the
    # explicit flag, and nothing is written.
    status, destination = decide(c3_paths, out="no-flag.json")
    assert status == 1 and not destination.exists()
    assert base.read_text(encoding="utf-8") == original

    # (2) --supersede must name that model's CURRENT head: not the pair's own
    # head, not a head nothing recorded, and not a head that is no object.
    for index, named in enumerate((heads["c3"], heads["c4"], "f" * 40)):
        status, destination = decide(
            c3_paths, supersede=named, out=f"stale-{index}.json"
        )
        assert status == 1, named
        assert not destination.exists(), named

    # (3) An absent model has nothing to supersede.
    absent_base = _gc3_seed_carrier(
        tmp_path / "absent" / "carrier.json", other_at_c2
    )
    status, destination = decide(
        c3_paths, base_path=absent_base, supersede=heads["c2"], out="absent.json"
    )
    assert status == 1 and not destination.exists()

    # (4) A divergent head is not a descendant; nor is an older one; nor is an
    # equal one. All three are refused with nothing written.
    status, destination = decide(
        side_paths, supersede=heads["c2"], out="divergent.json"
    )
    assert status == 1 and not destination.exists()
    status, destination = decide(c1_paths, supersede=heads["c2"], out="older.json")
    assert status == 1 and not destination.exists()
    same_head = paths(
        make_pair(("61", "62"), head=heads["c2"], per_arm=slow), "pair-same-head"
    )
    status, destination = decide(same_head, supersede=heads["c2"], out="equal.json")
    assert status == 1 and not destination.exists()

    # (5) A strict descendant, explicitly named, supersedes: the replaced
    # decision is appended IN FULL, the derived one becomes current, and the
    # other model's entry is preserved byte for byte.
    status, first_step = decide(c3_paths, supersede=heads["c2"], out="superseded.json")
    assert status == 0
    superseded = json.loads(first_step.read_text(encoding="utf-8"))
    probe.validate_decision(superseded)
    entry = superseded["models"][_GC3_MODEL]
    assert entry["status"] == probe.DECISION_UNHOSTABLE
    assert entry["evidenceHeadSha"] == heads["c3"]
    assert len(entry["superseded"]) == 1
    record = entry["superseded"][0]
    assert sorted(record) == sorted(probe.DECISION_HISTORY_KEYS)
    assert record["supersededByHeadSha"] == heads["c3"]
    assert record["decision"] == {
        key: value for key, value in carrier["models"][_GC3_MODEL].items()
        if key != "superseded"
    }
    assert "superseded" not in record["decision"]
    assert superseded["models"][_GC3_OTHER_MODEL] == carrier["models"][_GC3_OTHER_MODEL]
    # Both decisions recompute from their own embedded pairs, and the one edge
    # is a real strict descent.
    assert probe.recompute_decision(superseded)[_GC3_MODEL] == entry
    assert probe.verify_carrier_ancestry(superseded) == 1

    # (6) The exact retry, in the precise two-scratch form, changes no byte;
    # a retry naming the wrong preceding head is not a retry; and re-deriving
    # the current decision with no flag is the additive no-op.
    status, retried = decide(
        c3_paths, base_path=first_step, supersede=heads["c2"], out="retry.json"
    )
    assert status == 0
    assert retried.read_text(encoding="utf-8") == first_step.read_text(encoding="utf-8")
    status, destination = decide(
        c3_paths, base_path=first_step, supersede=heads["c4"], out="bad-retry.json"
    )
    assert status == 1 and not destination.exists()
    status, plain = decide(c3_paths, base_path=first_step, out="noop.json")
    assert status == 0
    assert plain.read_text(encoding="utf-8") == first_step.read_text(encoding="utf-8")
    # An aliased base/output is refused before any validation result is written.
    aliased = tmp_path / "out" / "aliased.json"
    aliased.write_text(first_step.read_text(encoding="utf-8"), encoding="utf-8")
    before = aliased.read_text(encoding="utf-8")
    assert probe.main([
        "decide", "--out", str(aliased), "--base", str(aliased), "--pair", *c4_paths,
        "--supersede", heads["c3"],
    ]) == 1
    assert aliased.read_text(encoding="utf-8") == before

    # (7) A second supersession appends AFTER the first: c2 -> c3 -> c4.
    status, second_step = decide(
        c4_paths, base_path=first_step, supersede=heads["c3"], out="chain.json"
    )
    assert status == 0
    chain = json.loads(second_step.read_text(encoding="utf-8"))
    probe.validate_decision(chain)
    entry = chain["models"][_GC3_MODEL]
    assert entry["status"] == probe.DECISION_SELECTED
    assert entry["evidenceHeadSha"] == heads["c4"]
    assert [r["decision"]["evidenceHeadSha"] for r in entry["superseded"]] == [
        heads["c2"], heads["c3"]
    ]
    assert [r["supersededByHeadSha"] for r in entry["superseded"]] == [
        heads["c3"], heads["c4"]
    ]
    assert [r["decision"]["status"] for r in entry["superseded"]] == [
        probe.DECISION_SELECTED, probe.DECISION_UNHOSTABLE
    ]
    assert probe.verify_carrier_ancestry(chain) == 2
    assert chain["models"][_GC3_OTHER_MODEL] == carrier["models"][_GC3_OTHER_MODEL]

    # (8) Routing consults ONLY the current entry, and needs no repository at
    # all: a selected decision that was superseded by an unhostable one records,
    # and an unhostable decision superseded by a selected one gates.
    monkeypatch.setattr(probe, "host_cpu_model", lambda: _GC3_MODEL)
    recorded = probe.route_host(first_step)
    probe.validate_route(recorded)
    assert recorded["decisionState"] == "unhostable"
    assert recorded["disposition"] == "recorded"
    assert recorded["topology"] is None
    gating = probe.route_host(second_step)
    probe.validate_route(gating)
    assert gating["disposition"] == "gating"
    assert gating["topology"] == entry["selected"]
    monkeypatch.setattr(probe, "REPO_ROOT", tmp_path / "not-a-repository")
    assert probe.route_host(second_step)["disposition"] == "gating"
    with pytest.raises(probe.TopologyProbeError, match="gc3_ancestry_unavailable"):
        probe.verify_decision_ancestry(heads["c2"], heads["c3"])
    monkeypatch.setattr(probe, "REPO_ROOT", repo)

    # (9) The history is closed and append-only. Every structural forgery below
    # is refused with no Git call: a mutated or nested record, a reordered
    # chain, a dropped newest or middle record, and an orphan edge. Dropping
    # the OLDEST record is not structurally visible in the file, which is
    # exactly why `--base` is required and the carrier is version controlled.
    def forged(mutate):
        copy = json.loads(json.dumps(chain))
        mutate(copy["models"][_GC3_MODEL])
        return copy

    def _reorder(model_entry):
        model_entry["superseded"].reverse()

    def _drop_newest(model_entry):
        del model_entry["superseded"][-1]

    def _drop_middle(model_entry):
        # c2 -> c3 -> c4 with the c3 record removed: the c2 record's edge now
        # points at a head no record and no current decision carries.
        del model_entry["superseded"][1]

    def _mutate(model_entry):
        model_entry["superseded"][0]["decision"]["status"] = probe.DECISION_UNHOSTABLE

    def _nest(model_entry):
        model_entry["superseded"][0]["decision"]["superseded"] = []

    def _orphan(model_entry):
        model_entry["superseded"][-1]["supersededByHeadSha"] = heads["side"]

    def _widen(model_entry):
        model_entry["superseded"][0]["note"] = "hand written"

    def _self_edge(model_entry):
        model_entry["superseded"].append({
            "supersededByHeadSha": model_entry["evidenceHeadSha"],
            "decision": {
                key: value for key, value in model_entry.items() if key != "superseded"
            },
        })

    for mutate in (_reorder, _drop_newest, _drop_middle, _mutate, _nest, _orphan,
                   _widen, _self_edge):
        with pytest.raises(probe.TopologyProbeError):
            probe.validate_decision(forged(mutate))
    # A history record that is not a list, or not an object, is not a history.
    for broken in ({}, "none", [[]]):
        with pytest.raises(probe.TopologyProbeError):
            probe.validate_decision(forged(
                lambda model_entry, value=broken: model_entry.__setitem__(
                    "superseded", value
                )
            ))

    # (10) The ancestry helper itself: accept only a proven strict descent, and
    # fail closed on anything Git cannot answer. No fetch, no network, no
    # recorded parent-head string.
    probe.verify_decision_ancestry(heads["c2"], heads["c4"])
    probe.verify_decision_ancestry(heads["c1"], heads["side"])
    for older, newer, reason in (
        (heads["c4"], heads["c2"], "not a strict descendant"),
        (heads["c2"], heads["side"], "not a strict descendant"),
        (heads["side"], heads["c4"], "not a strict descendant"),
        (heads["c2"], heads["c2"], "equals the named head"),
        ("f" * 40, heads["c4"], "gc3_ancestry_unavailable"),
        (heads["c2"], "0" * 40, "gc3_ancestry_unavailable"),
        ("not a sha", heads["c4"], "40 lowercase hex"),
        (heads["c2"], heads["c2"].upper(), "40 lowercase hex"),
    ):
        with pytest.raises(probe.TopologyProbeError, match=reason):
            probe.verify_decision_ancestry(older, newer)


def test_gc3_cpu_model_route_is_ratified_or_recorded(tmp_path, monkeypatch):
    """FP-GC3-4: the exact host model routes to its gate, or to a named record.

    Every branch below is decided by the carrier and the shared host reader
    alone. `route` takes no profile, model, topology, status or reason
    argument, and the launcher gets exactly two closed branch values out of
    `route-fields`: it never parses the carrier, chooses a model or
    reconstructs a topology in shell.
    """
    selected_pair = (_gc3_artifact("11"), _gc3_artifact("22"))

    def all_slow(index):
        return _gc3_operands(p99Ms=2387.1, maxInFlight=500)

    unhostable_pair = (
        _gc3_artifact("31", per_arm=all_slow, cpu_model=_GC3_OTHER_MODEL),
        _gc3_artifact("32", per_arm=all_slow, cpu_model=_GC3_OTHER_MODEL),
    )
    carrier = _gc3_carrier(tmp_path, selected_pair, unhostable_pair)
    decision = json.loads(carrier.read_text(encoding="utf-8"))
    chosen = decision["models"][_GC3_MODEL]["selected"]

    def route(model, *, path=carrier):
        monkeypatch.setattr(probe, "host_cpu_model", lambda: model)
        return probe.route_host(path)

    def run_cli(model, *, path=carrier, out=None, summary=None):
        monkeypatch.setattr(probe, "host_cpu_model", lambda: model)
        destination = out or (tmp_path / "route.json")
        if summary is not None:
            monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
        else:
            monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
        status = probe.main([
            "route", "--decision", str(path), "--out", str(destination)
        ])
        return status, destination

    # (1) selected -> gating, with this model's own topology/cardinality/schema.
    record = route(_GC3_MODEL)
    probe.validate_route(record)
    assert record == {
        "schema": 1,
        "profile": "ci-scale",
        "cpuModel": _GC3_MODEL,
        "decisionState": "selected",
        "disposition": "gating",
        "reason": None,
        "topology": chosen,
        "cardinality": probe.topology_cardinality(chosen),
        "placementSchema": 3,
    }
    assert record["topology"] == decision["models"][_GC3_MODEL]["selected"]
    assert record["cardinality"] == decision["models"][_GC3_MODEL]["cardinality"]
    assert record["placementSchema"] == decision["models"][_GC3_MODEL]["placementSchema"]
    assert probe.route_fields(record) == f"gating\t{chosen}"

    # (2) unhostable -> recorded, named for THAT model, no topology at all.
    record = route(_GC3_OTHER_MODEL)
    probe.validate_route(record)
    assert record["decisionState"] == "unhostable"
    assert record["disposition"] == "recorded"
    assert record["reason"] == f"topology_unratified_sku:{_GC3_OTHER_MODEL}"
    assert record["topology"] is None and record["cardinality"] is None
    assert record["placementSchema"] is None
    assert probe.route_fields(record) == "recorded\tnone"

    # (3) a valid model with no entry -> the same recorded reason. Another
    # model's entry is never a fallback, and neither is a prefix or a family.
    family_prefix = _GC3_MODEL.split(" 4-Core", 1)[0]
    assert family_prefix != _GC3_MODEL and _GC3_MODEL.startswith(family_prefix)
    assert _GC3_MODEL.upper() != _GC3_MODEL
    for absent in ("Totally Made Up CPU 9000", _GC3_MODEL[:-1], _GC3_MODEL.upper(),
                   family_prefix):
        record = route(absent)
        probe.validate_route(record)
        assert record["decisionState"] == "absent", absent
        assert record["disposition"] == "recorded"
        assert record["reason"] == f"topology_unratified_sku:{absent}"
        assert record["topology"] is None
        assert probe.route_fields(record) == "recorded\tnone"

    # (4) an unreadable or illegal model -> its own distinct recorded reason,
    # with a null key: the `unknown` sentinel never becomes a lookup key.
    for unreadable in (probe.CPU_MODEL_UNKNOWN, "", "x" * 300, "bad\x01model"):
        record = route(unreadable)
        probe.validate_route(record)
        assert record["cpuModel"] is None, unreadable
        assert record["decisionState"] == "unavailable"
        assert record["disposition"] == "recorded"
        assert record["reason"] == "topology_cpu_model_unavailable"
        assert probe.route_fields(record) == "recorded\tnone"

    # (5) a missing or corrupt carrier is a FAILURE, never an unratified SKU --
    # and an unreadable model cannot hide it.
    absent_carrier = tmp_path / "no-such-carrier.json"
    for model in (_GC3_MODEL, probe.CPU_MODEL_UNKNOWN):
        record = route(model, path=absent_carrier)
        probe.validate_route(record)
        assert record["decisionState"] == "invalid"
        assert record["disposition"] == "failure"
        assert record["reason"] == probe.DECISION_MISSING_REASON == "gc3_decision_missing"
        with pytest.raises(probe.TopologyProbeError, match="no launcher branch"):
            probe.route_fields(record)
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{ not json", encoding="utf-8")
    forged = tmp_path / "forged.json"
    tampered = json.loads(json.dumps(decision))
    tampered["models"][_GC3_MODEL]["selected"] = "postgres-core"
    forged.write_text(probe.canonical_json(tampered), encoding="utf-8")
    for path in (corrupt, forged):
        record = route(_GC3_MODEL, path=path)
        probe.validate_route(record)
        assert record["decisionState"] == "invalid"
        assert record["disposition"] == "failure"
        assert record["reason"] == probe.DECISION_INVALID_REASON == "gc3_decision_invalid"

    # (6) the CLI: canonical record on disk, exactly one stdout line that
    # decodes back to those same bytes, a step-summary row, and the exit map.
    summary = tmp_path / "summary.md"
    status, written = run_cli(_GC3_MODEL, out=tmp_path / "gating.json", summary=summary)
    assert status == 0
    raw = written.read_text(encoding="utf-8")
    assert raw == probe.canonical_json(json.loads(raw))
    assert json.loads(raw)["disposition"] == "gating"
    assert f"cpuModel={_GC3_MODEL}" in summary.read_text(encoding="utf-8")
    status, recorded_path = run_cli(_GC3_OTHER_MODEL, out=tmp_path / "recorded.json")
    assert status == 0
    assert json.loads(recorded_path.read_text(encoding="utf-8"))["disposition"] == "recorded"
    status, failed_path = run_cli(_GC3_MODEL, path=absent_carrier, out=tmp_path / "failed.json")
    assert status == 1
    assert json.loads(failed_path.read_text(encoding="utf-8"))["disposition"] == "failure"

    # (7) route-fields: the two closed combinations, and nothing else.
    assert probe.main(["route-fields", "--route", str(written)]) == 0
    assert probe.main(["route-fields", "--route", str(recorded_path)]) == 0
    assert probe.main(["route-fields", "--route", str(failed_path)]) == 1
    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text(json.dumps(json.loads(raw)), encoding="utf-8")
    assert probe.main(["route-fields", "--route", str(noncanonical)]) == 1
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{ not json", encoding="utf-8")
    assert probe.main(["route-fields", "--route", str(malformed)]) == 1
    assert probe.main(["route-fields", "--route", str(tmp_path / "absent.json")]) == 1

    # A hand-edited route record cannot manufacture a gate.
    for mutation, pattern in (
        ({"disposition": "gating"}, "routes to"),
        ({"decisionState": "selected"}, "routes to"),
        ({"schema": 2}, "unsupported route schema"),
        ({"profile": "ci-scale-probe"}, "route profile"),
        ({"reason": "something else"}, "reason"),
    ):
        broken = {**json.loads(recorded_path.read_text(encoding="utf-8")), **mutation}
        with pytest.raises(probe.TopologyProbeError, match=pattern):
            probe.validate_route(broken)
    invented = json.loads(raw)
    invented["topology"] = "postgres-core"
    with pytest.raises(probe.TopologyProbeError, match="cardinality is not topology-derived"):
        probe.validate_route(invented)
    with pytest.raises(probe.TopologyProbeError, match="closed route keys"):
        probe.validate_route({**json.loads(raw), "extra": 1})
    with pytest.raises(probe.TopologyProbeError, match="not an object"):
        probe.validate_route(["nope"])

    # (8) contract-selected renders the ROUTE's class over the OBSERVED pairs,
    # and prints only the driver CPU list the launcher runs the driver on.
    contract_path = tmp_path / "placement.json"
    assert probe.main([
        "contract-selected", "--topology", chosen, "--pairs", "0-1", "2-3",
        "--run-id", _gc3_run_id(5), "--out", str(contract_path),
    ]) == 0
    written_contract = json.loads(contract_path.read_text(encoding="utf-8"))
    assert written_contract["profile"] == "ci-scale" and written_contract["schema"] == 3
    assert written_contract["topology"] == chosen
    declaration = B1PlacementDeclaration.from_contract(written_contract)
    assert declaration.topology == chosen
    assert declaration.cardinality == probe.topology_cardinality(chosen)
    assert probe.main([
        "contract-selected", "--topology", "gateway-hyperthread", "--pairs", "0-1", "2-3",
        "--run-id", _gc3_run_id(5), "--out", str(contract_path),
    ]) == 1


# ---------------------------------------------------------------------------
# GC-4 (FP-GC4-5/6) — the wait sampler and the reported-only cost fields,
# container-free. Bounded real threads over fake connections; every one of
# them must be gone before the test returns.
# ---------------------------------------------------------------------------


class _FakeWaitCursor:
    def __init__(self, connection):
        self._connection = connection
        self.closed = False

    def execute(self, statement, parameters):
        self._connection.statements.append((statement, dict(parameters)))
        if self._connection.gate is not None:
            self._connection.gate.wait(30)
        if self._connection.raises:
            raise RuntimeError("induced sample failure")

    def fetchall(self):
        return list(self._connection.rows)

    def close(self):
        self.closed = True
        self._connection.closed_cursors += 1


class _FakeWaitConnection:
    """A DBAPI-shaped stand-in with a controllable clock, rows and failures."""

    def __init__(self, rows=(), *, raises=False, gate=None, close_raises=False):
        self.rows = list(rows)
        self.raises = raises
        self.gate = gate
        self.close_raises = close_raises
        self.statements: list = []
        self.closed = False
        self.closed_cursors = 0

    def cursor(self):
        return _FakeWaitCursor(self)

    def close(self):
        self.closed = True
        if self.close_raises:
            raise RuntimeError("induced close failure")


def _drain_sampler(sampler, *, at_least: int = 1, timeout_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while sampler.scheduled < at_least and time.monotonic() < deadline:
        time.sleep(0.005)


def test_gc4_postgres_wait_sampler_classifies_serializes_and_stops():
    """FP-GC4-5: closed classification, sorted encoding, counts, stop/join/close."""
    # (1) Classification is closed. An active backend with no wait event is on
    # CPU; everything else keeps its own identity; a stateless row raises
    # rather than being folded into the CPU bucket.
    assert classify_postgres_wait("active", None, None) == B1_WAIT_ACTIVE_CPU_KEY
    assert classify_postgres_wait("active", "LWLock", "WALWrite") == "active/LWLock/WALWrite"
    assert classify_postgres_wait("active", "IO", "WALSync") == "active/IO/WALSync"
    assert (
        classify_postgres_wait("idle in transaction", "Client", "ClientRead")
        == "idle in transaction/Client/ClientRead"
    )
    assert (
        classify_postgres_wait("idle in transaction", None, None)
        == f"idle in transaction/{B1_WAIT_NONE}/{B1_WAIT_NONE}"
    )
    for bad in (None, ""):
        with pytest.raises(b1.B1PlacementParseError):
            classify_postgres_wait(bad, "LWLock", "WALWrite")

    # (2) Serialization: sorted keys, percent-encoded (the `/` of the key and
    # the spaces of a multi-word state included, because `:` and `+` are this
    # field's own separators), never a literal zero for "nothing observed".
    assert serialize_postgres_wait_histogram({}) == DIAGNOSTIC_UNAVAILABLE
    assert serialize_postgres_wait_histogram(None) == DIAGNOSTIC_UNAVAILABLE
    rendered = serialize_postgres_wait_histogram(
        {
            "active/LWLock/WALWrite": 3,
            B1_WAIT_ACTIVE_CPU_KEY: 12,
            "idle in transaction/Client/ClientRead": 1,
        }
    )
    assert rendered == (
        "active%2FCPU%2Frunning:12+active%2FLWLock%2FWALWrite:3"
        "+idle%20in%20transaction%2FClient%2FClientRead:1"
    )
    keys = [pair.rsplit(":", 1)[0] for pair in rendered.split("+")]
    assert keys == sorted(keys), keys
    assert all(char in B1_DIAGNOSTIC_SAFE_CHARACTERS or char == "%" for char in rendered)
    for bad_count in (-1, 1.5, True, "3"):
        with pytest.raises(b1.B1PlacementParseError):
            serialize_postgres_wait_histogram({B1_WAIT_ACTIVE_CPU_KEY: bad_count})

    # (3) A bounded real thread over a fake connection: counts accumulate, the
    # sampler's own backend is excluded by name in the statement it sends, and
    # `stop()` sets, joins, verifies and closes.
    connection = _FakeWaitConnection(
        rows=[("active", None, None, 2), ("active", "LWLock", "WALWrite", 1)]
    )
    sampler = B1PostgresWaitSampler(
        lambda: connection, target_database="dbagent", interval_s=0.001
    )
    sampler.start()
    try:
        _drain_sampler(sampler, at_least=3)
    finally:
        sample = sampler.stop()
    assert sample is not None
    assert sample.scheduled >= 3
    assert sample.completed == sample.scheduled
    assert sample.failed == 0
    assert sample.observations == 3 * sample.completed
    assert sample.histogram == {
        B1_WAIT_ACTIVE_CPU_KEY: 2 * sample.completed,
        "active/LWLock/WALWrite": sample.completed,
    }
    assert connection.closed is True
    assert connection.closed_cursors == sample.scheduled
    statement, parameters = connection.statements[0]
    assert "pg_backend_pid()" in statement
    assert "backend_type = 'client backend'" in statement
    # GC-5: the sampler lives on a maintenance database now, so the measured
    # database is named explicitly rather than taken from the connection.
    assert "datname = %(target_database)s" in statement
    assert "current_database()" not in statement
    assert "state <> 'idle'" in statement
    assert parameters == {
        "application_name": B1_WAIT_SAMPLER_APPLICATION_NAME,
        "target_database": "dbagent",
    }
    assert threading.active_count() >= 1
    assert not any(
        thread.name == B1_WAIT_SAMPLER_APPLICATION_NAME and thread.is_alive()
        for thread in threading.enumerate()
    )
    # ...and stopping twice is the same record, not a second teardown.
    assert sampler.stop() is sample

    # (4) A failing sample is RECORDED, never raised, and never counted as a
    # completed one.
    failing = _FakeWaitConnection(rows=[("active", None, None, 1)], raises=True)
    failing_sampler = B1PostgresWaitSampler(
        lambda: failing, target_database="dbagent", interval_s=0.001
    )
    failing_sampler.start()
    try:
        _drain_sampler(failing_sampler, at_least=2)
    finally:
        failed_sample = failing_sampler.stop()
    assert failed_sample.failed == failed_sample.scheduled >= 2
    assert failed_sample.completed == 0
    assert failed_sample.observations == 0
    assert failed_sample.histogram == {}
    assert failing.closed is True

    # (5) A never-started sampler has no record at all -- not a zero-valued one.
    def _refuse():
        raise RuntimeError("no diagnostic connection")

    unavailable = B1PostgresWaitSampler(_refuse, target_database="dbagent")
    with pytest.raises(RuntimeError):
        unavailable.start()
    assert unavailable.started is False
    assert unavailable.stop() is None

    # (6) A thread that will not stop is a defect: `stop()` closes the
    # connection FIRST and then raises, so a stuck sampler never also leaks a
    # backend. The gate is released here so this test leaves no live thread.
    gate = threading.Event()
    stuck = _FakeWaitConnection(rows=[], gate=gate)
    stuck_sampler = B1PostgresWaitSampler(
        lambda: stuck, target_database="dbagent", interval_s=0.001, join_timeout_s=0.2
    )
    stuck_sampler.start()
    try:
        _drain_sampler(stuck_sampler, at_least=1)
        with pytest.raises(B1PlacementError, match="still alive"):
            stuck_sampler.stop()
        assert stuck.closed is True
    finally:
        gate.set()
        for thread in threading.enumerate():
            if thread.name == B1_WAIT_SAMPLER_APPLICATION_NAME:
                thread.join(10)
    assert not any(
        thread.name == B1_WAIT_SAMPLER_APPLICATION_NAME and thread.is_alive()
        for thread in threading.enumerate()
    ), "a sampler thread outlived its test"


def _cost_run(**overrides) -> dict:
    sample = overrides.pop(
        "sample",
        B1PostgresWaitSample(
            scheduled=600,
            completed=600,
            failed=0,
            observations=1800,
            histogram={B1_WAIT_ACTIVE_CPU_KEY: 1200, "active/IO/WALSync": 600},
        ),
    )
    run = {
        "result": SimpleNamespace(served=30000),
        "postgres_usage_usec": 18_000_000,
        "p99_leg_split": (1.0, 2.0, 3.0),
        "leg_p99s": (1.5, 2.5, 3.5),
        "postgres_wait_sample": sample,
    }
    run.update(overrides)
    return run


def test_gc4_postgres_cost_fields_are_reported_only_and_fail_soft():
    """FP-GC4-5/6: derived CPU, pinned order, unavailable-not-zero, no verdict use."""
    sample = _cost_run()["postgres_wait_sample"]

    # (1) The derived value is the run's own quotient, in microseconds per
    # served request, at the pinned width.
    rendered = serialize_postgres_cost_fields(18_000_000, 30000, sample)
    fields = [pair.split("=", 1) for pair in rendered.split(",")]
    assert [name for name, _ in fields] == list(B1_POSTGRES_COST_FIELDS)
    values = dict(fields)
    assert values["postgres_cpu_us_per_req"] == "600.000"
    assert values["postgres_wait_scheduled"] == "600"
    assert values["postgres_wait_completed"] == "600"
    assert values["postgres_wait_failed"] == "0"
    assert values["postgres_wait_observations"] == "1800"
    assert values["postgres_wait_events_pct"] == serialize_postgres_wait_histogram(
        sample.histogram
    )

    # (2) A missing operand is `unavailable`, NEVER a zero that would read like
    # a measurement.
    for usage, served in ((None, 30000), (18_000_000, 0), (18_000_000, None),
                          (18_000_000, True), (True, 30000)):
        degraded = dict(
            pair.split("=", 1)
            for pair in serialize_postgres_cost_fields(usage, served, sample).split(",")
        )
        assert degraded["postgres_cpu_us_per_req"] == DIAGNOSTIC_UNAVAILABLE, (usage, served)
        assert degraded["postgres_cpu_us_per_req"] != "0.000"

    # (3) There is NO absolute completed-sample floor. A sub-500 sample that
    # is at least 90% complete is usable, and serializes its own counters --
    # restoring a 500-style rejection makes exactly this assertion fail.
    assert not hasattr(sys.modules[__name__], "B1_WAIT_MIN_COMPLETED_SAMPLES"), (
        "an absolute completed-sample floor was reintroduced"
    )
    short = B1PostgresWaitSample(
        scheduled=550, completed=499, failed=0, observations=1200,
        histogram={B1_WAIT_ACTIVE_CPU_KEY: 1200},
    )
    assert 499 < 500 and short.completed >= B1_WAIT_MIN_COMPLETION_RATIO * short.scheduled
    assert postgres_wait_sample_failure(short) is None
    assert postgres_cost_record_failures(_cost_run(sample=short)) == []
    usable = dict(
        pair.split("=", 1)
        for pair in serialize_postgres_cost_fields(18_000_000, 30000, short).split(",")
    )
    assert usable["postgres_wait_completed"] == "499"
    assert usable["postgres_wait_scheduled"] == "550"
    assert usable["postgres_wait_events_pct"] != DIAGNOSTIC_UNAVAILABLE

    # (4) An absent OR unusable sampler serializes every wait field as
    # `unavailable` -- never a zero, never a mixture -- and names its reason
    # with the raw counts it does have. None of it is fatal: the record and,
    # on the manual route, the GC-3 arm survive a failed sampler.
    unusable = [
        (None, "no measured-window PostgreSQL wait sample was taken"),
        (B1PostgresWaitSample(600, 599, 1, 1800, {B1_WAIT_ACTIVE_CPU_KEY: 1}), "failed"),
        (B1PostgresWaitSample(700, 600, 0, 1800, {B1_WAIT_ACTIVE_CPU_KEY: 1}), "completed"),
        (B1PostgresWaitSample(600, 600, 0, 0, {}), "histogram is empty"),
        (B1PostgresWaitSample(0, 0, 0, 0, {}), "scheduled"),
    ]
    for bad, expected in unusable:
        reason = postgres_wait_sample_failure(bad)
        assert reason is not None and expected in reason, (bad, reason)
        if bad is not None:
            for raw in ("scheduled=", "completed=", "failed=", "observations="):
                assert raw in reason, (raw, reason)
        rendered_bad = dict(
            pair.split("=", 1)
            for pair in serialize_postgres_cost_fields(18_000_000, 30000, bad).split(",")
        )
        for field in B1_POSTGRES_COST_FIELDS[1:]:
            assert rendered_bad[field] == DIAGNOSTIC_UNAVAILABLE, (bad, field)
            assert rendered_bad[field] != "0"
        # The PostgreSQL CPU reading is independent of the sampler...
        assert rendered_bad["postgres_cpu_us_per_req"] == "600.000"
        # ...and the harness-operand validator does not raise for any of them.
        assert postgres_cost_record_failures(_cost_run(sample=bad)) == []
        assert_complete_postgres_cost_record(_cost_run(sample=bad))

    # (5) The harness-owned operands ARE fatal, and every one is named.
    assert postgres_cost_record_failures(_cost_run()) == []
    assert_complete_postgres_cost_record(_cost_run())
    cases = [
        ({"postgres_usage_usec": None}, "postgres_usage_usec"),
        ({"postgres_usage_usec": 0}, "postgres_usage_usec"),
        ({"result": SimpleNamespace(served=0)}, "served"),
        ({"p99_leg_split": (1.0, 2.0)}, "p99_leg_split"),
        ({"leg_p99s": None}, "leg_p99s"),
        ({"leg_p99s": (1.0, 2.0, float("nan"))}, "leg_p99s"),
    ]
    for overrides, expected in cases:
        failures = postgres_cost_record_failures(_cost_run(**overrides))
        assert any(expected in failure for failure in failures), (overrides, failures)
        with pytest.raises(B1PlacementError, match="incomplete GC-4 cost record"):
            assert_complete_postgres_cost_record(_cost_run(**overrides))

    # (6) Reported-only, structurally: no cost field is a gating placement
    # field, a product verdict, a discovery verdict or a GC-3 record key. The
    # new diagnostics travel inside the existing fingerprint field and nowhere
    # else, so the decision carrier's embedded evidence stays valid.
    for field in B1_POSTGRES_COST_FIELDS:
        assert field not in B1_PLACEMENT_FIELDS
        assert field not in B1_TOPOLOGY_PLACEMENT_FIELDS
        assert field not in PRODUCT_VERDICT_FIELDS
        assert field not in probe.VERDICT_FIELDS
        assert field not in probe.RECORD_KEYS


def test_gc4_probe_arm_is_written_when_only_the_wait_sampler_is_unavailable():
    """FP-GC4-5 / FP-GC3-2: a failed GC-4 diagnostic never voids a GC-3 arm.

    The 28-arm discovery sweep is GC-3's evidence. A test-only wait sampler
    that fails one `pg_stat_activity` query must not be able to destroy an
    arm's artifact, so the shared validator the manual node calls is proven
    here to accept every unusable-sampler shape, and the node itself is proven
    to reach `write_probe_arm_record` unconditionally after it.
    """
    probe_src = (Path(__file__).resolve().parent / "b1_topology_probe_live.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(probe_src)
    node = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "test_b1_ci_scale_topology_probe_record"
    )

    # (a) Behavioural: for every unusable-sampler shape the validator accepts
    # the record, and the wait fields degrade to `unavailable` plus a reason.
    for bad in (
        None,
        B1PostgresWaitSample(600, 599, 1, 1800, {B1_WAIT_ACTIVE_CPU_KEY: 1}),
        B1PostgresWaitSample(700, 600, 0, 1800, {B1_WAIT_ACTIVE_CPU_KEY: 1}),
        B1PostgresWaitSample(600, 600, 0, 0, {}),
    ):
        run = _cost_run(sample=bad)
        assert_complete_postgres_cost_record(run)  # must not raise
        assert postgres_wait_sample_failure(bad) is not None
        rendered = dict(
            pair.split("=", 1)
            for pair in serialize_postgres_cost_fields(18_000_000, 30000, bad).split(",")
        )
        assert {rendered[f] for f in B1_POSTGRES_COST_FIELDS[1:]} == {
            DIAGNOSTIC_UNAVAILABLE
        }

    # (b) Structural: the validator call is an unconditional statement of the
    # node body, `write_probe_arm_record(record)` follows it, and nothing
    # between them can return, raise or branch around the write.
    statements = node.body
    validator_at = next(
        i for i, stmt in enumerate(statements)
        if "assert_complete_postgres_cost_record" in ast.unparse(stmt)
    )
    write_at = next(
        i for i, stmt in enumerate(statements)
        if "write_probe_arm_record" in ast.unparse(stmt)
    )
    assert validator_at < write_at, "the arm is written before it is validated"
    assert isinstance(statements[validator_at], ast.Expr), (
        "the validator call is not a plain statement of the node body"
    )
    for stmt in statements[validator_at:write_at]:
        rendered = ast.unparse(stmt)
        for escape in ("return", "raise", "pytest.skip", "if "):
            assert escape not in rendered, (
                f"a {escape!r} sits between the validator and the arm write: {rendered}"
            )

    # (c) ...and the validator the node calls owns no wait-sampler rule at all.
    validator_src = ast.get_source_segment(
        Path(__file__).read_text(encoding="utf-8"),
        next(
            n for n in ast.walk(ast.parse(Path(__file__).read_text(encoding="utf-8")))
            if isinstance(n, ast.FunctionDef) and n.name == "postgres_cost_record_failures"
        ),
    ) or ""
    for forbidden in ("postgres_wait_sample", "failed", "histogram", "scheduled"):
        assert forbidden not in validator_src.split('"""')[-1], forbidden


# ---------------------------------------------------------------------------
# GC-5 (FP-GC5-7/8) — the maintenance-database stats reader and the eight
# transaction/WAL fields, container-free. Real threads are not needed here:
# the reader is synchronous and its connection is faked.
# ---------------------------------------------------------------------------


def _commit_snapshot(**overrides) -> B1PostgresCommitSnapshot:
    base = dict(
        database_name="dbagent",
        database_oid=16384,
        xact_commit=1_000,
        xact_rollback=5,
        database_stats_reset="2026-09-17 00:00:00+00",
        wal_records=2_000,
        wal_bytes=900_000,
        wal_write=300,
        wal_sync=120,
        wal_stats_reset="2026-09-17 00:00:00+00",
    )
    base.update(overrides)
    return B1PostgresCommitSnapshot(**base)


class _FakeStatsCursor:
    def __init__(self, connection):
        self._connection = connection
        self.closed = False

    def execute(self, statement, parameters=None):
        self._connection.statements.append((statement, parameters))
        if B1_WAL_STATS_SQL in statement:
            self._connection.rows = list(self._connection.wal_rows)
        else:
            self._connection.rows = list(self._connection.database_rows())

    def fetchall(self):
        return list(self._connection.rows)

    def close(self):
        self.closed = True
        self._connection.closed_cursors += 1


class _FakeStatsConnection:
    """A DBAPI-shaped stand-in whose target counter can advance per read."""

    def __init__(self, commits, *, oid=16384, datname="dbagent", wal_rows=None,
                 increasing=False):
        self.commits = list(commits)
        self.increasing = increasing
        self.oid = oid
        self.datname = datname
        self.wal_rows = wal_rows or [(2_000, 900_000, 300, 120, "2026-09-17 00:00:00+00")]
        self.statements: list = []
        self.rows: list = []
        self.closed = False
        self.closed_cursors = 0
        self.reads = 0

    def database_rows(self):
        if self.increasing:
            value = self.commits[0] + self.reads
        else:
            value = self.commits[min(self.reads, len(self.commits) - 1)]
        self.reads += 1
        return [(self.oid, self.datname, value, 5, "2026-09-17 00:00:00+00")]

    def cursor(self):
        return _FakeStatsCursor(self)

    def close(self):
        self.closed = True


def test_gc5_postgres_snapshot_uses_a_distinct_maintenance_database():
    """FP-GC5-7: both readers leave the measured database's counter alone.

    The DSN rewrite, the retained sampler exclusion, the target identity, the
    publication/stability rule and the unavailable-not-zero behaviour, all
    without a container: a reader that connected to the measured database
    would commit its own read transactions into the very counter it reports.
    """
    target = "postgresql+psycopg2://dbagent:dbagent@127.0.0.1:5433/dbagent"

    # (1) The DSN rewrite: same server, same credentials, a DIFFERENT database,
    # and an application name that identifies the reader.
    assert target_database_name(target) == "dbagent"
    assert maintenance_database_name(target) == B1_MAINTENANCE_DATABASE
    rewritten = maintenance_dsn(target, B1_STATS_READER_APPLICATION_NAME)
    from sqlalchemy.engine import make_url

    url = make_url(rewritten)
    assert url.database == B1_MAINTENANCE_DATABASE != target_database_name(target)
    assert (url.host, url.port, url.username, url.password) == (
        "127.0.0.1", 5433, "dbagent", "dbagent",
    )
    assert url.query["application_name"] == B1_STATS_READER_APPLICATION_NAME
    assert url.get_backend_name() == "postgresql"

    # ...and when the measured database IS `postgres`, the maintenance one is
    # the documented alternate, never the target itself.
    self_named = "postgresql://dbagent@127.0.0.1:5433/postgres"
    assert maintenance_database_name(self_named) == B1_MAINTENANCE_DATABASE_ALTERNATE
    assert make_url(
        maintenance_dsn(self_named, B1_STATS_READER_APPLICATION_NAME)
    ).database == B1_MAINTENANCE_DATABASE_ALTERNATE
    with pytest.raises(B1PlacementError):
        target_database_name("postgresql://dbagent@127.0.0.1:5433/")

    # (2) The GC-4 wait sampler moved with it and kept its own exclusion: its
    # connection is the maintenance one, its application name is unchanged,
    # and the measured database is now named explicitly in the statement.
    sampler_dsn = maintenance_dsn(target, B1_WAIT_SAMPLER_APPLICATION_NAME)
    sampler_url = make_url(sampler_dsn)
    assert sampler_url.database == B1_MAINTENANCE_DATABASE
    assert sampler_url.query["application_name"] == B1_WAIT_SAMPLER_APPLICATION_NAME
    assert "coalesce(application_name, '') <> %(application_name)s" in B1_WAIT_SAMPLE_SQL
    assert "datname = %(target_database)s" in B1_WAIT_SAMPLE_SQL
    assert "current_database()" not in B1_WAIT_SAMPLE_SQL

    # (3) The reader asks for the measured database by name and reads the
    # cluster's WAL row, through one connection it owns.
    connection = _FakeStatsConnection([1_000])
    reader = B1PostgresStatsReader(
        lambda: connection, target_database="dbagent",
        sleep=lambda _s: None, monotonic=lambda: 0.0,
    )
    snapshot = reader.snapshot()
    assert snapshot.database_name == "dbagent" and snapshot.database_oid == 16384
    assert snapshot.xact_commit == 1_000 and snapshot.xact_rollback == 5
    assert (snapshot.wal_records, snapshot.wal_bytes) == (2_000, 900_000)
    assert (snapshot.wal_write, snapshot.wal_sync) == (300, 120)
    statements = [statement for statement, _ in connection.statements]
    assert any("pg_stat_database" in statement for statement in statements)
    assert any("pg_stat_wal" in statement for statement in statements)
    assert connection.statements[0][1] == {"target_database": "dbagent"}
    for statement in statements:
        assert "current_database()" not in statement, statement
    reader.close()
    assert connection.closed is True

    # (4) A missing or duplicated target row is a failure, not a guess.
    for rows in ([], [1, 2]):
        broken = _FakeStatsConnection([1_000])
        broken.database_rows = lambda rows=rows: [
            (16384, "dbagent", 1, 0, "r") for _ in rows
        ]
        with pytest.raises(B1PlacementError):
            B1PostgresStatsReader(
                lambda: broken, target_database="dbagent"
            ).snapshot()

    # (5) Publication and stability: the reader waits at least 1.1 s, then
    # reads until two consecutive counters 100 ms apart agree.
    slept: list[float] = []
    ticking = _FakeStatsConnection([1_000, 1_005, 1_007, 1_007, 1_007])
    clock = {"now": 0.0}

    def _sleep(seconds):
        slept.append(seconds)
        clock["now"] += seconds

    stable = B1PostgresStatsReader(
        lambda: ticking, target_database="dbagent",
        sleep=_sleep, monotonic=lambda: clock["now"],
    )
    assert stable.wait_until_published() == 1_007
    assert slept[0] == B1_STATS_PUBLICATION_WAIT_S
    assert slept[1:] == [B1_STATS_STABLE_INTERVAL_S] * (len(slept) - 1)

    # ...and a counter that never settles is a bounded failure, not a hang.
    forever = _FakeStatsConnection([1], increasing=True)
    runaway = {"now": 0.0}

    def _runaway_sleep(seconds):
        runaway["now"] += seconds

    with pytest.raises(B1PlacementError, match="did not settle"):
        B1PostgresStatsReader(
            lambda: forever, target_database="dbagent",
            sleep=_runaway_sleep, monotonic=lambda: runaway["now"],
        ).wait_until_published()

    # (6) Closing a reader that never connected is safe, and a close failure
    # cannot fail the run.
    B1PostgresStatsReader(lambda: None, target_database="dbagent").close()

    class _CloseRaises(_FakeStatsConnection):
        def close(self):
            raise RuntimeError("induced close failure")

    raising = _CloseRaises([1])
    closing_reader = B1PostgresStatsReader(
        lambda: raising, target_database="dbagent"
    )
    closing_reader.snapshot()
    closing_reader.close()


def test_gc5_commit_shape_fields_serialize_honestly_and_only_ratio_gates():
    """FP-GC5-7/8: exact fields and arithmetic, the 0.60 boundary, no proxies."""
    before = _commit_snapshot(xact_commit=1_000, xact_rollback=5,
                              wal_records=2_000, wal_bytes=900_000,
                              wal_write=300, wal_sync=120)
    after = _commit_snapshot(xact_commit=1_300, xact_rollback=9,
                             wal_records=4_400, wal_bytes=1_800_000,
                             wal_write=460, wal_sync=180)

    # (1) Exact field inventory, order and arithmetic.
    rendered = serialize_postgres_commit_fields(before, after, 1_000)
    fields = [pair.split("=", 1) for pair in rendered.split(",")]
    assert [name for name, _ in fields] == list(B1_POSTGRES_COMMIT_FIELDS)
    values = dict(fields)
    assert values["postgres_xact_commit_delta"] == "300"
    assert values["postgres_xact_rollback_delta"] == "4"
    assert values["postgres_xact_commits_per_served"] == "0.300000"
    assert values["postgres_wal_records_delta"] == "2400"
    assert values["postgres_wal_bytes_delta"] == "900000"
    assert values["postgres_wal_write_delta"] == "160"
    assert values["postgres_wal_sync_delta"] == "60"
    assert values["postgres_wal_syncs_per_served"] == "0.060000"
    assert postgres_xact_commits_per_served(before, after, 1_000) == 0.3

    # (2) The ratio is computed against SERVED, not offered, and unrounded:
    # a value that renders as `0.600000` but exceeds the bar still fails it.
    assert postgres_xact_commits_per_served(before, after, 500) == 0.6
    exactly = _commit_snapshot(xact_commit=1_600)
    assert postgres_xact_commits_per_served(before, exactly, 1_000) == 0.6
    assert (
        postgres_xact_commits_per_served(before, exactly, 1_000)
        <= B1_COMMIT_SHAPE_MAX_COMMITS_PER_SERVED
    ), "the boundary value 0.60 must satisfy the bar"
    just_over = _commit_snapshot(xact_commit=1_600 + 1)
    ratio = postgres_xact_commits_per_served(before, just_over, 1_000)
    assert ratio > B1_COMMIT_SHAPE_MAX_COMMITS_PER_SERVED
    rounding = _commit_snapshot(xact_commit=1_000 + 600_000)
    rounded_ratio = postgres_xact_commits_per_served(before, rounding, 1_000_000)
    assert rounded_ratio == 0.6
    barely = _commit_snapshot(xact_commit=1_000 + 600_001)
    barely_ratio = postgres_xact_commits_per_served(before, barely, 1_000_000)
    assert f"{barely_ratio:.6f}" == "0.600001"
    assert barely_ratio > B1_COMMIT_SHAPE_MAX_COMMITS_PER_SERVED, (
        "a ratio above the bar must fail even when its rendering is close"
    )
    # ...and a ratio that ROUNDING would wash out still exceeds the bar: the
    # quantity is compared unrounded, so a `round(..., 6)` in the computation
    # would turn this into a false pass.
    washed = _commit_snapshot(xact_commit=1_000 + 6_000_001)
    washed_ratio = postgres_xact_commits_per_served(before, washed, 10_000_000)
    assert round(washed_ratio, 6) == 0.6, washed_ratio
    assert washed_ratio > B1_COMMIT_SHAPE_MAX_COMMITS_PER_SERVED, (
        "the ratio is rounded before it is compared"
    )
    assert washed_ratio == pytest.approx(0.6000001, abs=1e-12)

    # (3) Every unusable observation renders `unavailable` in ALL eight
    # fields -- never a zero, never a mixture -- and names its reason.
    unusable = [
        ((None, after, 1_000), "no measured-window PostgreSQL transaction snapshot"),
        ((before, None, 1_000), "no measured-window PostgreSQL transaction snapshot"),
        ((before, _commit_snapshot(database_oid=99, xact_commit=1_300), 1_000),
         "changed identity"),
        ((before, _commit_snapshot(database_name="other", xact_commit=1_300), 1_000),
         "changed identity"),
        ((before, _commit_snapshot(xact_commit=1_300,
                                   database_stats_reset="2026-09-17 01:00:00+00"), 1_000),
         "pg_stat_database was reset"),
        ((before, _commit_snapshot(xact_commit=1_300,
                                   wal_stats_reset="2026-09-17 01:00:00+00"), 1_000),
         "pg_stat_wal was reset"),
        ((before, _commit_snapshot(xact_commit=999), 1_000), "xact_commit decreased"),
        ((before, _commit_snapshot(xact_commit=1_300, wal_sync=1), 1_000),
         "wal_sync decreased"),
        ((before, _commit_snapshot(xact_commit=1_000), 1_000), "no database transaction"),
        ((before, after, 0), "served is not a positive count"),
        ((before, after, None), "served is not a positive count"),
        ((before, after, True), "served is not a positive count"),
    ]
    for (start, end, served), expected in unusable:
        reason = postgres_commit_snapshot_failure(start, end, served)
        assert reason is not None and expected in reason, (expected, reason)
        degraded = dict(
            pair.split("=", 1)
            for pair in serialize_postgres_commit_fields(start, end, served).split(",")
        )
        assert set(degraded) == set(B1_POSTGRES_COMMIT_FIELDS)
        for field in B1_POSTGRES_COMMIT_FIELDS:
            assert degraded[field] == DIAGNOSTIC_UNAVAILABLE, (expected, field)
            assert degraded[field] not in ("0", "0.000000"), (expected, field)
        # ...and such a record cannot satisfy FP-GC5-7.
        run = {
            "result": SimpleNamespace(served=served),
            "postgres_commit_before": start,
            "postgres_commit_after": end,
        }
        assert commit_shape_record_failures(run), expected
        with pytest.raises(B1PlacementError, match="incomplete GC-5 commit-shape"):
            assert_complete_commit_shape_record(run)

    # (4) A complete observation is admissible, and the validator judges
    # nothing else: no CPU, p99, in-flight, wait or WAL direction.
    good = {
        "result": SimpleNamespace(served=1_000),
        "postgres_commit_before": before,
        "postgres_commit_after": after,
    }
    assert commit_shape_record_failures(good) == []
    assert_complete_commit_shape_record(good)
    validator_source = ast.get_source_segment(
        Path(__file__).read_text(encoding="utf-8"),
        next(
            node for node in ast.walk(ast.parse(Path(__file__).read_text(encoding="utf-8")))
            if isinstance(node, ast.FunctionDef)
            and node.name == "commit_shape_record_failures"
        ),
    ) or ""
    body = validator_source.split('"""')[-1]
    for proxy in ("cpu", "p99", "max_in_flight", "wait", "wal"):
        assert proxy not in body.lower(), proxy

    # (5) Reported-only, structurally: no transaction field is a gating
    # placement field, a product verdict, a GC-3 verdict or a GC-3 record key.
    for field in B1_POSTGRES_COMMIT_FIELDS:
        assert field not in B1_PLACEMENT_FIELDS
        assert field not in B1_GATING_PLACEMENT_FIELDS
        assert field not in B1_TOPOLOGY_PLACEMENT_FIELDS
        assert field not in B1_TOPOLOGY_GATING_PLACEMENT_FIELDS
        assert field not in PRODUCT_VERDICT_FIELDS
        assert field not in probe.VERDICT_FIELDS
        assert field not in probe.RECORD_KEYS
    # ...and the eight fields are distinct from the six GC-4 cost fields.
    assert not set(B1_POSTGRES_COMMIT_FIELDS) & set(B1_POSTGRES_COST_FIELDS)
