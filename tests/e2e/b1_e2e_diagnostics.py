"""B1 e2e baseline diagnostics (slice e2e-b1-diagnostics, FP-E2EB1D-1..9).

Reported-only. Nothing in this module enters an assertion, a branch on a
verdict, a retry, a route, a skip, an xfail or a result mask: it collects
boundary readings around the already-closed baseline window, renders one
canonical line, prints it and writes it to the existing failure-artifact tree.

Not collected by pytest (the name does not match ``python_files``). Imported
by ``tests/e2e/test_e2e_load.py`` and exercised by the delivery tier through
its injectable ``run`` seam.

Stdlib and test-harness only: no product-runtime import, no environment read,
no ``Popen``, no polling thread or task, and no outcome logic.
"""
from __future__ import annotations

import json
import math
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Literal, Mapping, Sequence, TextIO
from urllib.parse import quote

# Direct pure imports from the shipped reference harness (design §3.1). Each
# binding is total over caller-supplied data; none of them reads a file, a
# socket or the environment, and none of them is re-exported from here.
from services.gateway.tests.b1_reference_profile import (
    counter_delta,
    parse_proc_stat_steal_ticks,
    parse_psi_total,
    serialize_leg_triple,
    serialize_status_histogram,
    steal_ticks_to_usec,
)

# --------------------------------------------------------------------------
# Fixed identities (design §3.3). Every one is a literal bound exactly once;
# none is composed from a pod value, a command output or the environment.
# --------------------------------------------------------------------------

DIAGNOSTIC_COMMAND_TIMEOUT_S = 5.0
CommandRunner = Callable[..., "subprocess.CompletedProcess[str]"]

NAMESPACE = "dbagent"
RELEASE_SELECTOR = "app.kubernetes.io/instance=dbagent"
COMPONENT_LABEL = "app.kubernetes.io/component"
GATEWAY_COMPONENT = "ingest-gateway"
GATEWAY_CONTAINER = "ingest-gateway"
POSTGRES_COMPONENT = "postgresql"
POSTGRES_CONTAINER = "postgresql"
KIND_CLUSTER = "rca-e2e"

B1_E2E_DIAGNOSTIC_PREFIX = "B1 e2e baseline diagnostics="
B1_E2E_DIAGNOSTIC_UNAVAILABLE = "unavailable"
B1_E2E_DIAGNOSTIC_ARTIFACT = Path("/tmp/rca-e2e/b1-baseline-diagnostics.txt")
B1_E2E_DIAGNOSTIC_SCHEMA = 1
B1_E2E_DIAGNOSTIC_FIELDS = (
    "schema",
    "offered", "served", "errors", "p99_ms",
    "p99_leg_split_ms", "leg_p99s_ms", "status_histogram",
    "max_in_flight",
    "gateway_pod", "gateway_cpu_usage_usec",
    "gateway_nr_throttled", "gateway_throttled_usec",
    "postgres_pod", "postgres_cpu_usage_usec",
    "postgres_nr_throttled", "postgres_throttled_usec",
    "kind_node", "runner_steal_usec",
    "runner_psi_cpu_some_usec", "runner_psi_cpu_full_usec",
    "runner_psi_io_some_usec", "runner_psi_io_full_usec",
    "runner_psi_memory_some_usec", "runner_psi_memory_full_usec",
    "pg_xact_commit_delta", "pg_wal_records_delta",
    "pg_wal_bytes_delta", "pg_wal_write_delta", "pg_wal_sync_delta",
    "pg_track_wal_io_timing", "pg_wal_write_time_ms_delta",
    "pg_wal_sync_time_ms_delta",
)
#: Percent-encoding safe set. Comma, equals and percent are deliberately NOT
#: safe: no arbitrary string may forge a top-level field boundary.
B1_E2E_DIAGNOSTIC_SAFE_CHARACTERS = "-._~:+/;@"

#: The PSI resources and record names, in canonical field order.
PSI_RESOURCES = ("cpu", "io", "memory")
PSI_RECORDS = ("some", "full")

# --------------------------------------------------------------------------
# Framed source scripts. Fixed literals: never composed, never templated.
# --------------------------------------------------------------------------

_FRAME_BEGIN = "#b1diag-begin:"
_FRAME_END = "#b1diag-end:"

#: The workload cgroup read. One fixed literal, used unchanged inside BOTH
#: application containers: run in the gateway pod it reports the gateway's own
#: accounting, and run in the PostgreSQL pod it reports PostgreSQL's.
_WORKLOAD_CGROUP_SCRIPT = (
    "echo '#b1diag-begin:proc_self_cgroup'\n"
    "cat /proc/self/cgroup 2>/dev/null\n"
    "echo '#b1diag-end:proc_self_cgroup'\n"
    "echo '#b1diag-begin:cpu_stat_v2'\n"
    "cat /sys/fs/cgroup/cpu.stat 2>/dev/null\n"
    "echo '#b1diag-end:cpu_stat_v2'\n"
    "echo '#b1diag-begin:cpuacct_usage_v1'\n"
    "if [ -f /sys/fs/cgroup/cpuacct/cpuacct.usage ]; then "
    "cat /sys/fs/cgroup/cpuacct/cpuacct.usage; fi\n"
    "echo '#b1diag-end:cpuacct_usage_v1'\n"
    "echo '#b1diag-begin:cpu_stat_v1'\n"
    "if [ -f /sys/fs/cgroup/cpu/cpu.stat ]; then cat /sys/fs/cgroup/cpu/cpu.stat; fi\n"
    "echo '#b1diag-end:cpu_stat_v1'\n"
)

#: The whole PostgreSQL statistics read, as one fixed script literal. It
#: connects to the separate ``postgres`` database, so its own transaction
#: never increments the measured ``dbagent`` commit counter (design §3.4).
_POSTGRES_STATS_FRAGMENT = (
    "echo '#b1diag-begin:pg_stats'\n"
    "psql --no-psqlrc --tuples-only --no-align -F '|' \\\n"
    "  -U dbagent -d postgres -h /var/run/postgresql \\\n"
    "  -c \"SELECT current_setting('track_wal_io_timing'),\n"
    "             d.xact_commit, d.stats_reset,\n"
    "             w.wal_records, w.wal_bytes::bigint, w.wal_write, w.wal_sync,\n"
    "             w.wal_write_time, w.wal_sync_time, w.stats_reset\n"
    "      FROM pg_stat_database AS d\n"
    "      CROSS JOIN pg_stat_wal AS w\n"
    "      WHERE d.datname = 'dbagent';\" 2>/dev/null\n"
    "echo '#b1diag-end:pg_stats'\n"
)
#: Open queries statistics FIRST and reads cpu.stat LAST; close reverses that,
#: so the query's own client/server work sits outside the CPU interval as far
#: as boundary ordering allows (design §3.4).
_POSTGRES_OPEN_SCRIPT = _POSTGRES_STATS_FRAGMENT + _WORKLOAD_CGROUP_SCRIPT
_POSTGRES_CLOSE_SCRIPT = _WORKLOAD_CGROUP_SCRIPT + _POSTGRES_STATS_FRAGMENT

#: Kernel-global counters, read through the verified kind-node route. These
#: files are NOT namespaced: the values describe the whole runner VM, which is
#: why every field built from them is named ``runner_*`` (design §3.3).
_RUNNER_COUNTER_SCRIPT = (
    "echo '#b1diag-begin:proc_stat'\n"
    "cat /proc/stat 2>/dev/null\n"
    "echo '#b1diag-end:proc_stat'\n"
    "echo '#b1diag-begin:psi_cpu'\n"
    "cat /proc/pressure/cpu 2>/dev/null\n"
    "echo '#b1diag-end:psi_cpu'\n"
    "echo '#b1diag-begin:psi_io'\n"
    "cat /proc/pressure/io 2>/dev/null\n"
    "echo '#b1diag-end:psi_io'\n"
    "echo '#b1diag-begin:psi_memory'\n"
    "cat /proc/pressure/memory 2>/dev/null\n"
    "echo '#b1diag-end:psi_memory'\n"
    "echo '#b1diag-begin:clk_tck'\n"
    "getconf CLK_TCK 2>/dev/null\n"
    "echo '#b1diag-end:clk_tck'\n"
)

POD_QUERY_ARGV = [
    "kubectl", "-n", NAMESPACE, "get", "pods",
    "-l", RELEASE_SELECTOR, "-o", "json",
]
KIND_NODES_ARGV = ["kind", "get", "nodes", "--name", KIND_CLUSTER]


class DiagnosticSourceError(RuntimeError):
    """A source was unusable. Never an outcome: only an ``unavailable``."""


# --------------------------------------------------------------------------
# Parsed source records
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PodTarget:
    name: str
    uid: str
    node_name: str
    container_id: str
    container_name: str


@dataclass(frozen=True)
class CgroupCpuReading:
    """One workload container's own cgroup CPU accounting, in microseconds."""

    usage_usec: int
    nr_throttled: int
    throttled_usec: int
    cgroup_version: int


@dataclass(frozen=True)
class RunnerCounters:
    """Whole-runner-kernel counters. Never node-container-cgroup scope."""

    steal_ticks: int
    clock_ticks: int | None
    psi: Mapping[str, int | None]


@dataclass(frozen=True)
class PostgresStats:
    track_wal_io_timing: str
    xact_commit: int
    db_stats_reset: str
    wal_records: int
    wal_bytes: int
    wal_write: int
    wal_sync: int
    wal_write_time_ms: float
    wal_sync_time_ms: float
    wal_stats_reset: str


@dataclass(frozen=True)
class BoundarySnapshot:
    """Resolved identities plus the parsed optional source counters."""

    label: str
    gateway: PodTarget | None = None
    postgres: PodTarget | None = None
    gateway_cpu: CgroupCpuReading | None = None
    postgres_cpu: CgroupCpuReading | None = None
    kind_node: str | None = None
    runner: RunnerCounters | None = None
    postgres_stats: PostgresStats | None = None


def unavailable_snapshot(label: str) -> BoundarySnapshot:
    """A complete snapshot in which every source is honestly absent."""
    return BoundarySnapshot(label=str(label))


# --------------------------------------------------------------------------
# Command execution. One helper, one keyword set, no retry.
# --------------------------------------------------------------------------


def _run_command(
    run: CommandRunner, argv: Sequence[str]
) -> "subprocess.CompletedProcess[str] | None":
    """Run one fixed command once. A failed command is a missing source."""
    try:
        return run(
            list(argv),
            capture_output=True,
            text=True,
            check=False,
            timeout=DIAGNOSTIC_COMMAND_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _stdout_of(completed: "subprocess.CompletedProcess[str] | None") -> str | None:
    if completed is None or completed.returncode != 0:
        return None
    text = completed.stdout
    if not isinstance(text, str):
        return None
    return text


# --------------------------------------------------------------------------
# Framing and parsing
# --------------------------------------------------------------------------


def parse_frames(text: str) -> dict[str, str]:
    """Split a framed source payload into ``{name: body}``.

    A duplicated, unterminated or unopened frame is refused: a half-read
    payload must not look like a complete one.
    """
    if not isinstance(text, str):
        raise DiagnosticSourceError(f"framed payload is not a string: {text!r}")
    frames: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith(_FRAME_BEGIN):
            if current is not None:
                raise DiagnosticSourceError(f"nested frame {line!r}")
            current = line[len(_FRAME_BEGIN):]
            if current in frames:
                raise DiagnosticSourceError(f"duplicate frame {current!r}")
            frames[current] = []
            continue
        if line.startswith(_FRAME_END):
            name = line[len(_FRAME_END):]
            if current is None or name != current:
                raise DiagnosticSourceError(f"unbalanced frame end {line!r}")
            current = None
            continue
        if current is not None:
            frames[current].append(line)
    if current is not None:
        raise DiagnosticSourceError(f"unterminated frame {current!r}")
    return {name: "\n".join(body) for name, body in frames.items()}


def _parse_counter_lines(body: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in body.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) != 2:
            raise DiagnosticSourceError(f"malformed cgroup counter line {line!r}")
        key, raw = fields
        if key in out:
            raise DiagnosticSourceError(f"duplicate cgroup counter {key!r}")
        if not raw.isdecimal():
            raise DiagnosticSourceError(f"non-decimal cgroup counter {key}={raw!r}")
        out[key] = int(raw)
    return out


def parse_cgroup_cpu_frames(frames: Mapping[str, str]) -> CgroupCpuReading:
    """One container's CPU accounting from the framed v2 or v1 payload.

    Nanosecond v1 values are kept in nanoseconds here and converted only
    AFTER the window subtraction (design §3.8); the conversion below is of a
    single reading's unit, not of a delta, and is therefore refused: the v1
    reading keeps its nanosecond magnitude and is converted in
    :func:`cgroup_cpu_delta`.
    """
    if not isinstance(frames, Mapping):
        raise DiagnosticSourceError("cgroup frames must be a mapping")
    for required in ("proc_self_cgroup", "cpu_stat_v2", "cpuacct_usage_v1", "cpu_stat_v1"):
        if required not in frames:
            raise DiagnosticSourceError(f"missing cgroup frame {required!r}")
    if not frames["proc_self_cgroup"].strip():
        raise DiagnosticSourceError("the exec process published no /proc/self/cgroup")
    v2_body = frames["cpu_stat_v2"].strip()
    usage_v1_body = frames["cpuacct_usage_v1"].strip()
    stat_v1_body = frames["cpu_stat_v1"].strip()
    has_v2 = bool(v2_body)
    has_v1 = bool(usage_v1_body) or bool(stat_v1_body)
    if has_v2 and has_v1:
        raise DiagnosticSourceError("mixed cgroup v1/v2 payload")
    if has_v2:
        values = _parse_counter_lines(v2_body)
        missing = [k for k in ("usage_usec", "nr_throttled", "throttled_usec") if k not in values]
        if missing:
            raise DiagnosticSourceError(f"incomplete cgroup v2 cpu.stat: missing {missing}")
        return CgroupCpuReading(
            usage_usec=values["usage_usec"],
            nr_throttled=values["nr_throttled"],
            throttled_usec=values["throttled_usec"],
            cgroup_version=2,
        )
    if not (usage_v1_body and stat_v1_body):
        raise DiagnosticSourceError("incomplete cgroup v1 payload")
    if not usage_v1_body.isdecimal():
        raise DiagnosticSourceError(f"non-decimal cpuacct.usage {usage_v1_body!r}")
    values = _parse_counter_lines(stat_v1_body)
    missing = [k for k in ("nr_throttled", "throttled_time") if k not in values]
    if missing:
        raise DiagnosticSourceError(f"incomplete cgroup v1 cpu.stat: missing {missing}")
    return CgroupCpuReading(
        usage_usec=int(usage_v1_body),
        nr_throttled=values["nr_throttled"],
        throttled_usec=values["throttled_time"],
        cgroup_version=1,
    )


def cgroup_cpu_delta(
    before: CgroupCpuReading, after: CgroupCpuReading, *, label: str
) -> tuple[int, int, int]:
    """``(usage_usec, nr_throttled, throttled_usec)`` across the window.

    v1 nanosecond magnitudes are converted to microseconds only here, after
    the subtraction, so no fabricated microsecond is ever reported.
    """
    if before.cgroup_version != after.cgroup_version:
        raise DiagnosticSourceError(
            f"{label}: cgroup version changed inside the window "
            f"({before.cgroup_version} -> {after.cgroup_version})"
        )
    usage = counter_delta(before.usage_usec, after.usage_usec, label=f"{label} usage")
    throttled = counter_delta(
        before.throttled_usec, after.throttled_usec, label=f"{label} throttled"
    )
    periods = counter_delta(
        before.nr_throttled, after.nr_throttled, label=f"{label} nr_throttled"
    )
    if before.cgroup_version == 1:
        usage = usage // 1000
        throttled = throttled // 1000
    return usage, periods, throttled


def parse_runner_frames(frames: Mapping[str, str]) -> RunnerCounters:
    """Whole-runner steal ticks, PSI totals and CLK_TCK from the node route."""
    if not isinstance(frames, Mapping):
        raise DiagnosticSourceError("runner frames must be a mapping")
    if "proc_stat" not in frames:
        raise DiagnosticSourceError("missing proc_stat frame")
    aggregate, _per_cpu = parse_proc_stat_steal_ticks(frames["proc_stat"])
    psi: dict[str, int | None] = {}
    for resource in PSI_RESOURCES:
        body = frames.get(f"psi_{resource}", "")
        for record in PSI_RECORDS:
            key = f"{resource}_{record}"
            try:
                psi[key] = parse_psi_total(body, record)
            except Exception:  # noqa: BLE001 -- one record's absence is local
                psi[key] = None
    clock_ticks: int | None = None
    raw = frames.get("clk_tck", "").strip()
    if raw.isdecimal() and int(raw) > 0:
        clock_ticks = int(raw)
    return RunnerCounters(steal_ticks=aggregate, clock_ticks=clock_ticks, psi=psi)


def _parse_timestamp_identity(raw: str, *, label: str) -> str:
    """A reset identity: the empty string, or an exactly-comparable stamp.

    SQL NULL arrives as the empty text and is a VALID identity (design §3.4):
    two empty boundary identities are equal and permit numeric deltas.
    """
    text = raw.strip()
    if not text:
        return ""
    try:
        datetime.fromisoformat(text)
    except ValueError as exc:
        raise DiagnosticSourceError(f"{label}: unparseable reset identity {raw!r}") from exc
    return text


def parse_postgres_stats_row(text: str) -> PostgresStats:
    """The single ten-column ``psql -F '|'`` row, or a refusal."""
    if not isinstance(text, str):
        raise DiagnosticSourceError(f"psql payload is not a string: {text!r}")
    rows = [line for line in text.split("\n") if line.strip()]
    if len(rows) != 1:
        raise DiagnosticSourceError(f"psql returned {len(rows)} rows, want exactly 1")
    columns = rows[0].rstrip("\r").split("|")
    if len(columns) != 10:
        raise DiagnosticSourceError(f"psql row has {len(columns)} columns, want 10")
    setting = columns[0].strip()
    if setting not in ("on", "off"):
        raise DiagnosticSourceError(f"track_wal_io_timing is {setting!r}")
    counters: list[int] = []
    for index, name in (
        (1, "xact_commit"), (3, "wal_records"), (4, "wal_bytes"),
        (5, "wal_write"), (6, "wal_sync"),
    ):
        raw = columns[index].strip()
        if not raw.isdecimal():
            raise DiagnosticSourceError(f"{name} is not a counter: {columns[index]!r}")
        counters.append(int(raw))
    timings: list[float] = []
    for index, name in ((7, "wal_write_time"), (8, "wal_sync_time")):
        raw = columns[index].strip()
        try:
            value = float(raw)
        except ValueError as exc:
            raise DiagnosticSourceError(f"{name} is not a timing: {columns[index]!r}") from exc
        if not math.isfinite(value) or value < 0.0:
            raise DiagnosticSourceError(f"{name} is not a finite non-negative timing: {value!r}")
        timings.append(value)
    return PostgresStats(
        track_wal_io_timing=setting,
        xact_commit=counters[0],
        db_stats_reset=_parse_timestamp_identity(columns[2], label="pg_stat_database"),
        wal_records=counters[1],
        wal_bytes=counters[2],
        wal_write=counters[3],
        wal_sync=counters[4],
        wal_write_time_ms=timings[0],
        wal_sync_time_ms=timings[1],
        wal_stats_reset=_parse_timestamp_identity(columns[9], label="pg_stat_wal"),
    )


# --------------------------------------------------------------------------
# Source selection and boundary collection
# --------------------------------------------------------------------------


def _select_pod_target(payload: object, component: str, container: str) -> PodTarget | None:
    """Exactly one Running pod whose named container is Ready, or nothing."""
    if not isinstance(payload, dict):
        return None
    items = payload.get("items")
    if not isinstance(items, list):
        return None
    matches = []
    for item in items:
        if not isinstance(item, dict):
            return None
        metadata = item.get("metadata") or {}
        labels = metadata.get("labels") or {}
        if not isinstance(labels, dict):
            return None
        if labels.get(COMPONENT_LABEL) == component:
            matches.append(item)
    if len(matches) != 1:
        return None
    pod = matches[0]
    metadata = pod.get("metadata") or {}
    spec = pod.get("spec") or {}
    status = pod.get("status") or {}
    if status.get("phase") != "Running":
        return None
    statuses = status.get("containerStatuses")
    if not isinstance(statuses, list):
        return None
    selected = [c for c in statuses if isinstance(c, dict) and c.get("name") == container]
    if len(selected) != 1 or selected[0].get("ready") is not True:
        return None
    name = str(metadata.get("name") or "")
    uid = str(metadata.get("uid") or "")
    node_name = str(spec.get("nodeName") or "")
    container_id = str(selected[0].get("containerID") or "")
    if not (name and uid and node_name and container_id):
        return None
    return PodTarget(
        name=name,
        uid=uid,
        node_name=node_name,
        container_id=container_id,
        container_name=container,
    )


def resolve_b1_pod_targets(run: CommandRunner) -> tuple[PodTarget | None, PodTarget | None]:
    """One combined exact-label resolution of both workload targets."""
    text = _stdout_of(_run_command(run, POD_QUERY_ARGV))
    if text is None:
        return None, None
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return None, None
    return (
        _select_pod_target(payload, GATEWAY_COMPONENT, GATEWAY_CONTAINER),
        _select_pod_target(payload, POSTGRES_COMPONENT, POSTGRES_CONTAINER),
    )


def pod_exec_argv(target: PodTarget, script: str) -> list[str]:
    """The exact application-container exec shape (design §3.3)."""
    return [
        "kubectl", "-n", NAMESPACE, "exec", f"pod/{target.name}",
        "-c", target.container_name, "--", "/bin/sh", "-c", script,
    ]


def node_exec_argv(node_name: str, script: str) -> list[str]:
    return ["docker", "exec", node_name, "/bin/sh", "-c", script]


def _read_pod_cgroup(run: CommandRunner, target: PodTarget) -> CgroupCpuReading | None:
    text = _stdout_of(_run_command(run, pod_exec_argv(target, _WORKLOAD_CGROUP_SCRIPT)))
    if text is None:
        return None
    try:
        return parse_cgroup_cpu_frames(parse_frames(text))
    except Exception:  # noqa: BLE001 -- a malformed source is an unavailable
        return None


def _read_postgres_pod(
    run: CommandRunner, target: PodTarget, label: str
) -> tuple[CgroupCpuReading | None, PostgresStats | None]:
    script = _POSTGRES_OPEN_SCRIPT if label == "open" else _POSTGRES_CLOSE_SCRIPT
    text = _stdout_of(_run_command(run, pod_exec_argv(target, script)))
    if text is None:
        return None, None
    try:
        frames = parse_frames(text)
    except Exception:  # noqa: BLE001
        return None, None
    cpu: CgroupCpuReading | None
    try:
        cpu = parse_cgroup_cpu_frames(frames)
    except Exception:  # noqa: BLE001
        cpu = None
    stats: PostgresStats | None
    try:
        stats = parse_postgres_stats_row(frames.get("pg_stats", ""))
    except Exception:  # noqa: BLE001 -- a whole-statement failure is group-wide
        stats = None
    return cpu, stats


def _resolve_kind_node(run: CommandRunner, expected: str) -> str | None:
    """The verified kind route, or nothing. There is no local /proc fallback."""
    text = _stdout_of(_run_command(run, KIND_NODES_ARGV))
    if text is None:
        return None
    names = [line.strip() for line in text.splitlines() if line.strip()]
    if len(names) != 1 or names[0] != expected:
        return None
    return names[0]


def _read_runner_counters(run: CommandRunner, node_name: str) -> RunnerCounters | None:
    text = _stdout_of(_run_command(run, node_exec_argv(node_name, _RUNNER_COUNTER_SCRIPT)))
    if text is None:
        return None
    try:
        return parse_runner_frames(parse_frames(text))
    except Exception:  # noqa: BLE001
        return None


def snapshot_e2e_b1_boundary(
    label: Literal["open", "close"], *, run: CommandRunner
) -> BoundarySnapshot:
    """One boundary reading: at most six sequential commands, no retry."""
    if label not in ("open", "close"):
        raise ValueError(f"not a boundary label: {label!r}")
    gateway, postgres = resolve_b1_pod_targets(run)             # 1
    gateway_cpu = _read_pod_cgroup(run, gateway) if gateway else None       # 2
    postgres_cpu, postgres_stats = (
        _read_postgres_pod(run, postgres, label) if postgres else (None, None)  # 3
    )
    gateway_after, postgres_after = resolve_b1_pod_targets(run)  # 4
    if gateway is None or gateway_after != gateway:
        gateway, gateway_cpu = None, None
    if postgres is None or postgres_after != postgres:
        postgres, postgres_cpu, postgres_stats = None, None, None
    kind_node: str | None = None
    runner: RunnerCounters | None = None
    if gateway is not None and postgres is not None and gateway.node_name == postgres.node_name:
        kind_node = _resolve_kind_node(run, gateway.node_name)   # 5
        if kind_node is not None:
            runner = _read_runner_counters(run, kind_node)       # 6
    return BoundarySnapshot(
        label=str(label),
        gateway=gateway,
        postgres=postgres,
        gateway_cpu=gateway_cpu,
        postgres_cpu=postgres_cpu,
        kind_node=kind_node,
        runner=runner,
        postgres_stats=postgres_stats,
    )


def safe_snapshot_e2e_b1_boundary(
    label: Literal["open", "close"], *, run: CommandRunner
) -> BoundarySnapshot:
    """Fail-soft boundary 2: any fault yields a complete unavailable snapshot.

    ``KeyboardInterrupt`` and ``SystemExit`` are deliberately not caught.
    """
    try:
        return snapshot_e2e_b1_boundary(label, run=run)
    except Exception as exc:  # noqa: BLE001
        _note(f"b1-e2e-diagnostics: {label} boundary unavailable: {type(exc).__name__}")
        return unavailable_snapshot(str(label))


def _note(message: str) -> None:
    """A concise, deliberately noncanonical stderr note."""
    try:
        print(message, file=sys.stderr, flush=True)
    except OSError:
        pass


# --------------------------------------------------------------------------
# Value construction
# --------------------------------------------------------------------------


def _blank_values() -> dict[str, object]:
    values: dict[str, object] = {
        name: B1_E2E_DIAGNOSTIC_UNAVAILABLE for name in B1_E2E_DIAGNOSTIC_FIELDS
    }
    values["schema"] = B1_E2E_DIAGNOSTIC_SCHEMA
    return values


def _set_count(values: dict[str, object], name: str, raw: object) -> None:
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        return
    values[name] = raw


def _leg_vectors_are_coherent(result: object, n: int) -> bool:
    vectors = (
        getattr(result, "pre_dispatch_slip_ms", None),
        getattr(result, "start_lag_ms", None),
        getattr(result, "attempt_duration_ms", None),
    )
    if n <= 0:
        return False
    for vector in vectors:
        if not isinstance(vector, list) or len(vector) != n:
            return False
        if not all(isinstance(v, float) and math.isfinite(v) for v in vector):
            return False
    return True


def _apply_result(values: dict[str, object], result: object) -> None:
    _set_count(values, "offered", getattr(result, "offered", None))
    _set_count(values, "served", getattr(result, "served", None))
    _set_count(values, "errors", getattr(result, "errors", None))
    _set_count(values, "max_in_flight", getattr(result, "max_in_flight", None))
    latencies = getattr(result, "latencies_ms", None)
    p99 = getattr(result, "p99", None)
    if isinstance(p99, float) and math.isfinite(p99) and p99 >= 0.0:
        values["p99_ms"] = p99
    if isinstance(latencies, list) and _leg_vectors_are_coherent(result, len(latencies)):
        split = result.p99_leg_split
        if all(math.isfinite(v) for v in split):
            values["p99_leg_split_ms"] = serialize_leg_triple(split)
        legs = result.leg_p99s
        if all(math.isfinite(v) for v in legs):
            values["leg_p99s_ms"] = serialize_leg_triple(legs)
    codes = getattr(result, "status_codes", None)
    if isinstance(codes, list) and codes and all(isinstance(c, int) for c in codes):
        histogram = serialize_status_histogram(codes)
        if histogram:
            values["status_histogram"] = histogram


def _apply_workload(
    values: dict[str, object],
    prefix: str,
    opening: BoundarySnapshot,
    closing: BoundarySnapshot,
) -> None:
    """The workload group is all-or-nothing: identity plus its three deltas."""
    before_target = getattr(opening, prefix, None)
    after_target = getattr(closing, prefix, None)
    if before_target is None or before_target != after_target:
        return
    before = getattr(opening, f"{prefix}_cpu", None)
    after = getattr(closing, f"{prefix}_cpu", None)
    if before is None or after is None:
        return
    try:
        usage, periods, throttled = cgroup_cpu_delta(before, after, label=prefix)
    except Exception:  # noqa: BLE001 -- a reset is a lost measurement, not a 0
        return
    values[f"{prefix}_pod"] = f"{before_target.name}@{before_target.uid}"
    values[f"{prefix}_cpu_usage_usec"] = usage
    values[f"{prefix}_nr_throttled"] = periods
    values[f"{prefix}_throttled_usec"] = throttled


def _apply_runner(
    values: dict[str, object], opening: BoundarySnapshot, closing: BoundarySnapshot
) -> None:
    route = opening.kind_node
    if not route or route != closing.kind_node:
        return
    values["kind_node"] = route
    before, after = opening.runner, closing.runner
    if before is None or after is None:
        return
    clock_ticks = before.clock_ticks
    if clock_ticks is not None and clock_ticks == after.clock_ticks:
        try:
            ticks = counter_delta(before.steal_ticks, after.steal_ticks, label="runner steal")
            values["runner_steal_usec"] = steal_ticks_to_usec(ticks, clock_ticks=clock_ticks)
        except Exception:  # noqa: BLE001
            pass
    for resource in PSI_RESOURCES:
        for record in PSI_RECORDS:
            key = f"{resource}_{record}"
            start, end = before.psi.get(key), after.psi.get(key)
            if start is None or end is None:
                continue
            try:
                values[f"runner_psi_{key}_usec"] = counter_delta(
                    start, end, label=f"runner psi {key}"
                )
            except Exception:  # noqa: BLE001 -- one resource never erases another
                continue


def _apply_postgres_stats(
    values: dict[str, object], opening: BoundarySnapshot, closing: BoundarySnapshot
) -> None:
    before, after = opening.postgres_stats, closing.postgres_stats
    if before is None or after is None:
        return
    if before.track_wal_io_timing == after.track_wal_io_timing:
        values["pg_track_wal_io_timing"] = before.track_wal_io_timing
    if before.db_stats_reset == after.db_stats_reset:
        try:
            values["pg_xact_commit_delta"] = counter_delta(
                before.xact_commit, after.xact_commit, label="pg xact_commit"
            )
        except Exception:  # noqa: BLE001
            pass
    if before.wal_stats_reset != after.wal_stats_reset:
        return
    for field_name, attribute in (
        ("pg_wal_records_delta", "wal_records"),
        ("pg_wal_bytes_delta", "wal_bytes"),
        ("pg_wal_write_delta", "wal_write"),
        ("pg_wal_sync_delta", "wal_sync"),
    ):
        try:
            values[field_name] = counter_delta(
                getattr(before, attribute), getattr(after, attribute), label=field_name
            )
        except Exception:  # noqa: BLE001
            continue
    if before.track_wal_io_timing != "on" or after.track_wal_io_timing != "on":
        return  # timing off is `unavailable`, never a zero
    for field_name, attribute in (
        ("pg_wal_write_time_ms_delta", "wal_write_time_ms"),
        ("pg_wal_sync_time_ms_delta", "wal_sync_time_ms"),
    ):
        delta = getattr(after, attribute) - getattr(before, attribute)
        if math.isfinite(delta) and delta >= 0.0:
            values[field_name] = delta


def build_e2e_b1_diagnostic_values(
    result: object, opening: BoundarySnapshot, closing: BoundarySnapshot
) -> dict[str, object]:
    """Start from a complete unavailable record; overlay validated readings."""
    values = _blank_values()
    _apply_result(values, result)
    _apply_workload(values, "gateway", opening, closing)
    _apply_workload(values, "postgres", opening, closing)
    _apply_runner(values, opening, closing)
    _apply_postgres_stats(values, opening, closing)
    return values


# --------------------------------------------------------------------------
# Serialization, emission and the fixed artifact
# --------------------------------------------------------------------------


def _render_value(name: str, value: object) -> str:
    if isinstance(value, bool):
        raise ValueError(f"{name}: a boolean is not a diagnostic value")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"{name}: negative counter {value}")
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value) or value < 0.0:
            raise ValueError(f"{name}: not a finite non-negative value: {value!r}")
        return f"{value:.3f}"
    if isinstance(value, str):
        if not value:
            raise ValueError(f"{name}: empty value")
        if value == B1_E2E_DIAGNOSTIC_UNAVAILABLE:
            return B1_E2E_DIAGNOSTIC_UNAVAILABLE
        return quote(value, safe=B1_E2E_DIAGNOSTIC_SAFE_CHARACTERS, encoding="utf-8")
    raise ValueError(f"{name}: unsupported value type {type(value).__name__}")


def serialize_e2e_b1_diagnostics(values: Mapping[str, object]) -> str:
    """One physical line with exactly the 33 declared fields, in order."""
    if tuple(values) != B1_E2E_DIAGNOSTIC_FIELDS:
        raise ValueError(
            f"diagnostic field set/order drift: {tuple(values)!r}"
        )
    rendered = [f"{name}={_render_value(name, values[name])}" for name in B1_E2E_DIAGNOSTIC_FIELDS]
    line = B1_E2E_DIAGNOSTIC_PREFIX + ",".join(rendered)
    if "\n" in line or "\r" in line:
        raise ValueError("the diagnostic record must be one physical line")
    return line


def fallback_e2e_b1_diagnostic_line() -> str:
    """A prevalidated complete line for the emit-time failure path."""
    return B1_E2E_DIAGNOSTIC_PREFIX + ",".join(
        f"{name}=" + (
            str(B1_E2E_DIAGNOSTIC_SCHEMA) if name == "schema"
            else B1_E2E_DIAGNOSTIC_UNAVAILABLE
        )
        for name in B1_E2E_DIAGNOSTIC_FIELDS
    )


def write_e2e_b1_diagnostic_artifact(
    line: str, *, path: Path = B1_E2E_DIAGNOSTIC_ARTIFACT
) -> bool:
    """Overwrite the one fixed file with the canonical bytes plus one newline."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(line + "\n", encoding="utf-8")
        return True
    except OSError:
        return False


class B1E2EDiagnosticSession:
    """The injectable open/close/emit seam the live e2e test wires in."""

    def __init__(self, *, run: CommandRunner = subprocess.run) -> None:
        self._run = run
        self._opening = unavailable_snapshot("open")
        self._closing = unavailable_snapshot("close")

    @property
    def opening(self) -> BoundarySnapshot:
        return self._opening

    @property
    def closing(self) -> BoundarySnapshot:
        return self._closing

    def open(self) -> None:
        self._opening = safe_snapshot_e2e_b1_boundary("open", run=self._run)

    def close(self) -> None:
        self._closing = safe_snapshot_e2e_b1_boundary("close", run=self._run)

    def emit(
        self,
        result: object,
        *,
        stdout: TextIO = sys.stdout,
        artifact_writer: Callable[[str], bool] = write_e2e_b1_diagnostic_artifact,
    ) -> str:
        """Print the record, then write it. Never reaches the B1 oracle."""
        try:
            line = serialize_e2e_b1_diagnostics(
                build_e2e_b1_diagnostic_values(result, self._opening, self._closing)
            )
        except Exception as exc:  # noqa: BLE001 -- fail-soft boundary 3
            _note(f"b1-e2e-diagnostics: record unavailable: {type(exc).__name__}")
            line = fallback_e2e_b1_diagnostic_line()
        try:
            print(line, file=stdout, flush=True)
        except Exception as exc:  # noqa: BLE001
            _note(f"b1-e2e-diagnostics: stdout unavailable: {type(exc).__name__}")
        try:
            artifact_writer(line)
        except Exception as exc:  # noqa: BLE001 -- fail-soft boundary 4
            _note(f"b1-e2e-diagnostics: artifact unavailable: {type(exc).__name__}")
        return line
