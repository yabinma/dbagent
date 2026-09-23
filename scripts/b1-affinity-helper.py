#!/usr/bin/env python3
"""GC-1 FP-GC1-3/4: the closed scheduler-affinity pin for B1's PostgreSQL role.

Why this exists as its own tiny program, and why it is this narrow.

The product-promise topology needs PostgreSQL's whole process tree confined to
a declared CPU set, and the postmaster runs inside a Docker-owned container
that the unprivileged B1 driver may observe but not re-schedule. Changing
another process's affinity needs ``CAP_SYS_NICE``, so exactly one short-lived
helper container gets that capability, runs this file once before warmup, and
is gone before the measured window opens. The driver itself keeps no added
capability and does every pre-run, in-window and post-run reading on its own.

Consequently this program has ONE subcommand and no general interface:

    b1-affinity-helper.py pin-postgres <container-id> <cpu-list> <run-label>

``<run-label>`` is the full ``dbagent.b1.run=<32 hex>`` label of the current
run. The helper refuses to touch a container that does not carry exactly that
label together with ``dbagent.b1.role=postgres``, so a stale container from an
earlier run -- or anything else on the host -- cannot be re-scheduled through
it. There is deliberately no "pin this PID" and no "run this command" door:
with ``CAP_SYS_NICE`` and the host PID namespace, either one would be a
general re-scheduling primitive for every process on the machine.

A pin is all-or-nothing over the live tree. Every live member is narrowed and
then read back; if any live member cannot be updated, or reads back a set
other than the declared one, the helper exits non-zero and the run fails
closed rather than measuring an unknown placement. Members that exit while the
walk is in progress are not live and are skipped -- PostgreSQL forks and reaps
backends continuously, and treating a vanished pid as a failure would make the
helper flaky for a reason that carries no evidence either way.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

RUN_LABEL_KEY = "dbagent.b1.run"
ROLE_LABEL_KEY = "dbagent.b1.role"
POSTGRES_ROLE = "postgres"
RUN_ID_LENGTH = 32
_HEX = frozenset("0123456789abcdef")


class PinError(RuntimeError):
    """The pin could not be completed against the declared placement."""


def parse_run_label(raw: str) -> str:
    """Return the run id from an exact ``dbagent.b1.run=<32 hex>`` label."""
    key, sep, value = raw.partition("=")
    if not sep or key != RUN_LABEL_KEY:
        raise PinError(f"run label must be {RUN_LABEL_KEY}=<run-id>, got {raw!r}")
    if len(value) != RUN_ID_LENGTH or not set(value) <= _HEX:
        raise PinError(f"run id must be {RUN_ID_LENGTH} lowercase hex characters, got {value!r}")
    return value


def parse_cpu_list(raw: str) -> list[int]:
    """Canonical Linux CPU-list syntax (``4-6``, ``0-3,8``) into sorted ids."""
    stripped = raw.strip()
    if not stripped:
        raise PinError("CPU list is empty")
    cpus: set[int] = set()
    for part in stripped.split(","):
        if part != part.strip() or not part:
            raise PinError(f"malformed CPU-list element {part!r}")
        bounds = part.split("-")
        if len(bounds) == 1:
            low_raw = high_raw = bounds[0]
        elif len(bounds) == 2:
            low_raw, high_raw = bounds
        else:
            raise PinError(f"malformed CPU-list range {part!r}")
        if not (low_raw.isdecimal() and high_raw.isdecimal()):
            raise PinError(f"non-decimal CPU id in {part!r}")
        low, high = int(low_raw), int(high_raw)
        if high < low:
            raise PinError(f"inverted CPU-list range {part!r}")
        for cpu in range(low, high + 1):
            if cpu in cpus:
                raise PinError(f"duplicate CPU id {cpu} in {raw!r}")
            cpus.add(cpu)
    return sorted(cpus)


def resolve_postgres_root_pid(container_id: str, run_id: str, *, client=None) -> int:
    """Resolve the container's host PID after checking both required labels."""
    if client is None:  # pragma: no cover - exercised through the injected fake
        import docker

        client = docker.from_env()
    container = client.containers.get(container_id)
    labels = dict(getattr(container, "labels", None) or {})
    if labels.get(RUN_LABEL_KEY) != run_id:
        raise PinError(
            f"container {container_id} carries {RUN_LABEL_KEY}={labels.get(RUN_LABEL_KEY)!r}, "
            f"not the current run {run_id!r}"
        )
    if labels.get(ROLE_LABEL_KEY) != POSTGRES_ROLE:
        raise PinError(
            f"container {container_id} carries {ROLE_LABEL_KEY}="
            f"{labels.get(ROLE_LABEL_KEY)!r}, not {POSTGRES_ROLE!r}"
        )
    attrs = getattr(container, "attrs", None) or {}
    pid = ((attrs.get("State") or {}).get("Pid"))
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise PinError(f"container {container_id} reports no live host pid ({pid!r})")
    return pid


def walk_process_tree(root_pid: int, *, proc_root: Path = Path("/proc")) -> list[int]:
    """Every currently live member of the tree rooted at ``root_pid``.

    Uses ``/proc/<pid>/task/*/children``, which is the only /proc interface
    that enumerates children directly; a process that exits mid-walk simply
    stops contributing.
    """
    seen: list[int] = []
    known: set[int] = set()
    pending = [root_pid]
    while pending:
        pid = pending.pop()
        if pid in known:
            continue
        known.add(pid)
        task_dir = proc_root / str(pid) / "task"
        if not task_dir.is_dir():
            continue  # Exited between enumeration and read; not a live member.
        seen.append(pid)
        try:
            tasks = sorted(task_dir.iterdir())
        except OSError:
            continue
        for task in tasks:
            try:
                children = (task / "children").read_text(encoding="utf-8")
            except OSError:
                continue
            for field in children.split():
                if field.isdecimal():
                    pending.append(int(field))
    return sorted(seen)


def pin_tree(root_pid: int, cpus: list[int], *, proc_root: Path = Path("/proc"),
             set_affinity=os.sched_setaffinity,
             get_affinity=os.sched_getaffinity) -> list[int]:
    """Narrow every live member to ``cpus`` and read each one back."""
    wanted = set(cpus)
    members = walk_process_tree(root_pid, proc_root=proc_root)
    if root_pid not in members:
        raise PinError(f"postgres root pid {root_pid} is not live")
    pinned: list[int] = []
    for pid in members:
        try:
            set_affinity(pid, wanted)
        except ProcessLookupError:
            continue  # Vanished between the walk and the write; not live.
        except OSError as exc:
            raise PinError(f"cannot set affinity of live pid {pid}: {exc}") from exc
        try:
            observed = set(get_affinity(pid))
        except ProcessLookupError:
            continue
        except OSError as exc:
            raise PinError(f"cannot read back affinity of live pid {pid}: {exc}") from exc
        if observed != wanted:
            raise PinError(
                f"pid {pid} read back cpus {sorted(observed)}, declared {sorted(wanted)}"
            )
        pinned.append(pid)
    if not pinned:
        raise PinError(f"no live member of the tree rooted at {root_pid} could be pinned")
    return pinned


def main(argv: list[str] | None = None, *, client=None) -> int:
    parser = argparse.ArgumentParser(
        prog="b1-affinity-helper.py",
        description="Closed scheduler-affinity pin for B1's PostgreSQL role.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    pin = sub.add_parser("pin-postgres", help="pin one labelled PostgreSQL container tree")
    pin.add_argument("container_id")
    pin.add_argument("cpu_list")
    pin.add_argument("run_label")
    ns = parser.parse_args(argv)

    try:
        run_id = parse_run_label(ns.run_label)
        cpus = parse_cpu_list(ns.cpu_list)
        root_pid = resolve_postgres_root_pid(ns.container_id, run_id, client=client)
        pinned = pin_tree(root_pid, cpus)
    except PinError as exc:
        print(f"b1-affinity-helper: {exc}", file=sys.stderr, flush=True)
        return 1
    print(
        f"b1-affinity-helper: pinned {len(pinned)} live postgres pids "
        f"(root {root_pid}) to cpus {ns.cpu_list}",
        flush=True,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
