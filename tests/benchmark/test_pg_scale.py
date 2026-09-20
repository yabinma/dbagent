"""B2 / B10 / B11 scale benchmarks (design.md FP-M6-20/21/22)."""
from __future__ import annotations

import os
import statistics
import time
import uuid
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import pytest
from docker.errors import DockerException
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from rca_common.audit import actor_system, write_audit
from rca_common.db.session import make_engine, make_session_factory
from rca_common.investigation_repo import find_open_by_fingerprint
from rca_common.llmclient.tracestore import LLMCallRecord, PGTraceStore
from services.gateway.tests.b1_reference_profile import (
    counter_delta,
    parse_proc_stat_steal_ticks,
    parse_psi_total,
    steal_ticks_to_usec,
)

# Sibling conftest (pytest prepends tests/benchmark/ on sys.path for this module).
from conftest import load_b11_writer_model

# B11's fifth, canonical diagnostic line (design/slices/b11-host-diagnostics
# §3.2).  The four legacy `B11 ...=` lines keep their exact prefixes and
# meanings; this one is appended, printed once per completed measurement,
# before the unchanged threshold assertion.  Every one of the 21 fields is
# outcome-inert: none can move the threshold, the outcome, the exit code, a
# retry or a skip.  Twenty of them stay reported-only.  The single exception is
# `host_psi_io_full_usec`, which may additionally feed the classification-only
# message branch of an already-red B11 result (design/slices/b11-gate-policy
# §3.2/§3.3); that branch is evaluated only after `rate >= 1000.0` has already
# failed and changes no outcome, exit code or threshold.
B11_DIAGNOSTIC_PREFIX = "B11 diagnostics="
B11_DIAGNOSTIC_UNAVAILABLE = "unavailable"
B11_DIAGNOSTIC_FIELDS = (
    "combined_rate_per_sec",
    "serial_commit_ms",
    "combined_over_single",
    "writer_elapsed_rows",
    "host_steal_usec",
    "host_psi_cpu_some_usec",
    "host_psi_cpu_full_usec",
    "host_psi_io_some_usec",
    "host_psi_io_full_usec",
    "host_psi_memory_some_usec",
    "host_psi_memory_full_usec",
    "storage_pgdata_path",
    "storage_filesystem",
    "storage_mount_source",
    "storage_mount_root",
    "storage_mount_point",
    "storage_device_majmin",
    "storage_block_device",
    "storage_rotational",
    "storage_scheduler",
    "storage_model",
)

# B11 gate-policy slice §3.2/§3.3: the provisional, message-only failure
# classification.  The share is compared unrounded against the reconstructed
# measured window -- never against a table-rounded percentage -- and the label
# is appended only to an assertion message Python builds after the sole gate
# `rate >= 1000.0` has already failed.
B11_IO_FULL_STALL_SHARE = 0.20
B11_IO_FULL_STALL_CLASSIFICATION = "io_full_stall_observed"

# The two closed scripts B11 runs, unprivileged, as OS user `postgres`, inside
# the exact PostgreSQL container the seeded fixture is already running.  Docker
# exec joins that container's mount namespace, which is also the server's own
# view, so the mount record and block attributes describe the storage under
# PostgreSQL's data directory -- never the pytest process's filesystem.  Each
# takes its one container-derived value as a validated positional argument.
B11_CONTAINER_MOUNT_SCRIPT = r"""
pgdata="$1"
case "$pgdata" in
    /*) ;;
    *) exit 2 ;;
esac
resolved="$(readlink -f "$pgdata" 2>/dev/null)" || exit 2
[ -n "$resolved" ] || exit 2
printf 'pgdata_resolved=%s\n' "$resolved"
cat /proc/self/mountinfo
""".strip()

B11_CONTAINER_BLOCK_SCRIPT = r"""
majmin="$1"
case "$majmin" in
    *[!0-9:]*|:*|*:|*:*:*) exit 2 ;;
    [0-9]*:[0-9]*) ;;
    *) exit 2 ;;
esac
device="$(readlink -f "/sys/dev/block/$majmin" 2>/dev/null)" || exit 0
[ -n "$device" ] || exit 0
candidate="$device"
if [ -f "$candidate/partition" ]; then
    candidate="$(dirname "$candidate")" || exit 0
fi
case "$(basename "$candidate")" in
    dm-*)
        # majmin was copied above; replacing $1 here is intentional.
        set -- "$candidate"/slaves/*
        if [ "$#" -eq 1 ] && [ -e "$1" ]; then
            slave="$(readlink -f "$1" 2>/dev/null)" || slave=""
            if [ -n "$slave" ]; then
                candidate="$slave"
                if [ -f "$candidate/partition" ]; then
                    candidate="$(dirname "$candidate")" || exit 0
                fi
            fi
        fi
        ;;
esac
name="$(basename "$candidate")" || exit 0
[ -n "$name" ] && printf 'block_device=%s\n' "$name"
for spec in rotational:queue/rotational scheduler:queue/scheduler model:device/model; do
    key="${spec%%:*}"
    rel="${spec#*:}"
    [ -r "$candidate/$rel" ] || continue
    value="$(cat "$candidate/$rel" 2>/dev/null)" || continue
    [ -n "$value" ] || continue
    printf '%s=%s\n' "$key" "$value"
done
""".strip()


def _p99(samples: list[float]) -> float:
    if not samples:
        return 0.0
    s = sorted(samples)
    idx = max(0, int(round(0.99 * (len(s) - 1))))
    return s[idx]


def test_b2_fingerprint_correlation_p99_under_20ms(scale_pg):
    factory = scale_pg["factory"]
    with factory() as session:
        find_open_by_fingerprint(
            session,
            fingerprint="fp-1",
            platform_key="plat-1",
            correlation_window_seconds=1800,
        )
        session.commit()

    samples_ms: list[float] = []
    for i in range(200):
        fp = f"fp-{i % 5000}"
        plat = f"plat-{i % 10}"
        t0 = time.perf_counter()
        with factory() as session:
            find_open_by_fingerprint(
                session,
                fingerprint=fp,
                platform_key=plat,
                correlation_window_seconds=1800,
            )
            session.commit()
        samples_ms.append((time.perf_counter() - t0) * 1000)
    p99 = _p99(samples_ms)
    assert p99 < 20.0, (
        f"B2 p99={p99:.2f}ms (threshold 20ms); median={statistics.median(samples_ms):.2f}"
    )


def test_b10_partitioned_list_and_filter_p99(scale_pg):
    """Two shapes through real dashboard_api.services.list_investigations."""
    from dashboard_api import services as dash_services

    factory = scale_pg["factory"]
    samples_cursor: list[float] = []
    samples_filter: list[float] = []

    for _ in range(50):
        with factory() as session:
            t0 = time.perf_counter()
            dash_services.list_investigations(session, limit=50)
            samples_cursor.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            dash_services.list_investigations(
                session,
                status=["RESOLVED"],
                platform_key="plat-1",
                category="resource",
                limit=50,
            )
            samples_filter.append((time.perf_counter() - t0) * 1000)
            session.commit()

    p99_c = _p99(samples_cursor)
    p99_f = _p99(samples_filter)
    assert p99_c < 200.0, f"B10 cursor p99={p99_c:.2f}ms"
    assert p99_f < 200.0, f"B10 filter p99={p99_f:.2f}ms"


def _encode_b11_value(value: str) -> str:
    """Percent-encode one free-form diagnostic value (B1-compatible safe set).

    Uppercase hex, and the only unencoded characters are ``A-Z a-z 0-9 - . _ ~
    : +``.  Comma, equals, percent, whitespace, slash and newline are all
    encoded, so no value can forge a field boundary or split the physical line.
    """
    return quote(value, safe="-._~:+")


def _writer_instance_label(entry, index: int) -> str:
    """The percent-encoded label of one writer process instance.

    The safe set here is ``A-Z a-z 0-9 - . _ ~ #`` -- ``:`` and ``+`` are the
    writer entry's own separators, so they are encoded and a future process
    name cannot forge an entry boundary.
    """
    process = entry["process"]
    label = process + "#" + str(index) if process == "ingest-gateway" else process
    return quote(label, safe="#")


def _serialize_writer_elapsed_rows(
    instances, writer_elapsed_rows: list[tuple[float, int] | None]
) -> str:
    """The ``writer_elapsed_rows`` field: seven ordered elapsed/row entries.

    Entries are ``+``-joined, never comma-joined, in the manifest-derived
    ``instances`` order.  Every slot of the preallocated side channel must have
    been replaced by exactly one writer, so an added, omitted or duplicated
    entry raises here rather than being reported.
    """
    assert len(writer_elapsed_rows) == len(instances), (
        f"B11 writer side channel has {len(writer_elapsed_rows)} slots for "
        f"{len(instances)} writer instances"
    )
    entries = []
    labels = []
    for idx in range(len(instances)):
        measured = writer_elapsed_rows[idx]
        assert measured is not None, (
            f"B11 writer instance {idx} recorded no elapsed/row pair"
        )
        elapsed_seconds = measured[0]
        rows = measured[1]
        assert elapsed_seconds >= 0 and rows >= 0, (
            f"B11 writer instance {idx} reported {measured!r}"
        )
        label = _writer_instance_label(instances[idx][0], instances[idx][1])
        rendered = f"{label}:{elapsed_seconds * 1000:.3f}:{rows}"
        assert "," not in rendered, f"B11 writer entry {rendered!r} carries a comma"
        labels.append(label)
        entries.append(rendered)
    assert len(set(labels)) == len(labels), (
        f"B11 writer labels are not unique: {labels}"
    )
    return "+".join(entries)


def _serialize_b11_diagnostics(values: Mapping[str, str]) -> str:
    """The one canonical, comma-safe ``B11 diagnostics=`` line.

    Exactly ``B11_DIAGNOSTIC_FIELDS``, in that order: an extra key, a missing
    key, a reordered mapping, an empty value or a raw comma/newline inside a
    value is a harness defect and raises rather than being printed.
    """
    assert isinstance(values, Mapping), f"B11 diagnostics are not a mapping: {values!r}"
    assert tuple(values) == B11_DIAGNOSTIC_FIELDS, (
        f"B11 diagnostic fields {tuple(values)} != {B11_DIAGNOSTIC_FIELDS}"
    )
    entries = []
    for field in B11_DIAGNOSTIC_FIELDS:
        value = values[field]
        assert isinstance(value, str) and value, (
            f"B11 diagnostic field {field!r} has no value"
        )
        assert "," not in value and "\n" not in value, (
            f"B11 diagnostic field {field!r} value {value!r} is not comma-safe"
        )
        entries.append(f"{field}={value}")
    return B11_DIAGNOSTIC_PREFIX + ",".join(entries)


def _read_b11_host_snapshot(
    *,
    proc_stat_path: Path = Path("/proc/stat"),
    psi_root: Path = Path("/proc/pressure"),
) -> dict[str, int | None]:
    """One boundary sample of the host's steal and PSI counters.

    Parsing is the B1 host-noise slice's shipped pure code, imported directly:
    the kernel aggregate steal row is read in raw ticks (the microsecond
    conversion is exact only after the window's subtraction) and each pressure
    file's exact ``some``/``full`` ``total=`` counter is read separately.  PSI
    averages are never read: they average over time outside this window.  Every
    member fails soft on its own -- a missing CPU ``full`` record does not erase
    CPU ``some``, and a missing memory file does not erase CPU or I/O.
    """
    snapshot: dict[str, int | None] = {
        "steal_ticks": None,
        "psi_cpu_some": None,
        "psi_cpu_full": None,
        "psi_io_some": None,
        "psi_io_full": None,
        "psi_memory_some": None,
        "psi_memory_full": None,
    }
    try:
        snapshot["steal_ticks"] = parse_proc_stat_steal_ticks(
            proc_stat_path.read_text(encoding="utf-8")
        )[0]
    except (OSError, ValueError):
        snapshot["steal_ticks"] = None
    for resource in ("cpu", "io", "memory"):
        try:
            pressure = (psi_root / resource).read_text(encoding="utf-8")
        except (OSError, ValueError):
            continue
        for record in ("some", "full"):
            try:
                snapshot["psi_" + resource + "_" + record] = parse_psi_total(
                    pressure, record
                )
            except (OSError, ValueError):
                snapshot["psi_" + resource + "_" + record] = None
    return snapshot


def _b11_host_delta_values(
    before: Mapping[str, int | None],
    after: Mapping[str, int | None],
    *,
    clock_ticks: int | None,
) -> dict[str, str]:
    """Render the seven host fields from two boundary snapshots.

    Subtraction first, conversion after: ``counter_delta`` refuses a counter
    that decreased inside the window and ``steal_ticks_to_usec`` converts only
    the already-subtracted tick delta.  A reset, a missing end, a malformed
    value or an unreadable source renders that one field ``unavailable`` --
    never zero -- while a real zero delta renders ``0``.  An unusable clock-tick
    rate costs only ``host_steal_usec``; PSI is already microseconds.
    """
    values: dict[str, str] = {}
    for resource in ("cpu", "io", "memory"):
        for record in ("some", "full"):
            key = "psi_" + resource + "_" + record
            start = before.get(key)
            end = after.get(key)
            rendered = B11_DIAGNOSTIC_UNAVAILABLE
            if isinstance(start, int) and isinstance(end, int):
                try:
                    rendered = str(counter_delta(start, end, label=key))
                except (OSError, ValueError):
                    rendered = B11_DIAGNOSTIC_UNAVAILABLE
            values["host_" + key + "_usec"] = rendered
    start = before.get("steal_ticks")
    end = after.get("steal_ticks")
    rendered = B11_DIAGNOSTIC_UNAVAILABLE
    if isinstance(start, int) and isinstance(end, int) and isinstance(clock_ticks, int):
        try:
            rendered = str(
                steal_ticks_to_usec(
                    counter_delta(start, end, label="steal_ticks"),
                    clock_ticks=clock_ticks,
                )
            )
        except (OSError, ValueError):
            rendered = B11_DIAGNOSTIC_UNAVAILABLE
    values["host_steal_usec"] = rendered
    return values


def _decode_b11_mountinfo_field(value: str) -> str:
    """Decode the four escapes the kernel emits in a mountinfo field.

    ``\\040`` space, ``\\011`` tab, ``\\012`` newline, ``\\134`` backslash --
    and nothing else.  Any other backslash sequence did not come from the
    kernel's own encoder, so it is refused rather than passed through as a
    possibly forged path boundary.
    """
    parts = value.split("\\")
    decoded = parts[0]
    for part in parts[1:]:
        if part.startswith("040"):
            decoded = decoded + " " + part[3:]
        elif part.startswith("011"):
            decoded = decoded + "\t" + part[3:]
        elif part.startswith("012"):
            decoded = decoded + "\n" + part[3:]
        elif part.startswith("134"):
            decoded = decoded + "\\" + part[3:]
        else:
            raise ValueError(f"unknown mountinfo escape in {value!r}")
    return decoded


def _parse_b11_container_mount_output(output: str) -> tuple[str, str]:
    """Split the mount exec's framed response into (resolved path, mountinfo).

    The frame proves the mountinfo bytes arrived in the same closed exec
    response as the container-resolved PGDATA path: a missing frame, a
    duplicated frame, content before the frame, a relative/traversing/empty
    resolved path or an empty mount table is refused.
    """
    lines = output.splitlines()
    frame = "pgdata_resolved="
    if not lines or not lines[0].startswith(frame):
        raise ValueError(f"B11 mount exec emitted no leading frame: {output!r}")
    resolved = lines[0][len(frame) :]
    if (
        not resolved
        or not Path(resolved).is_absolute()
        or ".." in resolved.split("/")
    ):
        raise ValueError(f"B11 container-resolved PGDATA path {resolved!r} is unusable")
    rest = lines[1:]
    if not rest:
        raise ValueError("B11 mount exec emitted no mountinfo record")
    for line in rest:
        if line.startswith(frame):
            raise ValueError("B11 mount exec emitted a duplicate frame")
    return resolved, "\n".join(rest)


def _mountinfo_record_for_path(
    mountinfo_output: str, container_path: str
) -> dict[str, str | None]:
    """The target container's own mount record covering ``container_path``.

    Selection is by decoded path components, never by string prefix, so
    ``/var/lib/postgresql/data-old`` cannot cover ``/var/lib/postgresql/data``,
    and the unique longest covering mount point wins.  A container ``/`` record
    is a valid answer here because it was read inside the target container.  A
    malformed record or a tie is unavailable rather than guessed; an individual
    unusable root, source, filesystem or major:minor costs only that field.
    """
    record: dict[str, str | None] = {
        "storage_mount_root": None,
        "storage_mount_point": None,
        "storage_filesystem": None,
        "storage_mount_source": None,
        "storage_device_majmin": None,
    }
    if not Path(container_path).is_absolute():
        return record
    best_pre = None
    best_post = None
    best_depth = -1
    ambiguous = False
    for line in mountinfo_output.splitlines():
        if not line.strip():
            continue
        halves = line.split(" - ", 1)
        if len(halves) != 2:
            return record
        pre = halves[0].split()
        post = halves[1].split()
        if len(pre) < 6 or len(post) < 3:
            return record
        try:
            point = _decode_b11_mountinfo_field(pre[4])
        except ValueError:
            return record
        if not Path(point).is_absolute():
            return record
        try:
            Path(container_path).relative_to(Path(point))
        except ValueError:
            continue
        depth = len([component for component in point.split("/") if component])
        if depth > best_depth:
            best_pre = pre
            best_post = post
            best_depth = depth
            ambiguous = False
        elif depth == best_depth:
            ambiguous = True
    if best_pre is None or best_post is None or ambiguous:
        return record
    try:
        root = _decode_b11_mountinfo_field(best_pre[3])
    except ValueError:
        root = ""
    try:
        point = _decode_b11_mountinfo_field(best_pre[4])
    except ValueError:
        point = ""
    try:
        filesystem = _decode_b11_mountinfo_field(best_post[0])
    except ValueError:
        filesystem = ""
    try:
        source = _decode_b11_mountinfo_field(best_post[1])
    except ValueError:
        source = ""
    record["storage_mount_root"] = root if root else None
    record["storage_mount_point"] = point if point else None
    record["storage_filesystem"] = filesystem if filesystem else None
    record["storage_mount_source"] = source if source else None
    device = best_pre[2].split(":")
    if len(device) == 2 and device[0].isdecimal() and device[1].isdecimal():
        record["storage_device_majmin"] = best_pre[2]
    return record


def _parse_b11_container_block_output(output: str) -> dict[str, str]:
    """The four block members of the block exec's response.

    Only ``block_device``, ``rotational``, ``scheduler`` and ``model`` exist;
    every member starts at ``unavailable`` and an empty, duplicated or invalid
    one costs only itself.  An unknown key cannot come from the closed script,
    so it is a harness-schema defect and raises.
    """
    values = {
        "storage_block_device": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_rotational": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_scheduler": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_model": B11_DIAGNOSTIC_UNAVAILABLE,
    }
    seen = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("=", 1)
        key = parts[0]
        assert len(parts) == 2 and key in (
            "block_device",
            "rotational",
            "scheduler",
            "model",
        ), f"B11 block script emitted an unknown member {line!r}"
        value = parts[1].strip()
        if key in seen:
            values["storage_" + key] = B11_DIAGNOSTIC_UNAVAILABLE
            continue
        seen.append(key)
        if not value:
            continue
        if key == "rotational" and value not in ("0", "1"):
            continue
        values["storage_" + key] = value
    return values


def _exec_b11_container_text(wrapped_container, argv: list[str]) -> str:
    """Run one of the two closed scripts in the target container, unprivileged.

    Only the two argv shapes in the slice design reach Docker, each with its one
    container-derived value already validated as a positional argument; every
    other argv is a harness defect and raises before the daemon is touched.  A
    nonzero exit or a non-bytes response is an environmental reading, not a
    defect, so it raises ``ValueError`` and the caller renders the affected
    fields unavailable.
    """
    assert isinstance(argv, list) and len(argv) == 5, f"B11 exec argv {argv!r}"
    assert argv[0] == "/bin/sh" and argv[1] == "-c", f"B11 exec argv {argv!r}"
    if argv[3] == "b11-mount":
        assert argv[2] == B11_CONTAINER_MOUNT_SCRIPT, "B11 mount script replaced"
        lines = argv[4].splitlines()
        assert (
            len(lines) == 1
            and lines[0] == argv[4]
            and Path(argv[4]).is_absolute()
            and ".." not in argv[4].split("/")
        ), f"B11 mount exec PGDATA argument {argv[4]!r} is not a validated path"
    else:
        assert argv[3] == "b11-block", f"B11 exec argv {argv!r}"
        assert argv[2] == B11_CONTAINER_BLOCK_SCRIPT, "B11 block script replaced"
        device = argv[4].split(":")
        assert (
            len(device) == 2 and device[0].isdecimal() and device[1].isdecimal()
        ), f"B11 block exec device argument {argv[4]!r} is not major:minor"
    exit_code, output = wrapped_container.exec_run(
        argv,
        stdout=True,
        stderr=False,
        stdin=False,
        tty=False,
        privileged=False,
        user="postgres",
        detach=False,
        stream=False,
        socket=False,
        environment=None,
        workdir=None,
        demux=False,
    )
    if exit_code != 0:
        raise ValueError(f"B11 container exec {argv[3]!r} exited {exit_code!r}")
    if not isinstance(output, bytes):
        raise ValueError(f"B11 container exec {argv[3]!r} returned {output!r}")
    return output.decode("utf-8")


def _read_b11_container_block_identity(
    wrapped_container, device_majmin: str
) -> dict[str, str]:
    """The exposed block attributes for one device, from the same container."""
    values = {
        "storage_block_device": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_rotational": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_scheduler": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_model": B11_DIAGNOSTIC_UNAVAILABLE,
    }
    try:
        output = _exec_b11_container_text(
            wrapped_container,
            [
                "/bin/sh",
                "-c",
                B11_CONTAINER_BLOCK_SCRIPT,
                "b11-block",
                device_majmin,
            ],
        )
    except (ValueError, DockerException):
        return values
    return _parse_b11_container_block_output(output)


def _read_b11_storage_identity(container, pgdata_path: str) -> dict[str, str]:
    """The storage identity PostgreSQL itself sees under its data directory.

    Everything is read by unprivileged exec in the exact running PostgreSQL
    container: the pytest process's ``/``, ``/proc`` and ``/sys``, the Docker
    daemon's own mount view and any host backing path are never candidates and
    are never substituted.  Docker volume class and host path are not claimed at
    all -- what the container does not expose stays ``unavailable``.
    """
    values = {
        "storage_pgdata_path": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_filesystem": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_mount_source": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_mount_root": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_mount_point": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_device_majmin": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_block_device": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_rotational": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_scheduler": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_model": B11_DIAGNOSTIC_UNAVAILABLE,
    }
    if not pgdata_path or pgdata_path == B11_DIAGNOSTIC_UNAVAILABLE:
        return values
    values["storage_pgdata_path"] = _encode_b11_value(pgdata_path)
    lines = pgdata_path.splitlines()
    if (
        len(lines) != 1
        or lines[0] != pgdata_path
        or not Path(pgdata_path).is_absolute()
        or ".." in pgdata_path.split("/")
    ):
        return values
    try:
        wrapped_container = container.get_wrapped_container()
        resolved, mountinfo_output = _parse_b11_container_mount_output(
            _exec_b11_container_text(
                wrapped_container,
                [
                    "/bin/sh",
                    "-c",
                    B11_CONTAINER_MOUNT_SCRIPT,
                    "b11-mount",
                    pgdata_path,
                ],
            )
        )
    except (ValueError, DockerException):
        return values
    record = _mountinfo_record_for_path(mountinfo_output, resolved)
    for key in (
        "storage_mount_root",
        "storage_mount_point",
        "storage_filesystem",
        "storage_mount_source",
    ):
        member = record.get(key)
        if member:
            values[key] = _encode_b11_value(member)
    device_majmin = record.get("storage_device_majmin")
    if not device_majmin:
        return values
    values["storage_device_majmin"] = device_majmin
    if int(device_majmin.split(":")[0]) == 0:
        return values
    block = _read_b11_container_block_identity(wrapped_container, device_majmin)
    for key in (
        "storage_block_device",
        "storage_rotational",
        "storage_scheduler",
        "storage_model",
    ):
        member = block.get(key)
        if member and member != B11_DIAGNOSTIC_UNAVAILABLE:
            values[key] = _encode_b11_value(member)
    return values


def _b11_failure_classification(
    combined_rate_per_sec: float,
    committed_rows: int,
    host_psi_io_full_usec: str,
) -> str:
    """Name the observed I/O-full symptom of an already-failed B11 measurement.

    Pure, lazily reached and outcome-inert: Python evaluates an ``assert``
    message only after its condition is already false, so this can never run on
    a pass.  It returns the empty string for a passing or non-positive rate, a
    non-positive row count and an unavailable counter, and otherwise
    reconstructs the measured window algebraically from the asserted rate and
    the fixed committed row count -- there is no second clock and no reread of
    the timed window.  The label names a symptom, not a mechanism, and the gate
    stays ``rate >= 1000.0``: a classified run is the same required-green
    failure with a longer message (design/slices/b11-gate-policy §3.2/§3.3).
    """
    if combined_rate_per_sec >= 1000.0 or combined_rate_per_sec <= 0:
        return ""
    if committed_rows <= 0 or host_psi_io_full_usec == B11_DIAGNOSTIC_UNAVAILABLE:
        return ""
    measured_window_usec = committed_rows / combined_rate_per_sec * 1_000_000
    io_full_share = int(host_psi_io_full_usec) / measured_window_usec
    if io_full_share < B11_IO_FULL_STALL_SHARE:
        return ""
    return (
        f"; B11 failure_classification={B11_IO_FULL_STALL_CLASSIFICATION}; "
        "B11 classification_scope=symptom_only_not_cause; "
        f"B11 host_psi_io_full_share={io_full_share:.3f}; "
        "B11 gate_outcome=red"
    )


def test_b11_audit_llm_insert_throughput(scale_pg):
    """Combined audit + llm_calls insert rate under durable Postgres.

    Writer count and mapping come from B11's structured concurrency_model
    (design.md §11.1.3 / FP-M6-22 / FP-IG-21): four writer *services*, seven
    process *instances* in the default deployment, each with an independent
    make_engine-default pool. Threads proxy process instances.

    The fifth, canonical `B11 diagnostics=` line is outcome-inert: it is
    printed on a pass and before a threshold failure and changes no knob, no
    threshold and no outcome (design/slices/b11-host-diagnostics §3.6).  Its
    one message-only use is `host_psi_io_full_usec`, read after the bar has
    already failed so the failure text can name the observed I/O-full symptom
    (design/slices/b11-gate-policy §3.2); the gate stays `rate >= 1000.0` and
    no reading of any kind can produce a pass, a skip or a retry.
    """
    dsn = scale_pg["dsn"]
    writers = load_b11_writer_model()
    instances = [
        (entry, i)
        for entry in writers
        for i in range(entry["processes"])
    ]
    n_iters = 800
    now = datetime.now(timezone.utc)

    # Storage identity first: PostgreSQL's own effective data_directory, then
    # the mount record and exposed block attributes at that path read *inside
    # the running server's own container*.  Both execs and all parsing finish
    # before any B11 engine, connection or row warmup, so no diagnostic I/O is
    # adjacent to the timed window (§3.4/§3.5).
    try:
        with scale_pg["engine"].connect() as conn:
            pgdata_row = conn.execute(
                text("SELECT current_setting('data_directory')")
            ).one()
        pgdata_path = pgdata_row[0]
    except SQLAlchemyError:
        pgdata_path = B11_DIAGNOSTIC_UNAVAILABLE
    storage_values = _read_b11_storage_identity(scale_pg["container"], pgdata_path)
    writer_elapsed_rows = [None] * len(instances)

    # One independent engine per process instance at make_engine defaults.
    # Built and warmed *outside* the timed window so we measure insert rate only.
    engines = []
    factories = []
    stores = []
    for _ in instances:
        eng = make_engine(dsn)
        fac = make_session_factory(eng)
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        engines.append(eng)
        factories.append(fac)
        stores.append(PGTraceStore(session_factory=fac))

    def _run_writer(idx: int) -> int:
        """Return rows committed by instances[idx].

        One commit per row — production shape for write_audit / insert_llm_call.
        Session is held open across commits (same connection from the pool),
        matching a long-lived process rather than open/close per row.

        The two boundary clock reads and the one distinct-index side-channel
        assignment are the only added writer-path operations; both lie outside
        the counted row loop, and the recorded row count is the same bare
        counter this function returns.
        """
        factory = factories[idx]
        store = stores[idx]
        process = instances[idx][0]["process"]
        rows = 0
        writer_t0 = time.perf_counter()
        with factory() as session:
            for i in range(n_iters):
                if process == "temporal-worker" and i % 2 == 1:
                    store.insert_llm_call(
                        LLMCallRecord(
                            call_id=uuid.uuid4(),
                            investigation_id=None,
                            round=None,
                            agent_role="rca",
                            model="mock",
                            provider=None,
                            prompt_ref="p",
                            response_ref="r",
                            input_tokens=1,
                            output_tokens=1,
                            cost_usd=0.0,
                            latency_ms=1,
                            error=None,
                            created_at=now,
                        )
                    )
                else:
                    write_audit(
                        session,
                        action="event_received",
                        actor=actor_system(),
                        detail={"i": i, "writer": process},
                    )
                    session.commit()
                rows += 1
        writer_elapsed_rows[idx] = (time.perf_counter() - writer_t0, rows)
        return rows

    writer_map = ",".join(
        f"{(entry['process'] + '#' + str(i)) if entry['process'] == 'ingest-gateway' else entry['process']}"
        f":{'+'.join(entry['tables'])}"
        for entry, i in instances
    )

    def _warmup(idx: int) -> None:
        factory = factories[idx]
        process = instances[idx][0]["process"]
        with factory() as session:
            for i in range(50):
                write_audit(
                    session,
                    action="event_received",
                    actor=actor_system(),
                    detail={"i": i, "writer": process, "warmup": True},
                )
                session.commit()

    # Pool created and warmed outside the timed window.
    pool = ThreadPoolExecutor(max_workers=len(instances))
    try:
        list(pool.map(_warmup, range(len(instances))))
        try:
            clock_ticks = os.sysconf("SC_CLK_TCK")
        except (OSError, ValueError):
            clock_ticks = None
        host_before = _read_b11_host_snapshot()
        t0 = time.perf_counter()
        committed = list(pool.map(_run_writer, range(len(instances))))
        elapsed = time.perf_counter() - t0
        host_after = _read_b11_host_snapshot()
    finally:
        pool.shutdown(wait=True)
    total_rows = sum(committed)
    rate = total_rows / elapsed if elapsed > 0 else 0.0
    host_values = _b11_host_delta_values(
        host_before, host_after, clock_ticks=clock_ticks
    )

    # Single-writer diagnostic on a pre-warmed engine (printed; not the bar).
    t_sw = time.perf_counter()
    sw_rows = 0
    with factories[0]() as session:
        for i in range(100):
            write_audit(
                session,
                action="event_received",
                actor=actor_system(),
                detail={"i": i, "writer": "single"},
            )
            session.commit()
            sw_rows += 1
    sw_elapsed = time.perf_counter() - t_sw
    single_writer_rate = sw_rows / sw_elapsed if sw_elapsed > 0 else 0.0
    serial_commit_ms = 1000.0 / single_writer_rate if single_writer_rate > 0 else 0.0
    combined_over_single = rate / single_writer_rate if single_writer_rate > 0 else 0.0
    env_line = (
        f"B11 env=cpus={os.cpu_count()},"
        f"serial_commit_ms={serial_commit_ms:.3f},"
        f"combined_over_single={combined_over_single:.2f}"
    )
    diagnostic_values = {
        "combined_rate_per_sec": f"{rate:.1f}",
        "serial_commit_ms": f"{serial_commit_ms:.3f}",
        "combined_over_single": f"{combined_over_single:.2f}",
        "writer_elapsed_rows": _serialize_writer_elapsed_rows(
            instances, writer_elapsed_rows
        ),
        "host_steal_usec": host_values["host_steal_usec"],
        "host_psi_cpu_some_usec": host_values["host_psi_cpu_some_usec"],
        "host_psi_cpu_full_usec": host_values["host_psi_cpu_full_usec"],
        "host_psi_io_some_usec": host_values["host_psi_io_some_usec"],
        "host_psi_io_full_usec": host_values["host_psi_io_full_usec"],
        "host_psi_memory_some_usec": host_values["host_psi_memory_some_usec"],
        "host_psi_memory_full_usec": host_values["host_psi_memory_full_usec"],
        "storage_pgdata_path": storage_values["storage_pgdata_path"],
        "storage_filesystem": storage_values["storage_filesystem"],
        "storage_mount_source": storage_values["storage_mount_source"],
        "storage_mount_root": storage_values["storage_mount_root"],
        "storage_mount_point": storage_values["storage_mount_point"],
        "storage_device_majmin": storage_values["storage_device_majmin"],
        "storage_block_device": storage_values["storage_block_device"],
        "storage_rotational": storage_values["storage_rotational"],
        "storage_scheduler": storage_values["storage_scheduler"],
        "storage_model": storage_values["storage_model"],
    }
    print(f"B11 writers={len(instances)}")
    print(f"B11 writer_map={writer_map}")
    print(f"B11 single_writer_rate={single_writer_rate:.1f}/s")
    print(env_line)
    print(_serialize_b11_diagnostics(diagnostic_values))
    assert rate >= 1000.0, (
        f"B11 combined insert rate={rate:.1f}/s (threshold 1000); "
        f"B11 writers={len(instances)}; B11 writer_map={writer_map}; "
        f"B11 single_writer_rate={single_writer_rate:.1f}/s; {env_line}"
        + _b11_failure_classification(
            rate,
            len(instances) * n_iters,
            host_values["host_psi_io_full_usec"],
        )
    )


def test_b11_failure_classification_names_only_high_io_full_reds():
    """FP-B11GP-2: only an unrounded same-window I/O-full share >= 20% is named.

    The literals are exact rather than illustrative: 5600 rows (the seven
    manifest-derived instances times the fixed 800 timed rows) at 700.0/s
    reconstruct an 8 000 000 usec window, so 1 600 000 usec is exactly 20.000%
    and 1 599 999 usec is 19.9999875%.  Both sit either side of the boundary in
    binary64 without rounding, which is the point: the comparison happens on
    raw counters and only the rendered share is rounded, to three decimals.

    Nothing here can turn a red green.  The helper only ever returns text, and
    the low-stall regression case -- a real product slowdown on a quiet host --
    must stay unclassified so it is never explained away.
    """
    classified = _b11_failure_classification(700.0, 5600, "1600000")
    assert classified == (
        "; B11 failure_classification=io_full_stall_observed; "
        "B11 classification_scope=symptom_only_not_cause; "
        "B11 host_psi_io_full_share=0.200; "
        "B11 gate_outcome=red"
    ), classified
    assert "classification_scope=symptom_only_not_cause" in classified, classified
    assert "gate_outcome=red" in classified, classified

    # One counter below the boundary: 19.9999875%, unrounded, is not named.
    assert _b11_failure_classification(700.0, 5600, "1599999") == "", "boundary"

    # Three decimals, rendered only after the unrounded comparison.
    assert _b11_failure_classification(700.0, 5600, "2080000") == (
        "; B11 failure_classification=io_full_stall_observed; "
        "B11 classification_scope=symptom_only_not_cause; "
        "B11 host_psi_io_full_share=0.260; "
        "B11 gate_outcome=red"
    ), "0.260"

    # A real regression on a quiet host: zero stall stays an ordinary red.
    assert _b11_failure_classification(700.0, 5600, "0") == "", "zero"

    # `unavailable` never becomes zero and never becomes a classification.
    assert _b11_failure_classification(700.0, 5600, "unavailable") == "", "unavailable"
    assert (
        _b11_failure_classification(700.0, 5600, B11_DIAGNOSTIC_UNAVAILABLE) == ""
    ), "unavailable constant"

    # No reconstructable window: no label, and the assertion still fails.
    assert _b11_failure_classification(0.0, 5600, "1600000") == "", "zero rate"
    assert _b11_failure_classification(-1.0, 5600, "1600000") == "", "negative rate"
    assert _b11_failure_classification(700.0, 0, "1600000") == "", "zero rows"
    assert _b11_failure_classification(700.0, -5600, "1600000") == "", "negative rows"

    # A passing rate is never classified, however high the stall: the message
    # is not even built, and the helper refuses anyway.
    assert _b11_failure_classification(1000.0, 5600, "1600000") == "", "at threshold"
    assert _b11_failure_classification(1735.0, 5600, "99999999") == "", "fast"

    # The two pinned module constants are the only tunables, and neither is
    # reachable from a runtime value.
    assert B11_IO_FULL_STALL_SHARE == 0.20, B11_IO_FULL_STALL_SHARE
    assert B11_IO_FULL_STALL_CLASSIFICATION == "io_full_stall_observed", (
        B11_IO_FULL_STALL_CLASSIFICATION
    )


def test_b11_host_parser_reuse_is_direct():
    """FP-B11HD-2: the four host-counter helpers are B1's shipped pure code.

    Every imported binding is exercised here against fixed inputs; the
    independent source guard requires their literal
    `services.gateway.tests.b1_reference_profile` import provenance, so a copy,
    a redefinition or a dynamic load is rejected there rather than drifting.
    """
    aggregate, per_cpu = parse_proc_stat_steal_ticks(
        "cpu  10 0 20 30 0 0 0 800 0 0\n"
        "cpu0 5 0 10 15 0 0 0 500 0 0\n"
        "cpu1 5 0 10 15 0 0 0 300 0 0\n"
        "intr 1 2 3\n"
    )
    assert aggregate == 800, aggregate
    assert per_cpu == {0: 500, 1: 300}, per_cpu
    pressure = (
        "some avg10=1.00 avg60=2.00 avg300=3.00 total=1234\n"
        "full avg10=4.00 avg60=5.00 avg300=6.00 total=56\n"
    )
    assert parse_psi_total(pressure, "some") == 1234
    assert parse_psi_total(pressure, "full") == 56
    assert counter_delta(10, 25, label="steal") == 15
    assert steal_ticks_to_usec(15, clock_ticks=100) == 150000


def test_b11_host_diagnostics_read_declared_sources(tmp_path):
    """FP-B11HD-2: exact steal and PSI deltas from the declared paths.

    Deterministic files prove the aggregate steal row (not the per-CPU sum),
    both PSI records of all three resources, tick-first subtraction through
    `os.sysconf("SC_CLK_TCK")`'s rate, a numeric zero delta, and field-local
    failure: a reset, a malformed value, a missing record, a missing file or an
    unusable clock rate costs only the member it belongs to.
    """
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    psi_root = tmp_path / "pressure"
    psi_root.mkdir()
    partial_root = tmp_path / "pressure-partial"
    partial_root.mkdir()
    stat_path = proc_root / "stat"

    def _stat(steal):
        return (
            f"cpu  10 0 20 30 0 0 0 {steal} 0 0\n"
            f"cpu0 5 0 10 15 0 0 0 {steal} 0 0\n"
        )

    def _psi(some_total, full_total, average):
        return (
            f"some avg10={average} avg60=0.00 avg300=0.00 total={some_total}\n"
            f"full avg10={average} avg60=0.00 avg300=0.00 total={full_total}\n"
        )

    def _snapshot(stat_body, cpu_body, io_body, memory_body):
        stat_path.write_text(stat_body, encoding="utf-8")
        (psi_root / "cpu").write_text(cpu_body, encoding="utf-8")
        (psi_root / "io").write_text(io_body, encoding="utf-8")
        (psi_root / "memory").write_text(memory_body, encoding="utf-8")
        return _read_b11_host_snapshot(proc_stat_path=stat_path, psi_root=psi_root)

    before = _snapshot(
        _stat(1000), _psi(100, 10, "9.99"), _psi(200, 20, "9.99"), _psi(300, 30, "9.99")
    )
    after = _snapshot(
        _stat(1007), _psi(123, 10, "0.00"), _psi(255, 26, "0.00"), _psi(300, 37, "0.00")
    )
    assert before["steal_ticks"] == 1000, before
    assert before["psi_cpu_some"] == 100, before
    values = _b11_host_delta_values(before, after, clock_ticks=100)
    # 7 ticks at 100 Hz = 70_000 us: subtraction first, conversion after.
    assert values["host_steal_usec"] == "70000", values
    assert values["host_psi_cpu_some_usec"] == "23", values
    assert values["host_psi_cpu_full_usec"] == "0", values
    assert values["host_psi_io_some_usec"] == "55", values
    assert values["host_psi_io_full_usec"] == "6", values
    assert values["host_psi_memory_some_usec"] == "0", values
    assert values["host_psi_memory_full_usec"] == "7", values
    assert tuple(sorted(values)) == (
        "host_psi_cpu_full_usec",
        "host_psi_cpu_some_usec",
        "host_psi_io_full_usec",
        "host_psi_io_some_usec",
        "host_psi_memory_full_usec",
        "host_psi_memory_some_usec",
        "host_steal_usec",
    ), tuple(sorted(values))

    # A different tick rate changes only the steal conversion.
    assert _b11_host_delta_values(before, after, clock_ticks=1000)[
        "host_steal_usec"
    ] == "7000"
    # An unusable tick rate costs the steal field alone.
    no_rate = _b11_host_delta_values(before, after, clock_ticks=None)
    assert no_rate["host_steal_usec"] == B11_DIAGNOSTIC_UNAVAILABLE, no_rate
    assert no_rate["host_psi_cpu_some_usec"] == "23", no_rate

    # A counter that reset inside the window is unavailable, never zero.
    reset = _b11_host_delta_values(after, before, clock_ticks=100)
    assert reset["host_steal_usec"] == B11_DIAGNOSTIC_UNAVAILABLE, reset
    assert reset["host_psi_cpu_some_usec"] == B11_DIAGNOSTIC_UNAVAILABLE, reset
    assert reset["host_psi_memory_some_usec"] == "0", reset

    # A missing `full` record leaves `some` intact.
    half = _snapshot(
        _stat(1007),
        "some avg10=0.00 avg60=0.00 avg300=0.00 total=123\n",
        _psi(255, 26, "0.00"),
        _psi(300, 37, "0.00"),
    )
    assert half["psi_cpu_some"] == 123, half
    assert half["psi_cpu_full"] is None, half
    half_values = _b11_host_delta_values(before, half, clock_ticks=100)
    assert half_values["host_psi_cpu_some_usec"] == "23", half_values
    assert (
        half_values["host_psi_cpu_full_usec"] == B11_DIAGNOSTIC_UNAVAILABLE
    ), half_values

    # A malformed steal field costs steal alone; the PSI members survive.
    malformed = _snapshot(
        "cpu  10 0 20 30 0 0 0 seven 0 0\ncpu0 1 0 1 1 0 0 0 1 0 0\n",
        _psi(123, 10, "0.00"),
        _psi(255, 26, "0.00"),
        _psi(300, 37, "0.00"),
    )
    assert malformed["steal_ticks"] is None, malformed
    malformed_values = _b11_host_delta_values(before, malformed, clock_ticks=100)
    assert (
        malformed_values["host_steal_usec"] == B11_DIAGNOSTIC_UNAVAILABLE
    ), malformed_values
    assert malformed_values["host_psi_io_some_usec"] == "55", malformed_values

    # A missing pressure file costs only its own resource.
    (partial_root / "cpu").write_text(_psi(123, 10, "0.00"), encoding="utf-8")
    partial = _read_b11_host_snapshot(proc_stat_path=stat_path, psi_root=partial_root)
    assert partial["psi_cpu_some"] == 123, partial
    assert partial["psi_io_some"] is None, partial
    assert partial["psi_memory_full"] is None, partial

    # A missing /proc/stat costs only steal.
    absent = _read_b11_host_snapshot(
        proc_stat_path=proc_root / "absent", psi_root=psi_root
    )
    assert absent["steal_ticks"] is None, absent
    assert absent["psi_cpu_some"] == 123, absent


def test_b11_host_reader_observes_real_proc_stat():
    """FP-B11HD-2: the default reader reads this host's real /proc.

    Container-free, and deliberately assertion-free about the values: what is
    required is that a readable source produces a reading, so an implementation
    whose synthetic fixtures pass while its live reader always reports
    `unavailable` is red here.
    """
    before = _read_b11_host_snapshot()
    after = _read_b11_host_snapshot()
    values = _b11_host_delta_values(before, after, clock_ticks=100)
    assert values["host_steal_usec"].isdecimal(), values
    for resource in ("cpu", "io", "memory"):
        try:
            Path("/proc/pressure/" + resource).read_text(encoding="utf-8")
        except OSError:
            continue
        assert values[
            "host_psi_" + resource + "_some_usec"
        ].isdecimal(), values


def test_b11_storage_identity_reads_target_postgres_container():
    """FP-B11HD-3: the mount and block identity at PostgreSQL's own PGDATA.

    The fake is the exact target container: its mountinfo carries a decoy
    `/workspace` mount, an always-covering `/` record and a sibling
    `...-old` mount, so a first-record choice, a string-prefix match or a
    substituted test-process mount table cannot produce these values.  The two
    unprivileged exec calls are asserted argument by argument.
    """
    calls = []
    mount_bytes = (
        b"pgdata_resolved=/var/lib/postgresql/data/pgdata\n"
        b"23 1 0:24 / / rw,relatime - overlay overlay rw\n"
        b"27 23 0:26 / /workspace rw,relatime - fuse.fuse-overlayfs fuse-overlayfs rw\n"
        b"41 23 259:3 /volumes/pg\\040data /var/lib/postgresql/data rw shared:1 - ext4 /dev/nvme0n1p3 rw\n"
        b"44 23 259:3 /volumes/old /var/lib/postgresql/data-old rw - ext4 /dev/nvme0n1p3 rw\n"
    )
    block_bytes = (
        b"block_device=nvme0n1\n"
        b"rotational=0\n"
        b"scheduler=[none] mq-deadline\n"
        b"model=Amazon Elastic Block Store\n"
    )

    class _Wrapped:
        def exec_run(
            self,
            cmd,
            stdout,
            stderr,
            stdin,
            tty,
            privileged,
            user,
            detach,
            stream,
            socket,
            environment,
            workdir,
            demux,
        ):
            calls.append(
                (
                    cmd,
                    stdout,
                    stderr,
                    stdin,
                    tty,
                    privileged,
                    user,
                    detach,
                    stream,
                    socket,
                    environment,
                    workdir,
                    demux,
                )
            )
            if cmd[3] == "b11-mount":
                return (0, mount_bytes)
            return (0, block_bytes)

    class _Container:
        def get_wrapped_container(self):
            return _Wrapped()

    values = _read_b11_storage_identity(
        _Container(), "/var/lib/postgresql/data/pgdata"
    )
    assert len(calls) == 2, calls
    assert calls[0][0] == [
        "/bin/sh",
        "-c",
        B11_CONTAINER_MOUNT_SCRIPT,
        "b11-mount",
        "/var/lib/postgresql/data/pgdata",
    ], calls[0][0]
    assert calls[0][1:] == (
        True,
        False,
        False,
        False,
        False,
        "postgres",
        False,
        False,
        False,
        None,
        None,
        False,
    ), calls[0][1:]
    assert calls[1][0] == [
        "/bin/sh",
        "-c",
        B11_CONTAINER_BLOCK_SCRIPT,
        "b11-block",
        "259:3",
    ], calls[1][0]
    assert calls[1][1:] == calls[0][1:], calls[1][1:]
    assert values["storage_pgdata_path"] == "%2Fvar%2Flib%2Fpostgresql%2Fdata%2Fpgdata"
    assert values["storage_filesystem"] == "ext4", values
    assert values["storage_mount_source"] == "%2Fdev%2Fnvme0n1p3", values
    assert values["storage_mount_root"] == "%2Fvolumes%2Fpg%20data", values
    assert values["storage_mount_point"] == "%2Fvar%2Flib%2Fpostgresql%2Fdata", values
    assert values["storage_device_majmin"] == "259:3", values
    assert values["storage_block_device"] == "nvme0n1", values
    assert values["storage_rotational"] == "0", values
    assert values["storage_scheduler"] == "%5Bnone%5D%20mq-deadline", values
    assert values["storage_model"] == "Amazon%20Elastic%20Block%20Store", values

    # A symlinked server path: selection follows the container-resolved path in
    # the same framed response, while the reported path stays the server's own.
    linked_calls = []

    class _LinkedWrapped:
        def exec_run(
            self,
            cmd,
            stdout,
            stderr,
            stdin,
            tty,
            privileged,
            user,
            detach,
            stream,
            socket,
            environment,
            workdir,
            demux,
        ):
            linked_calls.append(cmd)
            if cmd[3] == "b11-mount":
                return (0, mount_bytes)
            return (0, block_bytes)

    class _LinkedContainer:
        def get_wrapped_container(self):
            return _LinkedWrapped()

    linked = _read_b11_storage_identity(_LinkedContainer(), "/srv/pgdata-link")
    assert linked_calls[0][4] == "/srv/pgdata-link", linked_calls[0]
    assert linked["storage_pgdata_path"] == "%2Fsrv%2Fpgdata-link", linked
    assert linked["storage_mount_point"] == "%2Fvar%2Flib%2Fpostgresql%2Fdata", linked
    assert linked["storage_block_device"] == "nvme0n1", linked


def test_b11_storage_identity_fails_soft_without_substituting_another_mount():
    """FP-B11HD-3/5: every unexposed member is unavailable, nothing is invented.

    Overlay2, rootless fuse, a zero major, malformed and ambiguous mount
    points, a failed exec, absent or masked sysfs, partial and invalid block
    output, the device-mapper shapes and a Docker API failure each preserve
    every independently valid reading and substitute nothing.
    """
    pgdata = "/var/lib/postgresql/data"

    def _fake(responses, calls):
        class _Wrapped:
            def exec_run(
                self,
                cmd,
                stdout,
                stderr,
                stdin,
                tty,
                privileged,
                user,
                detach,
                stream,
                socket,
                environment,
                workdir,
                demux,
            ):
                calls.append(cmd)
                return responses[len(calls) - 1]

        class _Container:
            def get_wrapped_container(self):
                return _Wrapped()

        return _Container()

    # (a) overlay2 root: a valid virtual filesystem, a zero major, no block exec.
    calls = []
    overlay = _read_b11_storage_identity(
        _fake(
            [
                (
                    0,
                    b"pgdata_resolved=/var/lib/postgresql/data\n"
                    b"23 1 0:24 / / rw,relatime - overlay overlay rw\n",
                )
            ],
            calls,
        ),
        pgdata,
    )
    assert len(calls) == 1, calls
    assert overlay["storage_filesystem"] == "overlay", overlay
    assert overlay["storage_mount_source"] == "overlay", overlay
    assert overlay["storage_mount_root"] == "%2F", overlay
    assert overlay["storage_mount_point"] == "%2F", overlay
    assert overlay["storage_device_majmin"] == "0:24", overlay
    assert overlay["storage_block_device"] == B11_DIAGNOSTIC_UNAVAILABLE, overlay
    assert overlay["storage_rotational"] == B11_DIAGNOSTIC_UNAVAILABLE, overlay

    # (b) rootless fuse-overlayfs.
    calls = []
    rootless = _read_b11_storage_identity(
        _fake(
            [
                (
                    0,
                    b"pgdata_resolved=/var/lib/postgresql/data\n"
                    b"23 1 0:31 / / rw - fuse.fuse-overlayfs fuse-overlayfs rw\n",
                )
            ],
            calls,
        ),
        pgdata,
    )
    assert rootless["storage_filesystem"] == "fuse.fuse-overlayfs", rootless
    assert rootless["storage_mount_source"] == "fuse-overlayfs", rootless
    assert len(calls) == 1, calls

    # (c) a malformed mount point prevents an honest selection.
    calls = []
    malformed = _read_b11_storage_identity(
        _fake(
            [
                (
                    0,
                    b"pgdata_resolved=/var/lib/postgresql/data\n"
                    b"23 1 0:24 / relative rw - ext4 /dev/sda1 rw\n",
                )
            ],
            calls,
        ),
        pgdata,
    )
    assert malformed["storage_mount_point"] == B11_DIAGNOSTIC_UNAVAILABLE, malformed
    assert malformed["storage_filesystem"] == B11_DIAGNOSTIC_UNAVAILABLE, malformed
    assert (
        malformed["storage_pgdata_path"] == "%2Fvar%2Flib%2Fpostgresql%2Fdata"
    ), malformed

    # (d) two equally specific covering records are ambiguous, not guessed.
    calls = []
    ambiguous = _read_b11_storage_identity(
        _fake(
            [
                (
                    0,
                    b"pgdata_resolved=/var/lib/postgresql/data\n"
                    b"41 23 259:3 /a /var/lib/postgresql/data rw - ext4 /dev/sda1 rw\n"
                    b"42 23 259:4 /b /var/lib/postgresql/data rw - xfs /dev/sdb1 rw\n",
                )
            ],
            calls,
        ),
        pgdata,
    )
    assert ambiguous["storage_filesystem"] == B11_DIAGNOSTIC_UNAVAILABLE, ambiguous
    assert (
        ambiguous["storage_device_majmin"] == B11_DIAGNOSTIC_UNAVAILABLE
    ), ambiguous

    # (e) malformed root/source/major fields cost only themselves.
    calls = []
    fields = _read_b11_storage_identity(
        _fake(
            [
                (
                    0,
                    b"pgdata_resolved=/var/lib/postgresql/data\n"
                    b"41 23 25x:3 /volumes\\099pg /var/lib/postgresql/data rw - ext4 /dev/sda1 rw\n",
                )
            ],
            calls,
        ),
        pgdata,
    )
    assert fields["storage_mount_point"] == "%2Fvar%2Flib%2Fpostgresql%2Fdata", fields
    assert fields["storage_filesystem"] == "ext4", fields
    assert fields["storage_mount_source"] == "%2Fdev%2Fsda1", fields
    assert fields["storage_mount_root"] == B11_DIAGNOSTIC_UNAVAILABLE, fields
    assert fields["storage_device_majmin"] == B11_DIAGNOSTIC_UNAVAILABLE, fields
    assert len(calls) == 1, calls

    # (f) a nonzero exec exit preserves only the server's own PGDATA path.
    calls = []
    failed = _read_b11_storage_identity(_fake([(2, b"")], calls), pgdata)
    assert failed["storage_pgdata_path"] == "%2Fvar%2Flib%2Fpostgresql%2Fdata", failed
    assert failed["storage_mount_point"] == B11_DIAGNOSTIC_UNAVAILABLE, failed
    assert failed["storage_filesystem"] == B11_DIAGNOSTIC_UNAVAILABLE, failed
    assert len(calls) == 1, calls

    # (g) an unframed mountinfo response is refused: no proof of provenance.
    calls = []
    unframed = _read_b11_storage_identity(
        _fake([(0, b"41 23 259:3 / /var/lib/postgresql/data rw - ext4 /dev/sda1 rw\n")], calls),
        pgdata,
    )
    assert unframed["storage_mount_point"] == B11_DIAGNOSTIC_UNAVAILABLE, unframed

    # (h) absent or masked sysfs: every mount member survives.
    calls = []
    masked = _read_b11_storage_identity(
        _fake(
            [
                (
                    0,
                    b"pgdata_resolved=/var/lib/postgresql/data\n"
                    b"41 23 259:3 / /var/lib/postgresql/data rw - ext4 /dev/sda1 rw\n",
                ),
                (0, b""),
            ],
            calls,
        ),
        pgdata,
    )
    assert len(calls) == 2, calls
    assert masked["storage_device_majmin"] == "259:3", masked
    assert masked["storage_filesystem"] == "ext4", masked
    assert masked["storage_block_device"] == B11_DIAGNOSTIC_UNAVAILABLE, masked
    assert masked["storage_model"] == B11_DIAGNOSTIC_UNAVAILABLE, masked

    # (i) partial, invalid and duplicated block members, each field-local.
    calls = []
    partial = _read_b11_storage_identity(
        _fake(
            [
                (
                    0,
                    b"pgdata_resolved=/var/lib/postgresql/data\n"
                    b"41 23 259:3 / /var/lib/postgresql/data rw - ext4 /dev/sda1 rw\n",
                ),
                (
                    0,
                    b"block_device=dm-0\nrotational=7\nmodel=\nmodel=Fake\n",
                ),
            ],
            calls,
        ),
        pgdata,
    )
    assert partial["storage_block_device"] == "dm-0", partial
    assert partial["storage_rotational"] == B11_DIAGNOSTIC_UNAVAILABLE, partial
    assert partial["storage_scheduler"] == B11_DIAGNOSTIC_UNAVAILABLE, partial
    assert partial["storage_model"] == B11_DIAGNOSTIC_UNAVAILABLE, partial

    # (j) the device-mapper shapes the script can return: a kept dm node when
    # zero or several slaves are exposed, the sole slave's parent when exactly
    # one is.  The implementation never chooses among several backing devices.
    for emitted, expected in (
        (b"block_device=dm-0\nrotational=1\n", "dm-0"),
        (b"block_device=sda\nrotational=1\n", "sda"),
    ):
        calls = []
        mapper = _read_b11_storage_identity(
            _fake(
                [
                    (
                        0,
                        b"pgdata_resolved=/var/lib/postgresql/data\n"
                        b"41 23 253:0 / /var/lib/postgresql/data rw - ext4 /dev/dm-0 rw\n",
                    ),
                    (0, emitted),
                ],
                calls,
            ),
            pgdata,
        )
        assert mapper["storage_block_device"] == expected, mapper
        assert mapper["storage_rotational"] == "1", mapper

    # (k) an unknown block member is a harness-schema defect, not a reading.
    rejected = False
    try:
        _parse_b11_container_block_output("block_device=sda\nvendor=ACME\n")
    except AssertionError:
        rejected = True
    assert rejected, "an unknown block key must raise"

    # (l) a Docker API failure leaves every container-read field unavailable.
    class _Broken:
        def get_wrapped_container(self):
            raise DockerException("no daemon")

    broken = _read_b11_storage_identity(_Broken(), pgdata)
    assert broken["storage_pgdata_path"] == "%2Fvar%2Flib%2Fpostgresql%2Fdata", broken
    assert broken["storage_mount_point"] == B11_DIAGNOSTIC_UNAVAILABLE, broken
    assert broken["storage_block_device"] == B11_DIAGNOSTIC_UNAVAILABLE, broken

    # (m) a failed data_directory query, and a traversing path, read nothing.
    calls = []
    unknown = _read_b11_storage_identity(
        _fake([], calls), B11_DIAGNOSTIC_UNAVAILABLE
    )
    assert unknown["storage_pgdata_path"] == B11_DIAGNOSTIC_UNAVAILABLE, unknown
    assert len(calls) == 0, calls
    calls = []
    traversing = _read_b11_storage_identity(_fake([], calls), "/var/lib/../etc")
    assert traversing["storage_pgdata_path"] == "%2Fvar%2Flib%2F..%2Fetc", traversing
    assert traversing["storage_mount_point"] == B11_DIAGNOSTIC_UNAVAILABLE, traversing
    assert len(calls) == 0, calls

    # (n) the exec helper refuses every argv outside the two closed shapes,
    # before Docker is touched.
    class _NeverCalled:
        def exec_run(
            self,
            cmd,
            stdout,
            stderr,
            stdin,
            tty,
            privileged,
            user,
            detach,
            stream,
            socket,
            environment,
            workdir,
            demux,
        ):
            raise AssertionError("Docker must not be reached")

    for argv in (
        ["/bin/sh", "-c", "cat /proc/self/mountinfo", "b11-mount", "/data"],
        ["/bin/sh", "-c", B11_CONTAINER_MOUNT_SCRIPT, "b11-mount", "relative"],
        ["/bin/sh", "-c", B11_CONTAINER_MOUNT_SCRIPT, "b11-mount", "/a/../b"],
        ["/bin/sh", "-c", B11_CONTAINER_BLOCK_SCRIPT, "b11-block", "8:0:1"],
        ["/bin/sh", "-c", B11_CONTAINER_BLOCK_SCRIPT, "b11-block", "sda"],
        ["nsenter", "-t", "1", "b11-mount", "/data"],
    ):
        refused = False
        try:
            _exec_b11_container_text(_NeverCalled(), argv)
        except AssertionError:
            refused = True
        assert refused, argv


def test_b11_diagnostics_schema_is_canonical_and_comma_safe():
    """FP-B11HD-1: one fixed-prefix physical line, 21 fields, no raw comma.

    The serializer is the only thing that can print the line, and it refuses a
    missing, extra, reordered or empty field and any raw comma or newline in a
    value; writer entries are `+`-joined so a writer can never forge a
    top-level field boundary.
    """
    instances = [({"process": "ingest-gateway"}, i) for i in range(4)] + [
        ({"process": "dashboard-api"}, 0),
        ({"process": "probe-gateway"}, 0),
        ({"process": "temporal-worker"}, 0),
    ]
    measured = [
        (7.5, 800),
        (7.25, 800),
        (7.125, 800),
        (7.0625, 800),
        (6.5, 800),
        (6.25, 800),
        (6.125, 799),
    ]
    writer_field = _serialize_writer_elapsed_rows(instances, measured)
    assert writer_field == (
        "ingest-gateway#0:7500.000:800+"
        "ingest-gateway#1:7250.000:800+"
        "ingest-gateway#2:7125.000:800+"
        "ingest-gateway#3:7062.500:800+"
        "dashboard-api:6500.000:800+"
        "probe-gateway:6250.000:800+"
        "temporal-worker:6125.000:799"
    ), writer_field
    assert len(writer_field.split("+")) == 7, writer_field
    assert "," not in writer_field, writer_field

    # A future process name cannot forge an entry or field boundary.
    forged = _serialize_writer_elapsed_rows(
        [({"process": "a,b+c:d e"}, 0)], [(1.0, 1)]
    )
    assert forged == "a%2Cb%2Bc%3Ad%20e:1000.000:1", forged

    for broken_instances, broken_measured in (
        (instances, measured[:6]),
        (instances, [None] + measured[1:]),
        (
            [({"process": "dashboard-api"}, 0), ({"process": "dashboard-api"}, 0)],
            [(1.0, 1), (1.0, 1)],
        ),
        (instances, [(-1.0, 800)] + measured[1:]),
    ):
        rejected = False
        try:
            _serialize_writer_elapsed_rows(broken_instances, broken_measured)
        except AssertionError:
            rejected = True
        assert rejected, broken_measured

    values = {
        "combined_rate_per_sec": "743.7",
        "serial_commit_ms": "1.264",
        "combined_over_single": "0.94",
        "writer_elapsed_rows": writer_field,
        "host_steal_usec": "0",
        "host_psi_cpu_some_usec": "123",
        "host_psi_cpu_full_usec": B11_DIAGNOSTIC_UNAVAILABLE,
        "host_psi_io_some_usec": "456",
        "host_psi_io_full_usec": "7",
        "host_psi_memory_some_usec": "0",
        "host_psi_memory_full_usec": "0",
        "storage_pgdata_path": "%2Fvar%2Flib%2Fpostgresql%2Fdata",
        "storage_filesystem": "ext4",
        "storage_mount_source": "%2Fdev%2Fnvme0n1p1",
        "storage_mount_root": "%2F",
        "storage_mount_point": "%2Fvar%2Flib%2Fpostgresql%2Fdata",
        "storage_device_majmin": "259:1",
        "storage_block_device": "nvme0n1",
        "storage_rotational": "0",
        "storage_scheduler": "%5Bnone%5D%20mq-deadline",
        "storage_model": "Amazon%20Elastic%20Block%20Store",
    }
    line = _serialize_b11_diagnostics(values)
    assert line == (
        "B11 diagnostics=combined_rate_per_sec=743.7,serial_commit_ms=1.264,"
        "combined_over_single=0.94,writer_elapsed_rows=" + writer_field + ","
        "host_steal_usec=0,host_psi_cpu_some_usec=123,"
        "host_psi_cpu_full_usec=unavailable,host_psi_io_some_usec=456,"
        "host_psi_io_full_usec=7,host_psi_memory_some_usec=0,"
        "host_psi_memory_full_usec=0,"
        "storage_pgdata_path=%2Fvar%2Flib%2Fpostgresql%2Fdata,"
        "storage_filesystem=ext4,storage_mount_source=%2Fdev%2Fnvme0n1p1,"
        "storage_mount_root=%2F,"
        "storage_mount_point=%2Fvar%2Flib%2Fpostgresql%2Fdata,"
        "storage_device_majmin=259:1,storage_block_device=nvme0n1,"
        "storage_rotational=0,storage_scheduler=%5Bnone%5D%20mq-deadline,"
        "storage_model=Amazon%20Elastic%20Block%20Store"
    ), line
    assert line.startswith(B11_DIAGNOSTIC_PREFIX), line
    assert len(line.splitlines()) == 1, line
    body = line.split("=", 1)[1]
    fields = body.split(",")
    assert len(fields) == len(B11_DIAGNOSTIC_FIELDS) == 21, fields
    for number, entry in enumerate(fields):
        halves = entry.split("=")
        assert len(halves) == 2, entry
        assert halves[0] == B11_DIAGNOSTIC_FIELDS[number], entry
        assert halves[1], entry

    # Percent-encoding: uppercase hex, and every boundary character encoded.
    assert _encode_b11_value("Amazon Elastic Block Store") == (
        "Amazon%20Elastic%20Block%20Store"
    )
    assert _encode_b11_value("/dev/nvme0n1p1") == "%2Fdev%2Fnvme0n1p1"
    assert _encode_b11_value("a,b") == "a%2Cb"
    assert _encode_b11_value("a=b") == "a%3Db"
    assert _encode_b11_value("a\nb") == "a%0Ab"
    assert _encode_b11_value("a%b") == "a%25b"
    assert _encode_b11_value("é") == "%C3%A9"
    assert _encode_b11_value("keep-._~:+") == "keep-._~:+"

    missing = dict(values)
    del missing["storage_model"]
    extra = dict(values)
    extra["storage_zone"] = "eu-west-1a"
    reordered = {}
    for name in reversed(B11_DIAGNOSTIC_FIELDS):
        reordered[name] = values[name]
    raw_comma = dict(values)
    raw_comma["storage_model"] = "Amazon, Elastic"
    raw_newline = dict(values)
    raw_newline["storage_scheduler"] = "none\nmq-deadline"
    empty = dict(values)
    empty["storage_filesystem"] = ""
    for broken in (missing, extra, reordered, raw_comma, raw_newline, empty):
        rejected = False
        try:
            _serialize_b11_diagnostics(broken)
        except AssertionError:
            rejected = True
        assert rejected, tuple(broken)


def test_b11_diagnostic_sampling_brackets_the_timed_window():
    """FP-B11HD-4/5: every diagnostic read lies outside the measured work.

    A lexical line-order check over this file: PGDATA and both possible storage
    execs finish before the first engine, connection and row warmup; the
    in-place `elapsed` assignment follows the map immediately and the closing
    host read is the next action; the two writer-boundary clock reads and the
    one side-channel assignment stay outside the counted row loop; and no
    diagnostic I/O, formatting or printing is inside either timed loop.  The
    real AST proof and the movement mutations live in the independent guard
    tests/functional/test_b11_writer_model.py.
    """
    lines = Path(__file__).read_text(encoding="utf-8").splitlines()
    opened = None
    closed = len(lines)
    for number, body in enumerate(lines):
        if body.startswith("def test_b11_audit_llm_insert_throughput(scale_pg):"):
            opened = number
        elif opened is not None and body.startswith("def "):
            closed = number
            break
    assert opened is not None, "the B11 benchmark function moved"

    def _sole(marker):
        hits = []
        for number in range(opened, closed):
            if lines[number].strip() == marker:
                hits.append(number)
        assert len(hits) == 1, f"expected exactly one {marker!r}, found {hits}"
        return hits[0]

    def _sole_containing(fragment):
        hits = []
        for number in range(opened, closed):
            if fragment in lines[number]:
                hits.append(number)
        assert len(hits) == 1, f"expected one line with {fragment!r}, found {hits}"
        return hits[0]

    def _indent(number):
        return len(lines[number]) - len(lines[number].strip())

    query = _sole("pgdata_row = conn.execute(")
    storage = _sole(
        'storage_values = _read_b11_storage_identity(scale_pg["container"], pgdata_path)'
    )
    preallocation = _sole("writer_elapsed_rows = [None] * len(instances)")
    engine = _sole_containing("= make_engine(")
    connection_warmup = _sole('conn.execute(text("SELECT 1"))')
    row_warmup = _sole("list(pool.map(_warmup, range(len(instances))))")
    tick_rate = _sole('clock_ticks = os.sysconf("SC_CLK_TCK")')
    host_open = _sole("host_before = _read_b11_host_snapshot()")
    window_open = _sole("t0 = time.perf_counter()")
    mapped = _sole("committed = list(pool.map(_run_writer, range(len(instances))))")
    window_close = _sole("elapsed = time.perf_counter() - t0")
    host_close = _sole("host_after = _read_b11_host_snapshot()")
    single_writer = _sole("t_sw = time.perf_counter()")
    single_close = _sole("sw_elapsed = time.perf_counter() - t_sw")
    writer_open = _sole("writer_t0 = time.perf_counter()")
    side_channel = _sole(
        "writer_elapsed_rows[idx] = (time.perf_counter() - writer_t0, rows)"
    )
    row_loop = _sole("for i in range(n_iters):")
    writer_return = _sole("return rows")
    canonical = _sole("print(_serialize_b11_diagnostics(diagnostic_values))")
    bar = _sole("assert rate >= 1000.0, (")
    single_loop = _sole("for i in range(100):")
    warmup_loop = _sole("for i in range(50):")
    _sole("n_iters = 800")

    # (1) all storage work precedes every engine, connection and row warmup.
    assert query < storage < preallocation < engine, (query, storage, engine)
    assert storage < connection_warmup < row_warmup, (storage, row_warmup)

    # (2) the window opens after the host read and closes in place.
    assert row_warmup < tick_rate < host_open < window_open, (tick_rate, host_open)
    assert mapped == window_open + 1, (window_open, mapped)
    assert window_close == mapped + 1, (mapped, window_close)
    assert host_close == window_close + 1, (window_close, host_close)
    assert host_close < single_writer < canonical < bar, (host_close, bar)

    # (3) the writer takes two boundary clocks and writes one slot, both
    # outside its counted row loop.
    assert writer_open < row_loop < side_channel < writer_return, (
        writer_open,
        side_channel,
    )
    assert _indent(writer_open) == _indent(side_channel) == _indent(writer_return)
    assert _indent(row_loop) > _indent(side_channel), (row_loop, side_channel)

    # (4) neither timed loop contains diagnostic work.
    for start, stop in ((row_loop, side_channel), (single_loop, single_close)):
        for number in range(start + 1, stop):
            for token in (
                "_read_b11_host_snapshot",
                "_read_b11_storage_identity",
                "_exec_b11_container_text",
                "_parse_b11_container",
                "_mountinfo_record_for_path",
                "_serialize_",
                "_encode_b11_value",
                "perf_counter",
                "print(",
                "read_text",
                "exec_run",
                "/proc",
                "/sys",
            ):
                assert token not in lines[number], (number, token, lines[number])
