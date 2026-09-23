"""The relay override for `scripts/integration-test.sh`'s preflight.

design/slices/relay-override/design.md, FP-RELAY-1..7. The launcher refuses to
start a Docker-backed target when `/usr/bin/ip` reports no global-scope address,
because the Claude Code Bash sandbox has exactly that shape and every
testcontainers test in it starts a container it cannot reach. A jailed reviewer
has the same empty address list and a Docker socket relayed from the host, and
used to get past the gate by putting a fake `ip` on PATH -- which reports a route
nobody observed.

The override replaces that trick with evidence the script gathers itself: a local
unix socket, a `mktemp` directory the daemon can see through a bind mount, and a
`--network host` client that completes a TCP handshake with a `--network host`
listener started through the caller's own socket. `DBAGENT_DOCKER_RELAY=prove` is
a REQUEST for that proof; only the proof admits.

These tests follow tests/functional/test_b1_cleanup_run_dir.py: they read the
launcher, source only its `# RELAY_GATE_BEGIN` / `# RELAY_GATE_END` region in a
subprocess, and call the functions. Nothing here skips, xfails or retries. The
live cases need this host's Docker client and the `postgres:16-alpine` image the
tier already uses; a missing daemon fails them, exactly as it already fails
test_b1_cleanup_run_dir.py.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = REPO_ROOT / "scripts" / "integration-test.sh"
VERSIONS_ENV = REPO_ROOT / "deploy" / "versions.env"

REGION_BEGIN = "# RELAY_GATE_BEGIN"
REGION_END = "# RELAY_GATE_END"

#: Every name the region must define, declared here rather than discovered, so a
#: function that quietly disappears is a named failure and not a silent pass.
REGION_FUNCTIONS = (
    "relay_address_count",
    "relay_target_admitted",
    "relay_legacy_refuse",
    "relay_legacy_docker_info",
    "relay_fail",
    "relay_docker_socket_path",
    "relay_probe_cleanup",
    "relay_probe_server",
    "relay_probe_client",
    "relay_prove",
    "relay_gate_counted",
    "relay_gate",
    "relay_print_preflight",
)

PROBE_LABEL_KEY = "dbagent.relay-probe"
LEGACY_FIRST_LINE = (
    "integration-test.sh: REFUSING TO RUN -- this shell has no route to anything."
)
RELAY_REFUSAL = (
    "integration-test.sh: REFUSING TO RUN -- relay override did not prove "
    "host-network reachability ({reason})."
)
IMAGE_ABSENT_SECOND_LINE = (
    "integration-test.sh: probe image postgres:16-alpine is not present locally; "
    "this preflight does not pull it."
)

#: §3.3, narrowed by bench-on-demand FP-BOD-2: the CI-scale target, the
#: CPU-basis oracle and the topology sweep are deleted, so the relay admits
#: the two targets that remain. Exact `case` membership, not a substring test.
ADMITTED_TARGETS = ("preflight", "b1_product")
#: §3.3, declared independently of the script's argument `case`; the FP-RELAY-5
#: test parses that `case` and compares the two.
NON_ADMITTED_TARGETS = (
    "all", "go", "py", "python", "smoke",
    "d0_2a", "d0_2c", "d0_2d", "d0_3a", "d0_3b", "d0_3c", "d0_4", "d0_4_workers",
    "sp_1", "sp_1_run", "sp_1_sg4", "rm_1", "rm_1_run", "lv_1", "lv_1_run",
)

#: §3.2, byte for byte, with the two expansions the unquoted heredoc performs.
EXPECTED_REFUSAL = """integration-test.sh: REFUSING TO RUN -- this shell has no route to anything.

  No global-scope network address is present, which means this is running inside the
  Claude Code Bash sandbox (/proc/1/comm = {comm}).
  Every testcontainers test would start its container and then fail to connect to it,
  after burning 60s per package in Ryuk.

  This script must be excluded from the sandbox. In ~/.claude/settings.json:

      "sandbox": {{
        "excludedCommands": [
          "{repo_root}/scripts/integration-test.sh*",
          "bash {repo_root}/scripts/integration-test.sh*"
        ]
      }}

  If those entries are already there, the pattern did not match how this was invoked.
  Invoke it by ABSOLUTE PATH -- a relative path from another cwd matches neither entry.

  Background: ~/.claude/SANDBOX-NETWORK.md
"""

#: What a PATH `ip` shim prints. Three global-scope lines, so a count that came
#: from the shim is distinguishable from almost any host's real one.
FORGED_IP_OUTPUT = (
    '2: fake0    inet 203.0.113.9/24 scope global fake0\\       valid_lft forever\n'
    '3: fake1    inet 198.51.100.4/24 scope global fake1\\       valid_lft forever\n'
    '4: fake2    inet 192.0.2.7/24 scope global fake2\\       valid_lft forever'
)

#: A path that is not a socket, used to show that the request alone admits nothing.
ABSENT_SOCKET = "unix:///tmp/relay-preflight-no-such.sock"


# --- reading the launcher -------------------------------------------------


def _launcher_text() -> str:
    return LAUNCHER.read_text(encoding="utf-8")


def _relay_region(launcher: str | None = None) -> str:
    """The sourced region, asserted to be function definitions and nothing else."""
    text = _launcher_text() if launcher is None else launcher
    assert text.count(REGION_BEGIN) == 1, f"{REGION_BEGIN} is not in the launcher exactly once"
    assert text.count(REGION_END) == 1, f"{REGION_END} is not in the launcher exactly once"
    begin = text.index(REGION_BEGIN) + len(REGION_BEGIN)
    end = text.index(REGION_END)
    assert begin < end, "the region markers are out of order"
    region = text[begin:end]

    in_heredoc = False
    for line in region.splitlines():
        if in_heredoc:
            in_heredoc = line.strip() != "EOF"
            continue
        if not line.strip() or line.startswith((" ", "\t", "#")):
            in_heredoc = line.rstrip().endswith("<<EOF")
            continue
        assert re.fullmatch(r"[a-z0-9_]+\(\) \{", line) or line == "}", (
            f"the sourced region carries a top-level statement: {line!r}"
        )
    for name in REGION_FUNCTIONS:
        assert f"{name}() {{" in region, f"{name} is not defined in the region"
    return region


def _shell_function(region: str, name: str) -> str:
    """One shell function of the region, header through its own closing brace."""
    lines = region.splitlines()
    start = next((i for i, line in enumerate(lines) if line == f"{name}() {{"), None)
    assert start is not None, f"{name} is not defined in the region"
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
    return "\n".join(lines[start:end + 1]) + "\n"


def _argument_case_targets() -> tuple[str, ...]:
    """The names the launcher's argument `case` accepts, in its own order."""
    match = re.search(r"^  ([A-Za-z0-9_|]+)\) ;;$", _launcher_text(), re.MULTILINE)
    assert match is not None, "the launcher no longer opens with an argument case"
    names = tuple(match.group(1).split("|"))
    assert "preflight" in names and "b1_product" in names, names
    return names


# --- running it -----------------------------------------------------------


def _run_region(
    body: str,
    *,
    region: str | None = None,
    env: dict[str, str | None] | None = None,
    timeout: float = 180,
) -> subprocess.CompletedProcess:
    """Source the region in a fresh shell and run `body` against it."""
    program = "\n".join(("set -uo pipefail", 'eval "$RELAY_REGION"', body))
    environ = dict(os.environ)
    environ.pop("DBAGENT_DOCKER_RELAY", None)
    environ["RELAY_REGION"] = _relay_region() if region is None else region
    environ["REPO_ROOT"] = str(REPO_ROOT)
    for key, value in (env or {}).items():
        if value is None:
            environ.pop(key, None)
        else:
            environ[key] = value
    return subprocess.run(
        ["bash", "-c", program], capture_output=True, text=True,
        cwd=REPO_ROOT, env=environ, timeout=timeout,
    )


def _gate_counted(
    count: str, target: str, request: str, **kwargs
) -> subprocess.CompletedProcess:
    body = "\n".join((
        "relay_gate_counted {} {} {}".format(
            shlex.quote(count), shlex.quote(target), shlex.quote(request)
        ),
        'echo "rc=$?"',
        'echo "PREFLIGHT_MODE=${PREFLIGHT_MODE:-unset}"',
    ))
    return _run_region(body, **kwargs)


def _shim(directory: Path, name: str, *, stdout: str = "", status: int = 0) -> Path:
    """An executable on PATH that records every call and answers as told."""
    directory.mkdir(parents=True, exist_ok=True)
    log = directory / f"{name}.log"
    lines = ["#!/bin/sh", f'printf "%s\\n" "$*" >> {shlex.quote(str(log))}']
    if stdout:
        lines.append(f"cat <<'SHIMOUT'\n{stdout}\nSHIMOUT")
    lines.append(f"exit {status}")
    path = directory / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o755)
    return log


def _path_with(directory: Path) -> dict[str, str]:
    return {"PATH": f"{directory}:{os.environ['PATH']}"}


def _usr_bin_ip_count() -> int:
    """What the launcher's trusted counter sees on this host, right now."""
    result = subprocess.run(
        ["/usr/bin/ip", "-o", "addr", "show", "scope", "global"],
        capture_output=True, text=True, timeout=60,
    )
    return result.stdout.count("\n")


def _probe_containers() -> list[str]:
    """Every container this repository's relay proof has ever labelled, now."""
    result = subprocess.run(
        ["/usr/bin/docker", "ps", "-aq", "--filter", f"label={PROBE_LABEL_KEY}"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, (
        "these tests need this host's Docker client, the same requirement "
        "test_b1_cleanup_run_dir.py already has: "
        + result.stdout + result.stderr
    )
    return result.stdout.split()


def _pinned_postgres_image() -> str:
    for line in VERSIONS_ENV.read_text(encoding="utf-8").splitlines():
        if line.startswith("POSTGRES_IMAGE="):
            return line.split("=", 1)[1].strip()
    raise AssertionError("deploy/versions.env no longer pins POSTGRES_IMAGE")


@pytest.fixture
def clean_probe_census():
    """No probe container before the test, and none after it."""
    assert _probe_containers() == [], "a relay probe container was already running"
    yield
    assert _probe_containers() == [], "the relay proof left a probe container behind"


# --- unit tests -----------------------------------------------------------


def test_relay_address_count_matches_usr_bin_ip(tmp_path: Path):
    """FP-RELAY-1/2: the count is /usr/bin/ip's, and PATH's `ip` is never run."""
    shim_dir = tmp_path / "shim"
    ip_log = _shim(shim_dir, "ip", stdout=FORGED_IP_OUTPUT)
    env = _path_with(shim_dir)

    result = _run_region("relay_address_count", env=env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(_usr_bin_ip_count()), result.stdout
    assert result.stdout.strip().isdigit(), result.stdout
    assert not ip_log.exists(), (
        "the launcher executed a PATH `ip`: " + ip_log.read_text(encoding="utf-8")
    )

    # The absolute path is what keeps the shim out: take it away and the same
    # shim is executed and decides the count.
    region = _relay_region()
    forged_region = region.replace("/usr/bin/ip -o addr", "ip -o addr", 1)
    assert forged_region != region, "the counter no longer calls /usr/bin/ip by path"
    forged = _run_region("relay_address_count", region=forged_region, env=env)
    assert forged.stdout.strip() == "3", forged.stdout + forged.stderr
    assert ip_log.exists() and ip_log.read_text(encoding="utf-8").strip() == (
        "-o addr show scope global"
    )


def test_relay_decision_table(tmp_path: Path):
    """FP-RELAY-1/2/5/7: every row of the §3.2 table, by count and by target."""
    quiet = tmp_path / "quiet"
    quiet_log = _shim(quiet, "docker")
    quiet_env = _path_with(quiet)

    # Count 0, no request or a non-admitted target: today's refusal, no Docker.
    for target, request in (
        ("preflight", ""), ("b1_product", ""), ("all", ""),
        ("py", "prove"), ("all", "prove"), ("d0_2a", "prove"),
        ("b1_extra", "prove"),
    ):
        result = _gate_counted("0", target, request, env=quiet_env)
        detail = f"{target}/{request!r}: {result.stdout}{result.stderr}"
        assert result.returncode == 3, detail
        assert result.stderr.startswith(LEGACY_FIRST_LINE), detail
        assert "relay override" not in result.stderr, detail
        assert not quiet_log.exists(), (
            "the refusal path executed a PATH `docker`: "
            + quiet_log.read_text(encoding="utf-8")
        )

    # Count 0 and an admitted target with `prove`: the proof starts, and stops
    # at the first thing it checks. The variable did not admit anything.
    for target in ADMITTED_TARGETS:
        result = _gate_counted(
            "0", target, "prove", env={**quiet_env, "DOCKER_HOST": ABSENT_SOCKET}
        )
        detail = f"{target}: {result.stdout}{result.stderr}"
        assert result.returncode == 3, detail
        assert result.stderr == RELAY_REFUSAL.format(reason="relay_socket_absent") + "\n", detail
        assert not quiet_log.exists(), quiet_log.read_text(encoding="utf-8")

    # Count 0, admitted, any other non-empty request: fail closed, no Docker.
    invalid = _gate_counted("0", "b1_product", "1", env=quiet_env)
    assert invalid.returncode == 3
    assert invalid.stderr == RELAY_REFUSAL.format(reason="relay_request_invalid") + "\n"
    assert not quiet_log.exists()

    # Count > 0: the request is ignored, the proof is not entered, and the
    # existing `docker info` check decides.
    ok_dir = tmp_path / "docker-ok"
    ok_log = _shim(ok_dir, "docker", stdout="28.0.0")
    for target, request in (("preflight", "prove"), ("b1_product", "garbage"), ("py", "")):
        result = _gate_counted("2", target, request, env=_path_with(ok_dir))
        detail = f"{target}/{request!r}: {result.stdout}{result.stderr}"
        assert "rc=0" in result.stdout, detail
        assert "PREFLIGHT_MODE=legacy" in result.stdout, detail
        assert "relay override" not in result.stderr, detail
    assert [line.strip() for line in ok_log.read_text(encoding="utf-8").splitlines()] == [
        "info", "info", "info"
    ]

    bad_dir = tmp_path / "docker-bad"
    _shim(bad_dir, "docker", status=1)
    unreachable = _gate_counted("2", "b1_product", "prove", env=_path_with(bad_dir))
    assert unreachable.returncode == 3, unreachable.stdout
    assert "cannot reach the Docker daemon" in unreachable.stderr
    assert "relay override" not in unreachable.stderr

    # The legacy daemon check is load-bearing on that row: remove it and the
    # same failing daemon is admitted.
    region = _relay_region()
    without_check = region.replace("    relay_legacy_docker_info\n", "", 1)
    assert without_check != region, "the count>0 row no longer calls relay_legacy_docker_info"
    admitted = _gate_counted(
        "2", "b1_product", "prove", region=without_check, env=_path_with(bad_dir)
    )
    assert "rc=0" in admitted.stdout, admitted.stdout + admitted.stderr


def test_relay_socket_and_request_tokens(tmp_path: Path):
    """FP-RELAY-4/7: socket resolution never exits, and a bad request is closed."""
    for value, expected in (
        (None, "/var/run/docker.sock"),
        ("", "/var/run/docker.sock"),
        ("unix:///abs/docker.sock", "/abs/docker.sock"),
        ("unix:///run/user/1000/docker.sock", "/run/user/1000/docker.sock"),
        ("tcp://127.0.0.1:2375", ""),
        ("unix://relative/docker.sock", ""),
        ("unix://", ""),
    ):
        result = _run_region(
            'relay_docker_socket_path\necho "rc=$?"', env={"DOCKER_HOST": value}
        )
        detail = f"DOCKER_HOST={value!r}: {result.stdout!r} {result.stderr!r}"
        assert result.stderr == "", detail
        assert result.returncode == 0, detail
        printed, _, status = result.stdout.rpartition("rc=")
        assert status.strip() == "0", detail
        assert printed == (f"{expected}\n" if expected else ""), detail

    # The refusal is the caller's, after the empty capture -- not the helper's.
    quiet = tmp_path / "quiet"
    quiet_log = _shim(quiet, "docker")
    not_unix = _run_region(
        "relay_prove", env={**_path_with(quiet), "DOCKER_HOST": "tcp://127.0.0.1:2375"}
    )
    assert not_unix.returncode == 3, not_unix.stdout
    assert not_unix.stderr == RELAY_REFUSAL.format(reason="relay_socket_not_unix") + "\n"
    assert not quiet_log.exists()

    for request in ("Prove", "1", "PROVE", "prove "):
        result = _gate_counted("0", "b1_product", request, env=_path_with(quiet))
        detail = f"{request!r}: {result.stdout}{result.stderr}"
        assert result.returncode == 3, detail
        assert result.stderr == RELAY_REFUSAL.format(reason="relay_request_invalid") + "\n", detail
    assert not quiet_log.exists()


def test_relay_legacy_refusal_stderr_is_exact():
    """FP-RELAY-1: the refusal is the one this script has always printed."""
    try:
        comm = Path("/proc/1/comm").read_text(encoding="utf-8").strip() or "?"
    except OSError:
        comm = "?"
    expected = EXPECTED_REFUSAL.format(comm=comm, repo_root=REPO_ROOT)

    result = _run_region("relay_legacy_refuse")
    assert result.returncode == 3
    assert result.stdout == ""
    assert result.stderr == expected, repr(result.stderr)

    launcher = _launcher_text()
    assert launcher.count(LEGACY_FIRST_LINE) == 1, "the refusal has more than one copy"
    assert "relay override" not in expected


def test_relay_probe_image_literal_matches_versions_env():
    """FP-RELAY-4: one probe image, the pinned one, and no pull on any path."""
    pinned = _pinned_postgres_image()
    assert pinned == "postgres:16-alpine", pinned
    region = _relay_region()

    assert set(re.findall(r"postgres:[A-Za-z0-9._-]+", region)) == {pinned}
    assert f"image inspect {pinned}" in region
    for name in ("relay_probe_server", "relay_probe_client"):
        assert pinned in _shell_function(region, name), name
    assert "docker pull" not in region
    assert IMAGE_ABSENT_SECOND_LINE in region


# --- function tests, one per FP -------------------------------------------


def test_relay_script_refuses_zero_addresses_without_consulting_path_ip(tmp_path: Path):
    """FP-RELAY-1: the real script, a forged PATH `ip`, and no request."""
    shim_dir = tmp_path / "shim"
    ip_log = _shim(shim_dir, "ip", stdout=FORGED_IP_OUTPUT)
    env = dict(os.environ)
    env.pop("DBAGENT_DOCKER_RELAY", None)
    env["PATH"] = f"{shim_dir}:{env['PATH']}"

    result = subprocess.run(
        [str(LAUNCHER), "preflight"], capture_output=True, text=True,
        cwd=REPO_ROOT, env=env, timeout=300,
    )
    count = _usr_bin_ip_count()
    detail = f"count={count} rc={result.returncode}\n{result.stdout}\n{result.stderr}"
    if count == 0:
        assert result.returncode == 3, detail
        assert result.stderr.startswith(LEGACY_FIRST_LINE), detail
        assert "preflight OK" not in result.stdout, detail
    else:
        assert LEGACY_FIRST_LINE not in result.stderr, detail
        assert "preflight OK (relay override)" not in result.stdout, detail
    assert not ip_log.exists(), (
        "the launcher executed a PATH `ip`: " + ip_log.read_text(encoding="utf-8")
    )


def test_relay_positive_address_count_uses_legacy_docker_info(
    tmp_path: Path, clean_probe_census
):
    """FP-RELAY-2: a real address list keeps the existing gate and its text."""
    ok_dir = tmp_path / "docker-ok"
    ok_log = _shim(ok_dir, "docker", stdout="28.0.0")
    body = "\n".join((
        "relay_gate_counted 2 preflight prove",
        'echo "rc=$?"',
        'echo "PREFLIGHT_MODE=$PREFLIGHT_MODE"',
        "relay_print_preflight",
    ))
    result = _run_region(body, env=_path_with(ok_dir))
    detail = result.stdout + result.stderr
    assert "rc=0" in result.stdout, detail
    assert "PREFLIGHT_MODE=legacy" in result.stdout, detail
    assert "integration-test.sh: preflight OK" in result.stdout, detail
    assert "  outside the sandbox :" in result.stdout, detail
    assert "preflight OK (relay override)" not in result.stdout, detail
    assert "relay proof" not in result.stdout, detail
    assert [line.strip() for line in ok_log.read_text(encoding="utf-8").splitlines()] == [
        "info", "version --format {{.Server.Version}}"
    ], ok_log.read_text(encoding="utf-8")

    bad_dir = tmp_path / "docker-bad"
    _shim(bad_dir, "docker", status=1)
    refused = _gate_counted("2", "preflight", "prove", env=_path_with(bad_dir))
    assert refused.returncode == 3, refused.stdout
    assert "cannot reach the Docker daemon" in refused.stderr


def test_relay_prove_request_is_not_accepted_without_host_network_reachability(
    tmp_path: Path, clean_probe_census
):
    """FP-RELAY-3: `prove` asks; the host network is what answers."""
    region = _relay_region()
    client = _shell_function(region, "relay_probe_client")
    assert client.count("  --network host \\\n") == 1, client
    mutated = region.replace(client, client.replace("  --network host \\\n", "", 1), 1)
    assert mutated != region, "the client mutation was a no-op"

    # The copy differs from the shipped proof in one flag, on the client only.
    assert "--network host" in _shell_function(mutated, "relay_probe_server")
    assert "--network host" not in _shell_function(mutated, "relay_probe_client")
    for pin in (
        '      *"$listen_line"*"$ready_line"*) ready=1; break ;;',
        "  if ! relay_probe_client; then\n    relay_fail relay_probe_unreachable\n  fi\n",
    ):
        assert pin in mutated, pin
    assert mutated.count("relay_fail relay_probe_unreachable") == 1
    prove = _shell_function(mutated, "relay_prove")
    loop = prove[prove.index('  while [ "$SECONDS"'):prove.index("\n  done\n")]
    assert "relay_probe_client" not in loop, "the client is invoked inside the wait loop"
    assert prove.index("if ! relay_probe_client") > prove.index("\n  done\n")

    result = _run_region(
        'relay_prove\necho "rc=$?"', region=mutated,
        env={"TMPDIR": str(tmp_path)}, timeout=600,
    )
    detail = result.stdout + result.stderr
    assert result.returncode == 3, detail
    assert RELAY_REFUSAL.format(reason="relay_probe_unreachable") in result.stderr, detail
    for other in ("relay_probe_mount_invisible", "relay_probe_timeout",
                  "relay_probe_bind_failed", "relay_docker_info_failed"):
        assert other not in result.stderr, detail

    # And the request on its own still admits nothing, from the shipped script.
    request_only = _gate_counted("0", "b1_product", "prove", env={"DOCKER_HOST": ABSENT_SOCKET})
    assert request_only.returncode == 3
    assert request_only.stderr == RELAY_REFUSAL.format(reason="relay_socket_absent") + "\n"


def test_relay_proof_accepts_only_a_verified_host_network_probe(
    tmp_path: Path, clean_probe_census
):
    """FP-RELAY-4: the whole procedure, its closed reasons, and its cleanup."""
    region = _relay_region()

    accepted = _run_region(
        "\n".join((
            "relay_prove",
            'echo "rc=$?"',
            'echo "probe_dir=${probe_dir:-unset}"',
            'echo "probe_id=${probe_id:-unset}"',
        )),
        env={"TMPDIR": str(tmp_path)}, timeout=600,
    )
    detail = accepted.stdout + accepted.stderr
    assert "rc=0" in accepted.stdout, detail
    assert accepted.returncode == 0, detail
    # design rev 0.3 §3.4: the client's own stdout is dropped, so the proof
    # prints nothing of its own -- these three echoes are the whole of it, and
    # no `127.0.0.1:<port> - accepting connections` line can sit ahead of the
    # §3.5 preflight text.
    printed = accepted.stdout.splitlines()
    assert len(printed) == 3, printed
    assert printed[0] == "rc=0", printed
    assert printed[1].startswith("probe_dir=") and printed[2].startswith("probe_id="), printed
    assert "accepting connections" not in accepted.stdout, printed
    probe_dir = accepted.stdout.split("probe_dir=")[1].splitlines()[0]
    probe_id = accepted.stdout.split("probe_id=")[1].splitlines()[0]
    assert probe_dir.startswith(str(tmp_path)), detail
    assert not Path(probe_dir).exists(), "the proof left its mktemp directory behind"
    assert len(probe_id) == 16 and re.fullmatch(r"[0-9a-f]{16}", probe_id), probe_id

    # A sentinel that cannot match: the mount check is what it is named for.
    blind = region.replace(
        'if [ "$mount_out" != visible ]; then', 'if [ "$mount_out" != visible-no ]; then', 1
    )
    assert blind != region, "the mount check no longer compares against `visible`"
    invisible = _run_region(
        "relay_prove", region=blind, env={"TMPDIR": str(tmp_path)}, timeout=600
    )
    assert invisible.returncode == 3, invisible.stdout + invisible.stderr
    assert invisible.stderr == (
        RELAY_REFUSAL.format(reason="relay_probe_mount_invisible") + "\n"
        + "integration-test.sh: the mktemp directory was not visible to the daemon "
        "through its bind mount; set TMPDIR to a directory the host daemon can see.\n"
    ), invisible.stderr

    # An image that is not local: refuse, say so, and start no PostgreSQL.
    absent = region.replace(
        "image inspect postgres:16-alpine", "image inspect postgres:relay-absent", 1
    )
    assert absent != region
    missing = _run_region(
        "relay_prove", region=absent, env={"TMPDIR": str(tmp_path)}, timeout=600
    )
    assert missing.returncode == 3, missing.stdout + missing.stderr
    assert missing.stderr == (
        RELAY_REFUSAL.format(reason="relay_probe_image_absent") + "\n"
        + IMAGE_ABSENT_SECOND_LINE + "\n"
    ), missing.stderr
    assert _probe_containers() == [], "the image-absent path started a container"

    not_unix = _run_region(
        "relay_prove", env={"DOCKER_HOST": "tcp://127.0.0.1:2375", "TMPDIR": str(tmp_path)}
    )
    assert not_unix.returncode == 3
    assert not_unix.stderr == RELAY_REFUSAL.format(reason="relay_socket_not_unix") + "\n"

    # Static pins: the shape the live outcome above depends on.
    server = _shell_function(region, "relay_probe_server")
    client = _shell_function(region, "relay_probe_client")
    assert "  --network host \\\n" in server and "  --network host \\\n" in client
    assert "listen_addresses=127.0.0.1" in server
    assert "--publish" not in server and " -p " not in server
    assert "pg_isready" in client
    assert '      *"$listen_line"*"$ready_line"*) ready=1; break ;;' in region
    assert '      *"$ready_line"*) ready=1; break ;;' not in region
    assert "deadline=$((SECONDS + 20))" in region
    log_reads = [
        line for line in region.splitlines()
        if "docker logs" in line and not line.strip().startswith("#")
    ]
    assert len(log_reads) == 1, log_reads
    assert "|" not in log_reads[0] and "grep" not in log_reads[0], log_reads[0]
    cleanup = _shell_function(region, "relay_probe_cleanup")
    assert "/usr/bin/docker rm -f" in cleanup
    assert f'/usr/bin/docker ps -aq --filter "label={PROBE_LABEL_KEY}=' in cleanup
    assert (
        "/usr/bin/docker version --format '{{.Server.Version}}' 2>/dev/null"
        in _shell_function(region, "relay_print_preflight")
    )


def test_relay_non_admitted_targets_keep_the_legacy_refusal(tmp_path: Path):
    """FP-RELAY-5: `prove` changes nothing for a target this proof cannot cover."""
    names = _argument_case_targets()
    assert set(names) - set(ADMITTED_TARGETS) == set(NON_ADMITTED_TARGETS)
    assert set(names) & set(ADMITTED_TARGETS) == set(ADMITTED_TARGETS)

    quiet = tmp_path / "quiet"
    quiet_log = _shim(quiet, "docker")
    for name in sorted(set(names) - set(ADMITTED_TARGETS)):
        result = _gate_counted("0", name, "prove", env=_path_with(quiet))
        detail = f"{name}: rc={result.returncode}\n{result.stdout}{result.stderr}"
        assert result.returncode == 3, detail
        assert result.stderr.startswith(LEGACY_FIRST_LINE), detail
        assert "relay override" not in result.stderr, detail
    assert not quiet_log.exists(), quiet_log.read_text(encoding="utf-8")

    # Admission is what refuses them: widen it and `py` stops taking that path.
    region = _relay_region()
    widened = region.replace(
        "    preflight|b1_product) return 0 ;;",
        "    *) return 0 ;;", 1,
    )
    assert widened != region, "the admitted `case` is no longer spelled as declared"
    leaked = _gate_counted(
        "0", "py", "prove", region=widened,
        env={**_path_with(quiet), "DOCKER_HOST": ABSENT_SOCKET},
    )
    assert leaked.returncode == 3
    assert leaked.stderr == RELAY_REFUSAL.format(reason="relay_socket_absent") + "\n"


def test_relay_successful_proof_reaches_preflight_ok_without_changing_b1(tmp_path: Path):
    """FP-RELAY-6: after the proof, the script says so and the targets are untouched."""
    launcher = _launcher_text()
    copy_root = tmp_path / "copy"
    (copy_root / "scripts").mkdir(parents=True)
    copy = copy_root / "scripts" / "integration-test.sh"

    stubbed = launcher
    for name, stub_body in (("relay_address_count", "  echo 0"), ("relay_prove", "  return 0")):
        original = _shell_function(_relay_region(launcher), name)
        stubbed = stubbed.replace(original, f"{name}() {{\n{stub_body}\n}}\n", 1)
    assert stubbed != launcher
    # The copy forces the two inputs of the decision and nothing else: its proof
    # is a `return 0`, so what this test reads is the continuation, not a proof.
    stub_region = _relay_region(stubbed)
    assert _shell_function(stub_region, "relay_prove") == "relay_prove() {\n  return 0\n}\n"
    assert _shell_function(stub_region, "relay_address_count") == (
        "relay_address_count() {\n  echo 0\n}\n"
    )
    copy.write_text(stubbed, encoding="utf-8")
    copy.chmod(0o755)

    env = dict(os.environ, DBAGENT_DOCKER_RELAY="prove")
    result = subprocess.run(
        ["bash", str(copy), "preflight"], capture_output=True, text=True,
        cwd=copy_root, env=env, timeout=300,
    )
    detail = result.stdout + result.stderr
    assert result.returncode == 0, detail
    printed = result.stdout.splitlines()
    for line in (
        "integration-test.sh: preflight OK (relay override)",
        "  relay proof         : host-network reachability verified",
        "  admitted targets    : preflight b1_product",
    ):
        assert line in printed, f"{line!r} not in {printed}"
    assert "outside the sandbox" not in result.stdout, detail

    # The shipped script is not the stub, and this slice moved none of B1's work.
    shipped = _relay_region()
    shipped_prove = _shell_function(shipped, "relay_prove")
    assert shipped_prove != "relay_prove() {\n  return 0\n}\n"
    assert "if ! relay_probe_client; then" in shipped_prove
    assert "pg_isready" in _shell_function(shipped, "relay_probe_client")
    assert _shell_function(shipped, "relay_address_count") != (
        "relay_address_count() {\n  echo 0\n}\n"
    )
    assert 'run_step "B1 product promise (on-demand, gating)" b1_product' in launcher
    assert "    --network host \\\n" in launcher
    assert 'B1_RUN_DIR="$(mktemp -d -t dbagent-b1-XXXXXXXXXX)"' in launcher


def test_relay_invalid_request_value_exits_3(tmp_path: Path):
    """FP-RELAY-7: anything but the exact word, on a target that could have run."""
    quiet = tmp_path / "quiet"
    quiet_log = _shim(quiet, "docker")
    for target, request in (("b1_product", "1"), ("preflight", "yes")):
        result = _gate_counted("0", target, request, env=_path_with(quiet))
        detail = f"{target}/{request}: {result.stdout}{result.stderr}"
        assert result.returncode == 3, detail
        assert result.stderr == RELAY_REFUSAL.format(reason="relay_request_invalid") + "\n", detail
    assert not quiet_log.exists(), quiet_log.read_text(encoding="utf-8")

    ok_dir = tmp_path / "docker-ok"
    _shim(ok_dir, "docker", stdout="28.0.0")
    legacy = _gate_counted("2", "b1_product", "not-prove", env=_path_with(ok_dir))
    assert "rc=0" in legacy.stdout, legacy.stdout + legacy.stderr
    assert "PREFLIGHT_MODE=legacy" in legacy.stdout
    assert "relay_request_invalid" not in legacy.stderr
