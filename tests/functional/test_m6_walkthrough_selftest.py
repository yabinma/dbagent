"""FP-M6-19 + FP-SW-12: the real-cluster walkthrough driver's own evidence.

The historical case (`--self-test` end to end against the synthetic harness) is
unchanged. `test_walkthrough_two_phase_witnesses_pending_credentials` adds
design.md §11.2.3 E.5's twenty bullets / thirty-seven subtests: the two-phase
witness, the hardened bootstrap-token handoff, the `renameat2(RENAME_NOREPLACE)`
FFI contract, and every refusal (R1-R5, F1-F2).

The driver is exercised through `main()` **in process**, which is what lets the
fake admin API be blocked on `threading.Event`s -- so the "the destination is
never observable incomplete" case is proven by synchronization rather than by a
sleep.
"""
from __future__ import annotations

import errno
import importlib.util
import json
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tests/e2e/manual/real_cluster_walkthrough.py"

BLOCK_TIMEOUT = 30.0
PLATFORM_KEY = "presto-walkthrough"


@pytest.fixture()
def wt(monkeypatch):
    """A freshly imported driver module with its process-local seams cleared."""
    spec = importlib.util.spec_from_file_location("real_cluster_walkthrough", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module.SELFTEST_CALL_LOG.clear()
    module.SELFTEST_HOOKS.clear()
    module._PROCESS_AUTH_SESSION.clear()
    monkeypatch.chdir(REPO)
    return module



@pytest.fixture(autouse=True)
def _isolate_e2e_selftest_state(monkeypatch):
    """Each test starts without a leaked E2E_SELFTEST_STATE (review W1).

    Direct os.environ writes in this module used to leave the variable set for
    later cases; subprocess.run without env= then inherited it and flipped the
    historical FP-M6-19 harness into the wrong platform status.
    """
    monkeypatch.delenv("E2E_SELFTEST_STATE", raising=False)


def write_state(path: Path, *, credentials_installed=False, status_override=None) -> Path:
    path.write_text(
        json.dumps(
            {"credentials_installed": credentials_installed, "status_override": status_override}
        ),
        encoding="utf-8",
    )
    return path


def call_names(wt) -> list[str]:
    return [entry["name"] for entry in wt.SELFTEST_CALL_LOG]


def assert_no_token_in_output(wt, captured) -> None:
    """Cross-cutting: the token never reaches stdout, stderr or a log."""
    token = wt.SELFTEST_HOOKS.get("issued_token")
    if not token:
        return
    blob = captured.out + captured.err
    assert token not in blob
    for i in range(0, len(token) - 8 + 1):
        assert token[i : i + 8] not in blob, f"an 8-character slice of the token leaked: {token[i:i + 8]}"


def run_driver(wt, capsys, argv: list[str]) -> tuple[int, "object"]:
    rc = wt.main(argv)
    captured = capsys.readouterr()
    assert_no_token_in_output(wt, captured)
    return rc, captured


def find_key(obj, key: str) -> bool:
    """Is there a key named `key` anywhere in the object tree?"""
    if isinstance(obj, dict):
        return key in obj or any(find_key(v, key) for v in obj.values())
    if isinstance(obj, list):
        return any(find_key(v, key) for v in obj)
    return False


def find_value(obj, value: str) -> bool:
    if isinstance(obj, dict):
        return any(find_value(v, value) for v in obj.values())
    if isinstance(obj, list):
        return any(find_value(v, value) for v in obj)
    return obj == value


def phase_one_argv(out: Path, token_out: Path, state: Path, **extra) -> list[str]:
    argv = [
        "--self-test",
        "--phase",
        "pre-credentials",
        "--out",
        str(out),
        "--token-out",
        str(token_out),
        "--pending-timeout",
        extra.pop("pending_timeout", "10"),
        "--poll-interval",
        "0.05",
    ]
    for key, value in extra.items():
        argv.extend([f"--{key.replace('_', '-')}", value])
    _ = state
    return argv


# --------------------------------------------------------------------------
# The historical case: --self-test end to end (FP-M6-19), unchanged.
# --------------------------------------------------------------------------


def test_walkthrough_self_test_against_fake_harness(tmp_path):
    out = tmp_path / "report.json"
    # Hermetic: never inherit a leaked E2E_SELFTEST_STATE from other cases.
    env = {k: v for k, v in os.environ.items() if k != "E2E_SELFTEST_STATE"}
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--self-test", "--out", str(out)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["failures"] == 0
    assert report["summary"]["tools_total"] >= 10
    assert report["registration"]["steps"]
    steps = [s["name"] for s in report["registration"]["steps"]]
    assert "start_probe_without_credentials" in steps
    assert "assert_online" in steps
    for t in report["tools"]:
        assert t["envelope_valid"] is True


# --------------------------------------------------------------------------
# FP-SW-12: the two-phase witness (E.5's twenty bullets / thirty-seven subtests)
# --------------------------------------------------------------------------


def _happy_phase_one(wt, tmp_path, capsys, monkeypatch, *, deployment="k8s", token_out=None, out=None):
    """Gate sees `created`, a token is issued, the probe then goes pending."""
    state = write_state(tmp_path / "state.json", status_override="created")
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    out = out or (tmp_path / "phase1.json")
    token_out = token_out or (tmp_path / "bootstrap-token.txt")

    # The operator deploying the credential-less probe, modelled deterministically:
    # once the token exists, the platform starts reporting pending_credentials.
    def on_issue(_state):
        write_state(state, status_override=None)

    wt.SELFTEST_HOOKS["on_issue"] = on_issue

    observations: list[tuple[bool, str | None, int | None]] = []

    def on_list(_state):
        if token_out.exists():
            observations.append(
                (
                    True,
                    token_out.read_text(encoding="utf-8"),
                    stat.S_IMODE(token_out.stat().st_mode),
                )
            )
        else:
            observations.append((False, None, None))

    wt.SELFTEST_HOOKS["on_list_platforms"] = on_list

    rc, captured = run_driver(
        wt,
        capsys,
        [
            "--self-test",
            "--phase",
            "pre-credentials",
            "--deployment",
            deployment,
            "--out",
            str(out),
            "--token-out",
            str(token_out),
            "--pending-timeout",
            "20",
            "--poll-interval",
            "0.02",
        ],
    )
    return rc, captured, out, token_out, state, observations


def _happy_phase_two(wt, tmp_path, capsys, *, resume, state, deployment="k8s", token_out=None):
    write_state(state, credentials_installed=True)
    argv = [
        "--self-test",
        "--phase",
        "post-credentials",
        "--deployment",
        deployment,
        "--resume",
        str(resume),
        "--out",
        str(tmp_path / "complete.json"),
        "--online-timeout",
        "20",
        "--poll-interval",
        "0.02",
    ]
    if token_out is not None:
        argv.extend(["--token-out", str(token_out)])
    rc, captured = run_driver(wt, capsys, argv)
    return rc, captured, tmp_path / "complete.json"


def test_walkthrough_two_phase_witnesses_pending_credentials(wt, tmp_path, capsys, monkeypatch):
    """E.5 bullet 1: the happy path, driven through main() twice."""
    rc, _cap, artifact, token_out, state, _obs = _happy_phase_one(wt, tmp_path, capsys, monkeypatch)
    assert rc == 0
    phase1 = json.loads(artifact.read_text(encoding="utf-8"))
    assert phase1["phase"] == "pre-credentials"
    assert phase1["registration"]["pending_credentials_witnessed"] is True
    assert phase1["registration"]["mode"] == "two_phase"
    assert phase1["registration"]["gate_status"] == "created"
    assert token_out.exists()

    rc2, _cap2, complete = _happy_phase_two(wt, tmp_path, capsys, resume=artifact, state=state)
    assert rc2 == 0
    report = json.loads(complete.read_text(encoding="utf-8"))
    assert report["phase"] == "complete"
    assert report["registration"]["pending_credentials_witnessed"] is True
    names = [s["name"] for s in report["registration"]["steps"]]
    assert names == [
        "create_platform",
        "issue_bootstrap_token",
        "start_probe_without_credentials",
        "install_credentials",
        "assert_online",
    ]
    by_name = {s["name"]: s for s in report["registration"]["steps"]}
    assert (
        by_name["assert_online"]["observed_at"]
        > by_name["start_probe_without_credentials"]["observed_at"]
    ), "a transition is two observations in an order"
    assert report["tools"], "phase 2 ran no tools"
    assert report["summary"]["failures"] == 0
    assert report["started_at"] == phase1["started_at"], "phase 1's start must survive the merge"


def test_deployment_flag_reaches_create_platform(wt, tmp_path, capsys, monkeypatch):
    """E.5 bullet 2."""
    rc, _cap, artifact, _tok, _state, _obs = _happy_phase_one(
        wt, tmp_path, capsys, monkeypatch, deployment="swarm"
    )
    assert rc == 0
    bodies = [e["body"] for e in wt.SELFTEST_CALL_LOG if e["name"] == "create_platform"]
    assert bodies and bodies[0]["deployment"] == "swarm"
    report = json.loads(artifact.read_text(encoding="utf-8"))
    assert report["deployment"] == "swarm"


def test_token_handoff_precedes_polling(wt, tmp_path, capsys, monkeypatch):
    """E.5 bullet 3, asserted two ways (design review D1)."""
    rc, _cap, _artifact, token_out, _state, observations = _happy_phase_one(wt, tmp_path, capsys, monkeypatch)
    assert rc == 0
    names = call_names(wt)
    issue_index = names.index("issue_bootstrap_token")
    get_indexes = [i for i, n in enumerate(names) if n == "GET /platforms"]
    assert get_indexes[0] < issue_index, "the admissibility gate must precede the token call"
    assert issue_index < get_indexes[1], "the token must be handed off before polling starts"

    # Independently of the call log: on the first poll the file was already
    # complete, at mode 0600.
    present, content, mode = observations[1]
    assert present is True
    assert content == wt.SELFTEST_HOOKS["issued_token"]
    assert mode == 0o600
    assert stat.S_IMODE(token_out.stat().st_mode) == 0o600


def test_reports_carry_no_raw_token(wt, tmp_path, capsys, monkeypatch):
    """E.5 bullet 4."""
    rc, _cap, artifact, _tok, state, _obs = _happy_phase_one(wt, tmp_path, capsys, monkeypatch)
    assert rc == 0
    token = wt.SELFTEST_HOOKS["issued_token"]
    phase1 = json.loads(artifact.read_text(encoding="utf-8"))
    rc2, _cap2, complete = _happy_phase_two(wt, tmp_path, capsys, resume=artifact, state=state)
    assert rc2 == 0
    report = json.loads(complete.read_text(encoding="utf-8"))
    import hashlib

    want = "sha256:" + hashlib.sha256(token.encode()).hexdigest()
    for doc in (phase1, report):
        assert not find_key(doc, "bootstrap_token")
        assert not find_value(doc, token)
        assert doc["registration"]["bootstrap_token_issued"] is True
        assert doc["registration"]["bootstrap_token_sha256"] == want


def test_pending_credentials_at_the_gate_issues_nothing(wt, tmp_path, capsys, monkeypatch):
    """E.5 bullet 5."""
    state = write_state(tmp_path / "state.json")  # -> pending_credentials
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    out = tmp_path / "phase1.json"
    token_out = tmp_path / "bootstrap-token.txt"
    rc, _cap = run_driver(
        wt,
        capsys,
        [
            "--self-test",
            "--phase",
            "pre-credentials",
            "--out",
            str(out),
            "--token-out",
            str(token_out),
            "--pending-timeout",
            "5",
            "--poll-interval",
            "0.02",
        ],
    )
    assert rc == 0
    assert "issue_bootstrap_token" not in call_names(wt)
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["registration"]["gate_status"] == "pending_credentials"
    assert report["registration"]["bootstrap_token_issued"] is False
    assert not token_out.exists()


@pytest.mark.parametrize("variant", ["default-path", "custom-path", "already-gone"])
def test_phase_two_removes_the_token_file(wt, tmp_path, capsys, variant, monkeypatch):
    """E.5 bullet 6, x3."""
    custom = tmp_path / "custom-token.txt" if variant == "custom-path" else None
    rc, _cap, artifact, token_out, state, _obs = _happy_phase_one(
        wt, tmp_path, capsys, monkeypatch, token_out=custom
    )
    assert rc == 0
    if variant == "already-gone":
        token_out.unlink()
    rc2, _cap2, complete = _happy_phase_two(
        wt, tmp_path, capsys, resume=artifact, state=state, token_out=custom
    )
    assert rc2 == 0
    report = json.loads(complete.read_text(encoding="utf-8"))
    assert not token_out.exists()
    assert report["registration"]["token_file_removed"] is (variant != "already-gone")


@pytest.mark.parametrize("collision", ["destination", "staging"])
def test_token_out_refuses_to_overwrite_and_refuses_first(wt, tmp_path, capsys, collision, monkeypatch):
    """E.5 bullet 7, x2 (design review D1: the ordering is what is under test)."""
    state = write_state(tmp_path / "state.json", status_override="created")
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    token_out = tmp_path / "bootstrap-token.txt"
    victim = token_out if collision == "destination" else Path(f"{token_out}.staging")
    victim.write_bytes(b"pre-existing bytes")
    rc, captured = run_driver(
        wt,
        capsys,
        [
            "--self-test",
            "--phase",
            "pre-credentials",
            "--out",
            str(tmp_path / "phase1.json"),
            "--token-out",
            str(token_out),
            "--pending-timeout",
            "2",
            "--poll-interval",
            "0.02",
        ],
    )
    assert rc != 0
    assert "issue_bootstrap_token" not in call_names(wt), "a token was minted before the refusal"
    assert victim.read_bytes() == b"pre-existing bytes"
    assert not (tmp_path / "phase1.json").exists()
    if collision == "destination":
        assert "refusing to overwrite an existing token file" in captured.err
    else:
        assert "refusing to overwrite an existing staging file" in captured.err
        assert victim.exists(), "a staging file we do not own must not be deleted"


def test_destination_is_never_observable_incomplete(wt, tmp_path, capsys, monkeypatch):
    """E.5 bullet 8 (round-4 D1 / round-7 DW1): bounded synchronization, no sleeps."""
    state = write_state(tmp_path / "state.json", status_override="created")
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    token_out = tmp_path / "bootstrap-token.txt"

    issue_blocked = threading.Event()
    release_issue = threading.Event()
    observed_during_block = threading.Event()
    observations: list[tuple[bool, bytes | None]] = []
    stop_watch = threading.Event()

    def on_issue(_state):
        write_state(state, status_override=None)
        issue_blocked.set()
        assert release_issue.wait(BLOCK_TIMEOUT), "the test never released the issue handler"

    wt.SELFTEST_HOOKS["on_issue"] = on_issue

    def watcher():
        assert issue_blocked.wait(BLOCK_TIMEOUT)
        while not stop_watch.is_set():
            if token_out.exists():
                try:
                    observations.append((True, token_out.read_bytes()))
                except OSError:
                    continue
            else:
                observations.append((False, None))
            observed_during_block.set()

    def releaser():
        # An observation inside the blocked window is a certainty rather than a
        # scheduling accident: the handler is released only after one is made.
        if not issue_blocked.wait(BLOCK_TIMEOUT):
            release_issue.set()
            return
        observed_during_block.wait(BLOCK_TIMEOUT)
        stop_watch.set()
        release_issue.set()

    watch_thread = threading.Thread(target=watcher, daemon=True)
    release_thread = threading.Thread(target=releaser, daemon=True)
    watch_thread.start()
    release_thread.start()

    try:
        rc, _captured = run_driver(
        wt,
        capsys,
        [
            "--self-test",
            "--phase",
            "pre-credentials",
            "--out",
            str(tmp_path / "phase1.json"),
            "--token-out",
            str(token_out),
            "--pending-timeout",
            "20",
            "--poll-interval",
            "0.02",
        ],
        )
    finally:
        stop_watch.set()
        release_issue.set()
        watch_thread.join(BLOCK_TIMEOUT)
        release_thread.join(BLOCK_TIMEOUT)

    assert rc == 0
    assert observed_during_block.is_set()
    assert observations, "no observation was recorded inside the blocked window"
    token = wt.SELFTEST_HOOKS["issued_token"].encode()
    for present, content in observations:
        assert (not present) or content == token, (
            "--token-out was observed present but incomplete: " f"{content!r}"
        )
    assert token_out.read_bytes() == token
    assert stat.S_IMODE(token_out.stat().st_mode) == 0o600


@pytest.mark.parametrize("injection", ["issue-500", "write", "flush", "fsync", "close", "publish"])
def test_every_persistence_failure_is_clean(wt, tmp_path, capsys, monkeypatch, injection):
    """E.5 bullet 9, x6."""
    state = write_state(tmp_path / "state.json", status_override="created")
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    token_out = tmp_path / "bootstrap-token.txt"
    staging = Path(f"{token_out}.staging")

    def on_issue(_state):
        write_state(state, status_override=None)
        if injection == "issue-500":
            return 500
        return None

    wt.SELFTEST_HOOKS["on_issue"] = on_issue

    def boom(*_args, **_kwargs):
        raise OSError(errno.EIO, "injected")

    if injection in ("write", "flush", "fsync", "close"):
        monkeypatch.setattr(wt, f"_stage_{injection}", boom)
    elif injection == "publish":
        monkeypatch.setattr(wt, "_publish_no_replace", boom)

    argv = [
        "--self-test",
        "--phase",
        "pre-credentials",
        "--out",
        str(tmp_path / "phase1.json"),
        "--token-out",
        str(token_out),
        "--pending-timeout",
        "5",
        "--poll-interval",
        "0.02",
    ]
    rc, captured = run_driver(wt, capsys, argv)
    assert rc != 0
    assert not token_out.exists(), "--token-out survived a failed run"
    assert not staging.exists(), "the staging file survived a failed run"
    assert not (tmp_path / "phase1.json").exists()
    if injection != "issue-500":
        assert "WAS issued and could not be saved" in captured.err

    # An immediate re-run succeeds: nothing was left to collide with.
    # undo() also clears setenv; re-pin the self-test state for the re-run.
    monkeypatch.undo()
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    wt.SELFTEST_HOOKS.pop("on_issue", None)
    write_state(state, status_override="created")
    wt.SELFTEST_HOOKS["on_issue"] = lambda _s: write_state(state, status_override=None)
    rc2, _captured2 = run_driver(wt, capsys, argv)
    assert rc2 == 0
    assert token_out.exists()


def test_mid_run_competitor_cannot_be_clobbered(wt, tmp_path, capsys, monkeypatch):
    """E.5 bullet 10 (round-5 D1): the only case that separates
    RENAME_NOREPLACE from check-then-os.rename."""
    state = write_state(tmp_path / "state.json", status_override="created")
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    token_out = tmp_path / "bootstrap-token.txt"
    staging = Path(f"{token_out}.staging")
    barrier = threading.Event()
    at_publish = threading.Event()
    real_publish = wt._publish_no_replace

    def blocking_publish(src, dest):
        at_publish.set()
        assert barrier.wait(BLOCK_TIMEOUT), "the test never released the publish barrier"
        return real_publish(src, dest)

    monkeypatch.setattr(wt, "_publish_no_replace", blocking_publish)
    wt.SELFTEST_HOOKS["on_issue"] = lambda _s: write_state(state, status_override=None)

    def competitor():
        assert at_publish.wait(BLOCK_TIMEOUT)
        token_out.write_bytes(b"a competing secret")
        barrier.set()

    thread = threading.Thread(target=competitor, daemon=True)
    thread.start()
    try:
        rc, captured = run_driver(
            wt,
            capsys,
            [
                "--self-test",
                "--phase",
                "pre-credentials",
                "--out",
                str(tmp_path / "phase1.json"),
                "--token-out",
                str(token_out),
                "--pending-timeout",
                "5",
                "--poll-interval",
                "0.02",
            ],
        )
    finally:
        barrier.set()
        thread.join(BLOCK_TIMEOUT)

    assert rc != 0
    assert token_out.read_bytes() == b"a competing secret", "the competitor was clobbered"
    assert not staging.exists()
    assert "refusing to overwrite an existing token file" in captured.err


def test_fail_closed_when_no_replace_is_unsupported(wt, tmp_path, capsys, monkeypatch):
    """E.5 bullet 10's ENOSYS sub-case."""
    state = write_state(tmp_path / "state.json", status_override="created")
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    token_out = tmp_path / "bootstrap-token.txt"
    monkeypatch.setattr(wt, "_load_libc", lambda: _FakeLibc(errno.ENOSYS))
    wt.SELFTEST_HOOKS["on_issue"] = lambda _s: write_state(state, status_override=None)
    rc, captured = run_driver(
        wt,
        capsys,
        [
            "--self-test",
            "--phase",
            "pre-credentials",
            "--out",
            str(tmp_path / "phase1.json"),
            "--token-out",
            str(token_out),
            "--pending-timeout",
            "5",
            "--poll-interval",
            "0.02",
        ],
    )
    assert rc != 0
    assert "atomic no-replace rename unavailable" in captured.err
    assert not Path(f"{token_out}.staging").exists()
    assert not token_out.exists()


# --- the FFI contract itself (E.5's five sub-cases, calling the helper directly)


class _Spy:
    def __init__(self, result=-1):
        self.calls = 0
        self.result = result
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        self.calls += 1
        return self.result


class _FakeLibc:
    """A libc whose renameat2 always fails with a chosen errno."""

    def __init__(self, err: int):
        import ctypes

        self._ctypes = ctypes
        self._err = err
        self.renameat2 = _Spy()
        original = self.renameat2

        def failing(*args):
            original.calls += 1
            ctypes.set_errno(err)
            return -1

        failing.argtypes = None
        failing.restype = None
        self.renameat2 = failing
        self.syscall = _Spy()


class _NoWrapperLibc:
    """A libc without the glibc renameat2 wrapper, forwarding syscall."""

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        if name == "renameat2":
            raise AttributeError(name)
        return getattr(self._real, name)


def test_ffi_native_success_and_native_eexist(wt, tmp_path):
    """FFI sub-case 1: the declared ABI meets the real kernel."""
    if sys.platform != "linux":
        pytest.skip("renameat2 is Linux-only; CI is Linux")
    staging = tmp_path / "a.staging"
    dest = tmp_path / "a"
    staging.write_bytes(b"token-one")
    wt._publish_no_replace(str(staging), str(dest))
    assert dest.read_bytes() == b"token-one"
    assert not staging.exists()

    staging.write_bytes(b"token-two")
    with pytest.raises(wt.TokenFileCollision) as excinfo:
        wt._publish_no_replace(str(staging), str(dest))
    assert "refusing to overwrite an existing token file" in str(excinfo.value)
    assert dest.read_bytes() == b"token-one", "the existing bytes were replaced"


def test_ffi_missing_glibc_wrapper_falls_back_to_raw_syscall(wt, tmp_path, monkeypatch):
    """FFI sub-case 2: the glibc-2.28 fallback is wired, not merely described."""
    if sys.platform != "linux":
        pytest.skip("renameat2 is Linux-only; CI is Linux")
    real = wt._load_libc()
    monkeypatch.setattr(wt, "_load_libc", lambda: _NoWrapperLibc(real))
    staging = tmp_path / "a.staging"
    dest = tmp_path / "a"
    staging.write_bytes(b"token-syscall")
    wt._publish_no_replace(str(staging), str(dest))
    assert dest.read_bytes() == b"token-syscall"
    assert not staging.exists()


def test_ffi_unlisted_architecture_fails_closed(wt, tmp_path, monkeypatch):
    """FFI sub-case 3."""
    real = wt._load_libc()
    monkeypatch.setattr(wt, "_load_libc", lambda: _NoWrapperLibc(real))
    monkeypatch.setattr(wt._platform, "machine", lambda: "sparc64")
    staging = tmp_path / "a.staging"
    dest = tmp_path / "a"
    staging.write_bytes(b"tok")
    with pytest.raises(wt.UnsupportedPlatform) as excinfo:
        wt._publish_no_replace(str(staging), str(dest))
    assert "unsupported_platform" in str(excinfo.value)
    assert not dest.exists()


def test_ffi_non_linux_gate_precedes_every_native_call(wt, tmp_path, monkeypatch):
    """FFI sub-case 4 (round-7 D1 / review W1): on XNU, syscall 316 is aio_cancel.

    The Linux platform gate must run strictly before ``platform.machine()`` and
    before any libc load — the architecture table is Linux-specific.
    """
    spy_libc = _FakeLibc(errno.EEXIST)
    spy_libc.renameat2 = _Spy()
    loader_calls: list[int] = []
    machine_calls: list[int] = []

    def loader():
        loader_calls.append(1)
        return spy_libc

    def machine_spy():
        machine_calls.append(1)
        return "x86_64"

    monkeypatch.setattr(wt, "_load_libc", loader)
    monkeypatch.setattr(wt.sys, "platform", "darwin")
    monkeypatch.setattr(wt._platform, "machine", machine_spy)
    staging = tmp_path / "a.staging"
    dest = tmp_path / "a"
    staging.write_bytes(b"tok")
    with pytest.raises(wt.UnsupportedPlatform) as excinfo:
        wt._publish_no_replace(str(staging), str(dest))
    message = str(excinfo.value)
    assert "unsupported_platform" in message and "darwin" in message
    assert spy_libc.renameat2.calls == 0, "renameat2 was invoked on a non-Linux host"
    assert spy_libc.syscall.calls == 0, "syscall was invoked on a non-Linux host"
    assert not loader_calls, "libc was loaded before the platform gate"
    assert not machine_calls, "platform.machine() was called before the Linux platform gate"
    assert not dest.exists()


def test_ffi_generic_errno_reaches_its_own_branch(wt, tmp_path, monkeypatch):
    """FFI sub-case 5: the dispatch is a table, not `if EEXIST ... else`."""
    staging = tmp_path / "a.staging"
    dest = tmp_path / "a"
    for err, needle, forbidden in (
        (errno.EXDEV, "different filesystems", "refusing to overwrite"),
        (errno.EACCES, "permission denied", "unsupported_platform"),
    ):
        monkeypatch.setattr(wt, "_load_libc", lambda err=err: _FakeLibc(err))
        staging.write_bytes(b"tok")
        with pytest.raises(wt.PublishError) as excinfo:
            wt._publish_no_replace(str(staging), str(dest))
        message = str(excinfo.value)
        assert needle in message
        assert forbidden not in message
        assert not isinstance(excinfo.value, wt.TokenFileCollision)


# --- the five resume refusals R1-R5 ----------------------------------------


def _phase_two_argv(tmp_path, resume: str | None, **extra) -> list[str]:
    argv = [
        "--self-test",
        "--phase",
        "post-credentials",
        "--out",
        str(tmp_path / "complete.json"),
        "--online-timeout",
        "2",
        "--poll-interval",
        "0.02",
    ]
    if resume is not None:
        argv.extend(["--resume", resume])
    for key, value in extra.items():
        argv.extend([f"--{key.replace('_', '-')}", value])
    return argv


def test_r1_phase_two_without_resume(wt, tmp_path, capsys, monkeypatch):
    write_state(tmp_path / "state.json", credentials_installed=True)
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(tmp_path / "state.json"))
    rc, captured = run_driver(wt, capsys, _phase_two_argv(tmp_path, None))
    assert rc != 0
    assert "requires --resume" in captured.err


@pytest.mark.parametrize("kind", ["missing", "invalid-json"])
def test_r2_resume_unreadable_or_unparseable(wt, tmp_path, capsys, kind, monkeypatch):
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(write_state(tmp_path / "state.json")))
    path = tmp_path / "artifact.json"
    if kind == "invalid-json":
        path.write_text("{not json", encoding="utf-8")
    rc, captured = run_driver(wt, capsys, _phase_two_argv(tmp_path, str(path)))
    assert rc != 0
    assert ("cannot be read" in captured.err) or ("not valid JSON" in captured.err)


def _artifact(tmp_path, **overrides) -> Path:
    doc = {
        "phase": "pre-credentials",
        "deployment": "k8s",
        "platform_key": PLATFORM_KEY,
        "registration": {"pending_credentials_witnessed": True, "steps": []},
    }
    doc.update(overrides)
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_r3_resume_of_a_completed_artifact(wt, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(write_state(tmp_path / "state.json")))
    path = _artifact(tmp_path, phase="complete")
    rc, captured = run_driver(wt, capsys, _phase_two_argv(tmp_path, str(path)))
    assert rc != 0
    assert "not 'pre-credentials'" in captured.err


@pytest.mark.parametrize(
    "field,value,needle",
    [
        ("platform_key", "somewhere-else", "is for platform 'somewhere-else'"),
        ("deployment", "swarm", "is for deployment 'swarm'"),
    ],
)
def test_r4_resume_of_a_different_run(wt, tmp_path, capsys, field, value, needle, monkeypatch):
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(write_state(tmp_path / "state.json")))
    path = _artifact(tmp_path, **{field: value})
    rc, captured = run_driver(wt, capsys, _phase_two_argv(tmp_path, str(path)))
    assert rc != 0
    assert needle in captured.err


@pytest.mark.parametrize("witness", ["false", "absent"])
def test_r5_resume_without_the_witness(wt, tmp_path, capsys, witness, monkeypatch):
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(write_state(tmp_path / "state.json")))
    registration = {"steps": []}
    if witness == "false":
        registration["pending_credentials_witnessed"] = False
    path = _artifact(tmp_path, registration=registration)
    rc, captured = run_driver(wt, capsys, _phase_two_argv(tmp_path, str(path)))
    assert rc != 0
    assert "pending_credentials_witnessed" in captured.err


def test_r5_resume_with_malformed_registration_shape(wt, tmp_path, capsys, monkeypatch):
    """W3 / FP-SW-12: registration as a non-object is WalkthroughRefusal, not traceback."""
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(        write_state(tmp_path / "state.json", credentials_installed=True)
    ))
    path = _artifact(tmp_path, registration="malformed")
    complete = tmp_path / "complete.json"
    rc, captured = run_driver(wt, capsys, _phase_two_argv(tmp_path, str(path)))
    assert rc == 2, f"expected exit 2 (WalkthroughRefusal), got {rc}; err={captured.err!r}"
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out
    assert "AttributeError" not in captured.err
    assert "malformed registration" in captured.err or "pending_credentials_witnessed" in captured.err
    assert not complete.exists(), "a refused resume must not write an output artifact"


# --- F1 / F2 and the escalation's own regression ---------------------------


@pytest.mark.parametrize("status", ["online", "degraded", "offline"])
def test_f1_inadmissible_status_refuses_read_only(wt, tmp_path, capsys, status, monkeypatch):
    state = write_state(tmp_path / "state.json", status_override=status)
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    out = tmp_path / "phase1.json"
    token_out = tmp_path / "bootstrap-token.txt"
    rc, captured = run_driver(
        wt,
        capsys,
        [
            "--self-test",
            "--phase",
            "pre-credentials",
            "--out",
            str(out),
            "--token-out",
            str(token_out),
            "--pending-timeout",
            "2",
            "--poll-interval",
            "0.02",
        ],
    )
    assert rc != 0
    assert f"is '{status}'" in captured.err
    assert "PENDING_CREDENTIALS path cannot be witnessed" in captured.err
    assert not out.exists(), "a refusal wrote an artifact"
    assert not token_out.exists(), "a refusal wrote a token file"
    assert "issue_bootstrap_token" not in call_names(wt), "the refusal was not read-only"


def test_f2_pending_timeout_removes_the_issued_token_file(wt, tmp_path, capsys, monkeypatch):
    # `created` is admissible, so the run proceeds through the reservation, the
    # issue and the write, and then never reaches pending_credentials.
    state = write_state(tmp_path / "state.json", status_override="created")
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    out = tmp_path / "phase1.json"
    token_out = tmp_path / "bootstrap-token.txt"
    rc, captured = run_driver(
        wt,
        capsys,
        [
            "--self-test",
            "--phase",
            "pre-credentials",
            "--out",
            str(out),
            "--token-out",
            str(token_out),
            "--pending-timeout",
            "0.3",
            "--poll-interval",
            "0.05",
        ],
    )
    assert rc != 0
    assert "never reached 'pending_credentials'" in captured.err
    assert "created" in captured.err
    assert "issue_bootstrap_token" in call_names(wt), "the token was never minted"
    assert not out.exists()
    assert not token_out.exists(), "an unspent token was stranded on disk"


def test_phase_both_against_an_already_online_fake_still_fails(wt, tmp_path, capsys, monkeypatch):
    """The regression that started the escalation: it must fail."""
    state = write_state(tmp_path / "state.json", credentials_installed=True)
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    out = tmp_path / "both.json"
    rc, captured = run_driver(
        wt,
        capsys,
        [
            "--self-test",
            "--phase",
            "both",
            "--out",
            str(out),
            "--token-out",
            str(tmp_path / "bootstrap-token.txt"),
            "--pending-timeout",
            "1",
            "--online-timeout",
            "1",
            "--poll-interval",
            "0.02",
        ],
    )
    assert rc != 0
    assert "is 'online'" in captured.err
    assert not out.exists()


# --- Review regressions (C2, C3, C4) ----------------------------------------


def test_resume_with_planted_bootstrap_token_is_rejected(wt, tmp_path, capsys, monkeypatch):
    """C2: a resume artifact carrying a sentinel token must be REJECTED, not
    silently sanitized into the completed report."""
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(        write_state(tmp_path / "state.json", credentials_installed=True)
    ))
    sentinel = "SENTINEL-PLANTED-BOOTSTRAP-TOKEN-c2-regression"
    path = _artifact(
        tmp_path,
        registration={
            "pending_credentials_witnessed": True,
            "bootstrap_token_issued": True,
            "bootstrap_token": sentinel,
            "steps": [{"name": "create_platform", "ok": True, "bootstrap_token": sentinel}],
        },
    )
    complete = tmp_path / "complete.json"
    rc, captured = run_driver(
        wt,
        capsys,
        _phase_two_argv(tmp_path, str(path)),
    )
    assert rc != 0, "planted bootstrap_token must refuse phase 2"
    assert "forbidden" in captured.err.lower() or "bootstrap_token" in captured.err
    assert not complete.exists(), "a refused resume must not write a completed report"
    # The sentinel must not appear in any written artifact either.
    for p in tmp_path.glob("*.json"):
        if p.name == path.name:
            continue
        text = p.read_text(encoding="utf-8")
        assert sentinel not in text
        assert "bootstrap_token" not in text or p == path


def test_resume_with_top_level_planted_token_is_rejected(wt, tmp_path, capsys, monkeypatch):
    """C2: forbidden keys at any depth, including the top level, refuse."""
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(        write_state(tmp_path / "state.json", credentials_installed=True)
    ))
    path = _artifact(tmp_path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["bootstrap_token"] = "TOP-LEVEL-SENTINEL-TOKEN"
    path.write_text(json.dumps(doc), encoding="utf-8")
    rc, captured = run_driver(wt, capsys, _phase_two_argv(tmp_path, str(path)))
    assert rc != 0
    assert "forbidden" in captured.err.lower()
    assert not (tmp_path / "complete.json").exists()


def test_admissibility_gate_refuses_non_200_status_read(wt, tmp_path, capsys, monkeypatch):
    """C3: a failed status read must not be treated as 'created' (fail-closed)."""
    state = write_state(tmp_path / "state.json", status_override="created")
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    out = tmp_path / "phase1.json"
    token_out = tmp_path / "bootstrap-token.txt"

    # After create_platform, force every GET /platforms to look like a 500.
    original_build = wt._build_self_test_client

    def wrapping_build(platform_key):
        client = original_build(platform_key)
        real_get = client.get

        def get(url, **kwargs):
            if url.rstrip("/").endswith("/platforms") and "bootstrap-token" not in url:
                class _Bad:
                    status_code = 500

                    def json(self):
                        return {"error": "injected"}

                return _Bad()
            return real_get(url, **kwargs)

        client.get = get
        return client

    monkeypatch.setattr(wt, "_build_self_test_client", wrapping_build)
    rc, captured = run_driver(
        wt,
        capsys,
        [
            "--self-test",
            "--phase",
            "pre-credentials",
            "--out",
            str(out),
            "--token-out",
            str(token_out),
            "--pending-timeout",
            "2",
            "--poll-interval",
            "0.02",
        ],
    )
    assert rc != 0
    assert "could not be read" in captured.err or "refusing to issue" in captured.err
    assert "issue_bootstrap_token" not in call_names(wt), "token issued after a failed status read"
    assert not out.exists()
    assert not token_out.exists()


def test_admissibility_gate_refuses_missing_platform_status(wt, tmp_path, capsys, monkeypatch):
    """C3: a successful read that does not establish an admissible status refuses."""
    # Empty status (platform absent from a 200 list) used to default to "created".
    state = write_state(tmp_path / "state.json", status_override="created")
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))

    def force_empty_status(client, dashboard_url, headers, platform_key):
        return True, ""  # ok read, no status

    monkeypatch.setattr(wt, "_platform_status", force_empty_status)
    # create_platform still has to succeed for the gate to be reached; the
    # real create runs, then our patched status returns empty.
    out = tmp_path / "phase1.json"
    token_out = tmp_path / "bootstrap-token.txt"
    rc, captured = run_driver(
        wt,
        capsys,
        [
            "--self-test",
            "--phase",
            "pre-credentials",
            "--out",
            str(out),
            "--token-out",
            str(token_out),
            "--pending-timeout",
            "2",
            "--poll-interval",
            "0.02",
        ],
    )
    assert rc != 0
    assert "not 'created' or 'pending_credentials'" in captured.err or "unknown" in captured.err
    assert "issue_bootstrap_token" not in call_names(wt)
    assert not token_out.exists()


def test_create_platform_failure_refuses_before_token(wt, tmp_path, capsys, monkeypatch):
    """C3: a non-accepted create_platform response must refuse before any token call."""
    state = write_state(tmp_path / "state.json", status_override="created")
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    original_build = wt._build_self_test_client

    def wrapping_build(platform_key):
        client = original_build(platform_key)
        real_post = client.post

        def post(url, **kwargs):
            if url.rstrip("/").endswith("/platforms"):
                class _Bad:
                    status_code = 500

                    def json(self):
                        return {"error": "injected create failure"}

                return _Bad()
            return real_post(url, **kwargs)

        client.post = post
        return client

    monkeypatch.setattr(wt, "_build_self_test_client", wrapping_build)
    out = tmp_path / "phase1.json"
    token_out = tmp_path / "bootstrap-token.txt"
    rc, captured = run_driver(
        wt,
        capsys,
        [
            "--self-test",
            "--phase",
            "pre-credentials",
            "--out",
            str(out),
            "--token-out",
            str(token_out),
            "--pending-timeout",
            "2",
            "--poll-interval",
            "0.02",
        ],
    )
    assert rc != 0
    assert "create_platform" in captured.err
    assert "issue_bootstrap_token" not in call_names(wt)
    assert not token_out.exists()
    assert not out.exists()


def test_staging_unlink_failure_is_explicit_and_sanitizes(wt, tmp_path, capsys, monkeypatch):
    """C4: a failed staging unlink must not claim success or leave a raw token."""
    state = write_state(tmp_path / "state.json", status_override="created")
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    token_out = tmp_path / "bootstrap-token.txt"
    staging = Path(f"{token_out}.staging")

    real_unlink = os.unlink
    unlink_attempts: list[str] = []

    def flaky_unlink(path):
        path_s = str(path)
        unlink_attempts.append(path_s)
        if path_s.endswith(".staging"):
            # Leave the file in place so the failure is observable, then raise.
            raise OSError(errno.EPERM, "injected unlink failure")
        return real_unlink(path)

    monkeypatch.setattr(wt.os, "unlink", flaky_unlink)
    # Force a post-issue failure so the finally path must clean the staging file
    # that still holds the token.
    def boom(*_a, **_k):
        raise OSError(errno.EIO, "injected publish failure")

    monkeypatch.setattr(wt, "_publish_no_replace", boom)
    wt.SELFTEST_HOOKS["on_issue"] = lambda _s: write_state(state, status_override=None)

    rc, captured = run_driver(
        wt,
        capsys,
        [
            "--self-test",
            "--phase",
            "pre-credentials",
            "--out",
            str(tmp_path / "phase1.json"),
            "--token-out",
            str(token_out),
            "--pending-timeout",
            "5",
            "--poll-interval",
            "0.02",
        ],
    )
    assert rc != 0
    assert unlink_attempts, "cleanup never attempted to unlink the staging file"
    assert "could not remove" in captured.err or "sanitized" in captured.err
    # The raw token must not remain readable on disk.
    if staging.exists():
        content = staging.read_bytes()
        issued = wt.SELFTEST_HOOKS.get("issued_token", "")
        assert issued.encode() not in content, "raw token left on disk after failed unlink"
        assert content != issued.encode()
    assert not token_out.exists()


def test_f2_token_unlink_failure_is_explicit_and_sanitizes(wt, tmp_path, capsys, monkeypatch):
    """C4: F2 cleanup must not swallow unlink errors and leave the token file."""
    state = write_state(tmp_path / "state.json", status_override="created")
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(state))
    token_out = tmp_path / "bootstrap-token.txt"

    real_unlink = os.unlink
    # Allow staging cleanup during handoff; fail only on the final token path.
    def selective_unlink(path):
        path_s = str(path)
        if path_s == str(token_out):
            raise OSError(errno.EPERM, "injected token unlink failure")
        return real_unlink(path)

    monkeypatch.setattr(wt.os, "unlink", selective_unlink)
    # Keep the platform at `created` so the pending_credentials poll times out
    # after the token has been written (F2 path).
    rc, captured = run_driver(
        wt,
        capsys,
        [
            "--self-test",
            "--phase",
            "pre-credentials",
            "--out",
            str(tmp_path / "phase1.json"),
            "--token-out",
            str(token_out),
            "--pending-timeout",
            "0.3",
            "--poll-interval",
            "0.05",
        ],
    )
    assert rc != 0
    assert "never reached 'pending_credentials'" in captured.err
    assert "could not remove" in captured.err or "sanitized" in captured.err
    issued = wt.SELFTEST_HOOKS.get("issued_token", "")
    if token_out.exists():
        assert token_out.read_text(encoding="utf-8") != issued
        assert issued not in token_out.read_text(encoding="utf-8")
    else:
        # Sanitized-then-eventually-removed is also acceptable if a later path
        # succeeds; the critical property is the raw token is gone.
        pass


def test_remove_owned_secret_file_missing_is_noop(wt, tmp_path):
    """C4 helper: absence is success (operator already tidied up)."""
    missing = tmp_path / "already-gone.txt"
    wt._remove_owned_secret_file(str(missing), role="token file")  # must not raise


def test_remove_owned_secret_file_detects_stubborn_path(wt, tmp_path, monkeypatch):
    """C4 helper: unlink that reports success but leaves the file is still a failure."""
    path = tmp_path / "stubborn.txt"
    path.write_text("secret-token-value", encoding="utf-8")

    def pretend_unlink(_p):
        return None  # claims success without removing

    monkeypatch.setattr(wt.os, "unlink", pretend_unlink)
    with pytest.raises(wt.WalkthroughRefusal) as excinfo:
        wt._remove_owned_secret_file(str(path), role="token file")
    assert "still present after unlink" in str(excinfo.value)
    # Contents must have been sanitized.
    assert path.read_text(encoding="utf-8") != "secret-token-value"


def test_sanitize_secret_file_tolerates_missing_path(wt, tmp_path):
    """C4 helper: sanitize is best-effort and never raises."""
    wt._sanitize_secret_file(str(tmp_path / "no-such-file"))


def test_reconstruct_registration_allowlist_only(wt):
    """C2: reconstruction drops unknown keys and non-dict steps."""
    raw = {
        "mode": "two_phase",
        "pending_credentials_witnessed": True,
        "gate_status": "created",
        "bootstrap_token_issued": True,
        "bootstrap_token_sha256": "sha256:abc",
        "extra_planted": "must-drop",
        "steps": [
            {"name": "create_platform", "ok": True, "planted": 1},
            "not-a-dict",
        ],
        "auth": {"password_changed": True, "password": "drop-me"},
    }
    clean = wt._reconstruct_registration(raw)
    assert "extra_planted" not in clean
    assert clean["steps"] == [{"name": "create_platform", "ok": True}]
    assert clean["auth"] == {"password_changed": True}
    assert wt._reconstruct_registration("bad") == {}
    assert wt._reconstruct_steps("bad") == []
    assert wt._reconstruct_auth("bad") == {}


def test_reconstruct_resume_drops_summary_and_tools(wt):
    """C2: planted tools/summary never copy through."""
    artifact = {
        "phase": "pre-credentials",
        "deployment": "k8s",
        "platform_key": PLATFORM_KEY,
        "tools": [{"name": "planted"}],
        "summary": {"failures": 0, "bootstrap_token": "nope"},
        "registration": {"pending_credentials_witnessed": True, "steps": []},
        "unknown_top": True,
    }
    clean = wt._reconstruct_resume_artifact(artifact)
    assert clean["tools"] == []
    assert "summary" not in clean
    assert "unknown_top" not in clean
    assert clean["registration"]["pending_credentials_witnessed"] is True


def test_fdopen_failure_closes_fd_and_cleans_staging(wt, tmp_path, monkeypatch):
    """C4: os.fdopen failure must not leak the reserved staging fd/file."""
    token_out = tmp_path / "bootstrap-token.txt"
    staging = Path(f"{token_out}.staging")

    def boom_fdopen(*_a, **_k):
        raise OSError(errno.EMFILE, "injected fdopen failure")

    monkeypatch.setattr(wt.os, "fdopen", boom_fdopen)
    with pytest.raises(wt.WalkthroughRefusal) as excinfo:
        wt.handoff_bootstrap_token(
            issue=lambda: "should-not-issue",
            token_out=str(token_out),
            platform_key=PLATFORM_KEY,
            deadline_seconds=1,
        )
    message = str(excinfo.value)
    assert "issuing the bootstrap token failed" in message or "injected" in message
    assert not staging.exists(), "staging file leaked after fdopen failure"
    assert not token_out.exists()


def test_platform_status_unreadable_json_is_failed_read(wt):
    """C3: a 200 with unparseable JSON must not be treated as ok."""

    class _BadBody:
        status_code = 200

        def json(self):
            raise ValueError("not json")

    class _Client:
        def get(self, *_a, **_k):
            return _BadBody()

    ok, status = wt._platform_status(_Client(), "http://example", {}, PLATFORM_KEY)
    assert ok is False
    assert status == ""


def test_platform_status_absent_key_is_empty_not_created(wt):
    """C3: a 200 list without the platform key yields empty status (not 'created')."""

    class _Ok:
        status_code = 200

        def json(self):
            return {"items": [{"platform_key": "other", "status": "created"}]}

    class _Client:
        def get(self, *_a, **_k):
            return _Ok()

    ok, status = wt._platform_status(_Client(), "http://example", {}, PLATFORM_KEY)
    assert ok is True
    assert status == ""


def test_walkthrough_refusal_reraised_from_handoff(wt, tmp_path, monkeypatch):
    """WalkthroughRefusal from publish (e.g. collision) is not re-wrapped."""
    token_out = tmp_path / "bootstrap-token.txt"

    def refuse(*_a, **_k):
        raise wt.WalkthroughRefusal("injected refusal")

    monkeypatch.setattr(wt, "_publish_no_replace", refuse)
    with pytest.raises(wt.WalkthroughRefusal) as excinfo:
        wt.handoff_bootstrap_token(
            issue=lambda: "tok-value",
            token_out=str(token_out),
            platform_key=PLATFORM_KEY,
            deadline_seconds=1,
        )
    assert str(excinfo.value) == "injected refusal"
    assert not Path(f"{token_out}.staging").exists()


# --- Review round-three regressions (C1, C2, W1) ----------------------------


def test_phase_both_reuses_effective_password_after_change(tmp_path):
    """C1: `--phase both` with distinct old/new passwords must succeed.

    Phase one changes the password; phase two must not re-authenticate with
    the stale original. The fake login validates credentials, so a stale
    re-login is HTTP 401. Runs as a subprocess so the self-test harness
    (and its distinct SELF_TEST_* passwords) is exercised end-to-end without
    leftover E2E_SELFTEST_STATE from other cases.
    """
    out = tmp_path / "both.json"
    token_out = tmp_path / "bootstrap-token.txt"
    env = {k: v for k, v in os.environ.items() if k != "E2E_SELFTEST_STATE"}
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--self-test",
            "--phase",
            "both",
            "--out",
            str(out),
            "--token-out",
            str(token_out),
            "--pending-timeout",
            "10",
            "--online-timeout",
            "10",
            "--poll-interval",
            "0.02",
        ],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    report = json.loads(out.read_text(encoding="utf-8"))
    # E.3/E.4: --phase both is the single_process registration lifecycle
    # (pairs with two_phase asserted in test_walkthrough_two_phase_...).
    assert report["registration"]["mode"] == "single_process"
    assert report["registration"]["auth"]["password_changed"] is True
    assert report["summary"]["failures"] == 0
    # Report must never carry the effective password / session token.
    assert not find_key(report, "effective_password")
    assert not find_key(report, "password")
    # Load constants from the driver module without relying on the wt fixture.
    import importlib.util as _ilu

    spec = _ilu.spec_from_file_location("_wt_c1", SCRIPT)
    mod = _ilu.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    assert not find_value(report, mod.SELF_TEST_NEW_PASSWORD)
    assert not find_value(report, mod.SELF_TEST_ADMIN_PASSWORD)


def test_stale_password_login_is_rejected_by_fake(wt):
    """C1: self-test login validates credentials (adversarial case)."""
    client = wt._build_self_test_client(PLATFORM_KEY)
    # Fresh admin: must_change_password=true, password is SELF_TEST_ADMIN_PASSWORD.
    r = client.post(
        f"{wt.SELF_TEST_BASE_URL}/api/v1/auth/login",
        json={"username": "admin", "password": "wrong-password-not-the-real-one"},
    )
    assert r.status_code == 401
    assert r.json().get("error") == "invalid_credentials"
    # Correct password works.
    r_ok = client.post(
        f"{wt.SELF_TEST_BASE_URL}/api/v1/auth/login",
        json={"username": "admin", "password": wt.SELF_TEST_ADMIN_PASSWORD},
    )
    assert r_ok.status_code == 200
    # After change-password, the old password is invalid.
    token = r_ok.json()["token"]
    r_ch = client.post(
        f"{wt.SELF_TEST_BASE_URL}/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "old_password": wt.SELF_TEST_ADMIN_PASSWORD,
            "new_password": wt.SELF_TEST_NEW_PASSWORD,
        },
    )
    assert r_ch.status_code == 204
    r_stale = client.post(
        f"{wt.SELF_TEST_BASE_URL}/api/v1/auth/login",
        json={"username": "admin", "password": wt.SELF_TEST_ADMIN_PASSWORD},
    )
    assert r_stale.status_code == 401
    r_new = client.post(
        f"{wt.SELF_TEST_BASE_URL}/api/v1/auth/login",
        json={"username": "admin", "password": wt.SELF_TEST_NEW_PASSWORD},
    )
    assert r_new.status_code == 200
    assert r_new.json().get("must_change_password") is False


def test_empty_discovery_counts_as_failure_not_skip(wt):
    """C2: empty presto_list_queries / k8s_pods must fail dependents, not skip."""

    class _EmptyDiscoveryClient:
        def post(self, url, **kwargs):
            body = kwargs.get("json") or {}
            name = body.get("tool") or "unknown"
            args = body.get("args") or {}

            class _Resp:
                status_code = 200
                text = ""

                def json(self_inner):
                    data: object
                    if name == wt.QUERY_ID_TOOL:
                        data = []  # successful but empty discovery
                    elif name in wt.TARGET_TOOLS.values():
                        data = {"targets": []}
                    else:
                        data = {"self_test": True}
                    return {
                        "tool": name,
                        "args": args,
                        "platform_key": PLATFORM_KEY,
                        "probe_id": "empty-discovery",
                        "collected_at": wt._now(),
                        "exit_code": 0,
                        "truncated": False,
                        "redacted": False,
                        "data": data,
                    }

            return _Resp()

    tools = wt.execute_tools(
        execute_url="http://empty-discovery",
        platform_key=PLATFORM_KEY,
        tool_names=[
            "presto_list_queries",
            "k8s_pods",
            "presto_query_detail",
            "pod_logs",
        ],
        client=_EmptyDiscoveryClient(),
        deployment="k8s",
    )
    by_name = {t["name"]: t for t in tools}
    assert by_name["presto_list_queries"]["ok"] is True
    assert by_name["k8s_pods"]["ok"] is True
    for dependent in ("presto_query_detail", "pod_logs"):
        entry = by_name[dependent]
        assert entry.get("skipped") is not True, f"{dependent} must not be a neutral skip"
        assert entry["ok"] is False
        assert "no representative argument" in (entry.get("error") or entry.get("reason") or "")
    summary = wt._summarize(tools, {"steps": []})
    assert summary["tools_total"] == 4
    assert summary["tools_ok"] == 2
    assert summary["tools_skipped"] == 0
    assert summary["failures"] == 2, (
        f"empty discovery must produce nonzero failures, got {summary}"
    )


def test_empty_discovery_swarm_skips_only_k8s_pair(wt):
    """C2: deployment-kind skips stay neutral; empty discovery still fails."""

    class _EmptySwarmClient:
        def post(self, url, **kwargs):
            body = kwargs.get("json") or {}
            name = body.get("tool") or "unknown"
            args = body.get("args") or {}

            class _Resp:
                status_code = 200
                text = ""

                def json(self_inner):
                    data: object = []
                    if name == "swarm_tasks":
                        data = []
                    elif name == wt.QUERY_ID_TOOL:
                        data = []
                    return {
                        "tool": name,
                        "args": args,
                        "platform_key": PLATFORM_KEY,
                        "probe_id": "empty-swarm",
                        "collected_at": wt._now(),
                        "exit_code": 0,
                        "truncated": False,
                        "redacted": False,
                        "data": data,
                    }

            return _Resp()

    tools = wt.execute_tools(
        execute_url="http://empty-swarm",
        platform_key=PLATFORM_KEY,
        tool_names=[
            "presto_list_queries",
            "swarm_tasks",
            "presto_query_detail",
            "container_logs",
            "pod_logs",  # k8s-only: neutral skip
        ],
        client=_EmptySwarmClient(),
        deployment="swarm",
    )
    by_name = {t["name"]: t for t in tools}
    assert by_name["pod_logs"].get("skipped") is True
    assert by_name["presto_query_detail"].get("skipped") is not True
    assert by_name["presto_query_detail"]["ok"] is False
    assert by_name["container_logs"].get("skipped") is not True
    assert by_name["container_logs"]["ok"] is False
    summary = wt._summarize(tools, {"steps": []})
    assert summary["tools_skipped"] == 1
    assert summary["failures"] >= 2


def test_r2_resume_binary_artifact_is_named_refusal(wt, tmp_path, capsys, monkeypatch):
    """W1: non-UTF-8 resume exits 2 with WalkthroughRefusal, no traceback/artifact."""
    monkeypatch.setenv("E2E_SELFTEST_STATE", str(        write_state(tmp_path / "state.json", credentials_installed=True)
    ))
    path = tmp_path / "binary-resume.json"
    # Invalid UTF-8 sequence; read_text(encoding="utf-8") raises UnicodeDecodeError.
    path.write_bytes(b'{"phase": "pre-credentials", "x": "\xff\xfe binary"}')
    complete = tmp_path / "complete.json"
    rc, captured = run_driver(wt, capsys, _phase_two_argv(tmp_path, str(path)))
    assert rc == 2, f"expected exit 2, got {rc}; err={captured.err!r}"
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out
    assert "UnicodeDecodeError" not in captured.err
    assert "cannot be read" in captured.err
    assert not complete.exists(), "a refused resume must not write an output artifact"
