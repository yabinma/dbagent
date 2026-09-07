#!/usr/bin/env python3
"""Real-cluster walkthrough driver (FP-M6-19, FP-SW-12).

Two phases, because the PENDING_CREDENTIALS state the acceptance gate is about
is produced by an operator action the driver cannot perform: phase 1 hands the
one-time bootstrap token to the operator and then polls for the state a
credential-less probe produces; phase 2 resumes that artifact once the
credentials are installed (design.md §11.2.3 E).

Usage:
  # phase 1 -- leave running; deploy the probe WITHOUT credentials meanwhile
  python tests/e2e/manual/real_cluster_walkthrough.py \\
    --phase pre-credentials --deployment k8s --platform-key presto-prod \\
    --dashboard-url http://... --out phase1.json --token-out ./bootstrap-token.txt

  # phase 2 -- after installing the credentials Secret / Docker secret
  python tests/e2e/manual/real_cluster_walkthrough.py \\
    --phase post-credentials --resume phase1.json --deployment k8s \\
    --platform-key presto-prod --dashboard-url http://... \\
    --execute-url http://... --out walkthrough-report.json \\
    --token-out ./bootstrap-token.txt

  # single process (scripted operator only; --phase both is the default)
  python tests/e2e/manual/real_cluster_walkthrough.py --self-test
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import ctypes.util
import errno as _errno
import hashlib
import json
import os
import platform as _platform
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]

# --- test seams (design.md §11.2.3 E.5) -------------------------------------
# `--self-test` builds its fake admin API per invocation, so a two-phase
# self-test needs somewhere for the fake to record what it saw and somewhere
# for the test to reach into it. Both are process-local and only ever populated
# under `--self-test`.
SELFTEST_CALL_LOG: list[dict[str, Any]] = []
SELFTEST_HOOKS: dict[str, Any] = {}

# Transient same-process auth handoff for `--phase both` (review C1).
# Phase one may force a password change; phase two must not re-login with the
# stale original password. Secrets here are never written into the report.
_PROCESS_AUTH_SESSION: dict[str, str] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- Atomic no-replace publication of the bootstrap-token file --------------
# design.md §11.2.3 E.2 step 4d. `os.rename` is the wrong primitive: POSIX
# rename(2) SILENTLY REPLACES an existing destination, and a check in front of
# it is a separate operation, so a destination created in between is clobbered
# without a trace. Publication therefore uses a primitive that *is* the check.

AT_FDCWD = -100
RENAME_NOREPLACE = 1
# Linux syscall numbers. They are OS-specific -- on Apple XNU, 316 is
# aio_cancel -- so the platform gate below runs BEFORE this table is consulted.
SYS_RENAMEAT2 = {"x86_64": 316, "aarch64": 276}


class PublishError(RuntimeError):
    """Publication of the token file failed. Always fail-closed."""


class TokenFileCollision(PublishError):
    """The destination (or the staging path) already exists."""


class UnsupportedPlatform(PublishError):
    """No usable atomic no-replace primitive on this host."""


def _load_libc() -> Any:
    """Load libc with errno capture. A seam so tests can install spies."""
    return ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def _publish_no_replace(staging: str, dest: str) -> None:
    """Publish `staging` at `dest` atomically, refusing to replace anything.

    Returns None on success; raises a PublishError subclass otherwise. There is
    deliberately NO fallback to plain rename: silently degrading to a primitive
    that can clobber a competing secret is the failure this exists to prevent.
    """
    # (1a) The platform gate precedes ANY native call -- before CDLL, before a
    # symbol lookup, before platform.machine(), before the syscall table is
    # consulted (design.md §11.2.3 E.2 step 4d(1); review W1).
    if sys.platform != "linux":
        raise UnsupportedPlatform(
            f"unsupported_platform: atomic no-replace rename is unavailable on this "
            f"platform ({sys.platform}); the walkthrough requires Linux"
        )
    machine = _platform.machine()

    libc = _load_libc()
    # (1b) glibc's renameat2 wrapper exists only from glibc 2.28; this runs on
    # an operator's host, where no libc floor is declared.
    try:
        fn = getattr(libc, "renameat2")
    except AttributeError:
        fn = None

    src_b, dst_b = os.fsencode(staging), os.fsencode(dest)
    if fn is not None:
        # (3) ABI declaration: an undeclared ctypes function passes Python ints
        # as C int and would mis-marshal on some ABIs.
        fn.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        fn.restype = ctypes.c_int
        rc = fn(AT_FDCWD, src_b, AT_FDCWD, dst_b, RENAME_NOREPLACE)
    else:
        number = SYS_RENAMEAT2.get(machine)
        if number is None:
            raise UnsupportedPlatform(
                f"unsupported_platform: atomic no-replace rename is unavailable on this "
                f"platform ({sys.platform}/{machine}); the walkthrough requires Linux"
            )
        libc.syscall.argtypes = [
            ctypes.c_long,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        libc.syscall.restype = ctypes.c_long
        rc = libc.syscall(number, AT_FDCWD, src_b, AT_FDCWD, dst_b, RENAME_NOREPLACE)

    # (3) ctypes raises nothing on -1, so test the return value explicitly.
    if rc == 0:
        return
    # (2) errno is read ONLY immediately after a -1 return.
    err = ctypes.get_errno()

    # (4) Exhaustive dispatch; every branch fails closed with its own message.
    if err == _errno.EEXIST:
        raise TokenFileCollision(
            f"refusing to overwrite an existing token file {dest}: move or delete it and re-run"
        )
    if err in (_errno.ENOSYS, _errno.EINVAL):
        raise PublishError(
            f"atomic no-replace rename unavailable on {dest}'s filesystem; "
            "write --token-out to a local filesystem"
        )
    if err == _errno.EXDEV:
        raise PublishError(
            "--token-out and its .staging file are on different filesystems; "
            "choose a --token-out path whose directory is a single filesystem"
        )
    if err in (_errno.EACCES, _errno.EPERM):
        raise PublishError(f"cannot publish the token file to {dest}: permission denied")
    if err in (_errno.ENOENT, _errno.ENOTDIR):
        raise PublishError(f"{dest}'s directory disappeared during the run")
    if err == _errno.EROFS:
        raise PublishError(f"{dest} is on a read-only filesystem")
    if err in (_errno.ENOSPC, getattr(_errno, "EDQUOT", -1)):
        raise PublishError(f"no space to publish the token file to {dest}")
    raise PublishError(
        f"publishing the token file to {dest} failed: "
        f"{_errno.errorcode.get(err, 'errno')} ({err})"
    )


# The four staging-file operations are module-level seams so the self-test can
# inject a failure at each of them (design.md §11.2.3 E.5).
def _stage_write(handle: Any, token: str) -> None:
    handle.write(token.encode("utf-8"))


def _stage_flush(handle: Any) -> None:
    handle.flush()


def _stage_fsync(handle: Any) -> None:
    os.fsync(handle.fileno())


def _stage_close(handle: Any) -> None:
    handle.close()


class WalkthroughRefusal(RuntimeError):
    """A named refusal: the driver stops, non-zero, having changed nothing."""


def _sanitize_secret_file(path: str) -> None:
    """Overwrite a secret-bearing file we own so a failed unlink cannot leave it.

    Best-effort: if even truncation fails the caller still surfaces the original
    cleanup error. Never raises; the secret is zeroed when possible.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
    except OSError:
        return
    try:
        # A short overwrite is enough for a token-sized secret; the truncate
        # already zeroed the length for subsequent readers.
        os.write(fd, b"\x00" * 64)
        with contextlib.suppress(OSError):
            os.fsync(fd)
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


def _remove_owned_secret_file(path: str, *, role: str) -> None:
    """Unlink a secret file we own. Failures are explicit; contents are sanitized.

    Verifies absence after a successful unlink. On unlink failure, truncates/
    overwrites the file so a raw token is not left on disk, then raises.
    """
    if not os.path.exists(path):
        return
    try:
        os.unlink(path)
    except OSError as exc:
        _sanitize_secret_file(path)
        raise WalkthroughRefusal(
            f"could not remove {role} {path}: {exc}; contents were sanitized where possible"
        ) from None
    if os.path.exists(path):
        _sanitize_secret_file(path)
        raise WalkthroughRefusal(
            f"could not remove {role} {path}: file still present after unlink; "
            "contents were sanitized where possible"
        )


def handoff_bootstrap_token(
    *,
    issue: Any,
    token_out: str,
    platform_key: str,
    deadline_seconds: float,
) -> str:
    """§11.2.3 E.2 step 4: reserve, issue, write, publish, announce.

    Two invariants: the destination is reserved before the secret exists, and
    `--token-out` never exists in an incomplete state. Returns the raw token
    (which never reaches the report, stdout, stderr or any log).
    """
    staging = f"{token_out}.staging"

    # 4a -- reserve. The destination check is a fast-fail courtesy; the
    # no-overwrite guarantee itself lives in 4d, where it is a property of a
    # single syscall rather than of a check.
    if os.path.exists(token_out):
        raise WalkthroughRefusal(
            f"refusing to overwrite an existing token file {token_out}: move or delete it and re-run"
        )
    try:
        fd = os.open(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        # We do not own this staging file, so we must not delete it.
        raise WalkthroughRefusal(
            f"refusing to overwrite an existing staging file {staging}: a concurrent or "
            "crashed phase-1 run owns it; move or delete it and re-run"
        ) from None

    # os.fdopen transfers ownership of `fd` only on success. Keep both inside
    # the same try/finally so a failed fdopen cannot leak an open secret fd.
    handle: Any | None = None
    owned_fd: int | None = fd
    issued = False
    try:
        try:
            handle = os.fdopen(fd, "wb")
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(fd)
            owned_fd = None
            raise
        owned_fd = None  # ownership transferred to handle
        # 4b -- issue.
        token = issue()
        issued = True
        # 4c -- write and durably close.
        _stage_write(handle, token)
        _stage_flush(handle)
        _stage_fsync(handle)
        _stage_close(handle)
        handle = None
        # 4d -- publish with an atomic no-replace rename.
        _publish_no_replace(staging, token_out)
    except WalkthroughRefusal:
        raise
    except BaseException as exc:  # noqa: BLE001 -- every failure fails closed
        if issued:
            raise WalkthroughRefusal(
                f"{exc}; a bootstrap token WAS issued and could not be saved to {token_out} -- "
                "re-run phase 1: the platform has not registered, the gate re-admits it, and "
                "the fresh token replaces the stranded one"
            ) from None
        raise WalkthroughRefusal(f"issuing the bootstrap token failed: {exc}") from None
    finally:
        if handle is not None:
            with contextlib.suppress(OSError):
                handle.close()
        if owned_fd is not None:
            with contextlib.suppress(OSError):
                os.close(owned_fd)
        # Structural cleanup: no failure path leaves a staging file behind, and
        # a failed unlink is never silent (review C4).
        if os.path.exists(staging):
            _remove_owned_secret_file(staging, role="staging file")

    # 4e -- announce, to stderr, never the token value.
    print(
        f"bootstrap token for platform {platform_key} written to {token_out} (mode 0600); "
        f"deploy the probe WITHOUT platform credentials within {int(deadline_seconds)}s",
        file=sys.stderr,
    )
    return token


def _token_sha256(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def validate_envelope(obj: dict[str, Any]) -> bool:
    """Validate against the Toolpack envelope schema. Hard-fail if jsonschema missing."""
    schema_path = REPO / "schemas" / "tool_result_envelope.schema.json"
    if not schema_path.is_file():
        raise RuntimeError(f"envelope schema missing: {schema_path}")
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError(
            "jsonschema is required for envelope validation (install project test extras)"
        ) from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(obj, schema)
        return True
    except jsonschema.ValidationError:
        return False


def toolpack_tool_names() -> list[str]:
    names: list[str] = []
    for p in sorted((REPO / "probe/internal/toolpack/schemas").glob("*.schema.json")):
        data = json.loads(p.read_text(encoding="utf-8"))
        tools = data.get("tools") or {}
        names.extend(sorted(tools.keys()))
    # de-dupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _login(client: Any, dashboard_url: str, user: str, password: str) -> tuple[str, bool]:
    """POST /api/v1/auth/login. Returns (token, must_change_password)."""
    r = client.post(
        f"{dashboard_url.rstrip('/')}/api/v1/auth/login",
        json={"username": user, "password": password},
    )
    r.raise_for_status()
    body = r.json()
    token = body.get("access_token") or body.get("token")
    if not token:
        raise RuntimeError(f"login response missing token: {body}")
    return token, bool(body.get("must_change_password"))


def _change_password(
    client: Any, dashboard_url: str, token: str, old_password: str, new_password: str
) -> None:
    """POST /api/v1/auth/change-password (dashboard_api returns 204)."""
    r = client.post(
        f"{dashboard_url.rstrip('/')}/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={"old_password": old_password, "new_password": new_password},
    )
    if r.status_code not in (200, 204):
        detail = ""
        try:
            detail = json.dumps(r.json())
        except Exception:  # noqa: BLE001
            detail = str(getattr(r, "text", ""))[:200]
        raise RuntimeError(
            f"change-password failed: {r.status_code} {detail} "
            "(a fresh admin must clear must_change_password before any other "
            "endpoint; pass --new-admin-password if the current one is shorter "
            "than the server's password_min_length)"
        )


def authenticate(
    client: Any,
    dashboard_url: str,
    user: str,
    password: str,
    new_password: str | None = None,
) -> tuple[str, str, bool]:
    """Log in and clear the forced first-login password change if it is set.

    dashboard_api.auth answers 403 `password_change_required` on every
    endpoint except /auth/change-password while the flag is set (FP-M4-3),
    so this must happen before any other call. Returns
    (token, effective_password, changed).
    """
    token, must_change = _login(client, dashboard_url, user, password)
    if not must_change:
        return token, password, False
    effective = new_password or password
    _change_password(client, dashboard_url, token, password, effective)
    # Re-login with the effective password: the token is unchanged in
    # practice, but this proves the new credential works and that the
    # flag is really cleared.
    token, still_must_change = _login(client, dashboard_url, user, effective)
    if still_must_change:
        raise RuntimeError("must_change_password still set after change-password")
    return token, effective, True


# --- Registration flow v3, two-phase (design.md §11.2.3 E.2) ----------------

ADMISSIBLE_GATE_STATUSES = ("created", "pending_credentials")
INADMISSIBLE_GATE_STATUSES = ("online", "degraded", "offline")


def _platform_status(
    client: Any, dashboard_url: str, headers: dict[str, str], platform_key: str
) -> tuple[bool, str]:
    """One read of GET /api/v1/platforms. Never mutates anything.

    Returns ``(ok, status)``. ``ok`` is True only for an HTTP 200 response that
    could be parsed; a non-200 or unreadable body is ``(False, "")`` and must
    never be treated as an admissible status (review C3 / fail-closed gate).
    When ok, ``status`` is the lower-cased platform status, or ``""`` if the
    platform key is absent from the list.
    """
    r = client.get(f"{dashboard_url.rstrip('/')}/api/v1/platforms", headers=headers)
    if r.status_code != 200:
        return False, ""
    try:
        body = r.json()
    except Exception:  # noqa: BLE001 -- unreadable body is a failed read
        return False, ""
    plats = body.get("items") or body.get("platforms") or body if isinstance(body, dict) else body
    for p in plats if isinstance(plats, list) else []:
        if isinstance(p, dict) and p.get("platform_key") == platform_key:
            return True, (p.get("status") or "").lower()
    return True, ""


def admissibility_gate(
    client: Any, dashboard_url: str, headers: dict[str, str], platform_key: str
) -> str:
    """Step 3: a status read that precedes every token call.

    Returns the admissible status. Fail-closed: a failed/missing/non-200 status
    read refuses (review C3). Raises F1 -- read-only, nothing issued, nothing
    written -- for online/degraded/offline. Only an explicit ``created`` or
    ``pending_credentials`` status admits a token path.
    """
    ok, status = _platform_status(client, dashboard_url, headers, platform_key)
    if not ok:
        raise WalkthroughRefusal(
            f"platform {platform_key} status could not be read (non-200 or unreadable "
            "GET /api/v1/platforms response); refusing to issue a bootstrap token without "
            "an established admissible status"
        )
    if status in INADMISSIBLE_GATE_STATUSES:
        raise WalkthroughRefusal(
            f"platform {platform_key} is '{status}', not 'created' or 'pending_credentials': "
            "the walkthrough must start from a platform whose probe has not yet registered, "
            "and the probe must then be deployed WITHOUT platform credentials (step 4), or "
            "the PENDING_CREDENTIALS path cannot be witnessed"
        )
    if status not in ADMISSIBLE_GATE_STATUSES:
        raise WalkthroughRefusal(
            f"platform {platform_key} status is '{status or 'unknown'}', not 'created' or "
            "'pending_credentials'; refusing to issue a bootstrap token without an "
            "explicit admissible status"
        )
    return status


def _poll_until(
    client: Any,
    dashboard_url: str,
    headers: dict[str, str],
    platform_key: str,
    want: str,
    timeout: float,
    poll_interval: float,
) -> tuple[bool, str, int]:
    """Poll GET /platforms until `want`. Returns (reached, last_status, polls)."""
    deadline = time.time() + timeout
    polls = 0
    last = ""
    while True:
        polls += 1
        ok, status = _platform_status(client, dashboard_url, headers, platform_key)
        if ok:
            last = status
            if last == want:
                return True, last, polls
        if time.time() >= deadline:
            return False, last, polls
        time.sleep(min(poll_interval, max(0.0, deadline - time.time())))


def _default_token_out(anchor: str) -> str:
    return str(Path(anchor).resolve().parent / "bootstrap-token.txt")


def registration_phase_one(
    *,
    dashboard_url: str,
    platform_key: str,
    deployment: str,
    token_out: str,
    pending_timeout: float,
    poll_interval: float,
    mode: str,
    admin_user: str = "admin",
    admin_password: str = "admin",
    admin_new_password: str | None = None,
    self_test_client: Any | None = None,
) -> dict[str, Any]:
    """Phase `pre-credentials`, in the normative order of §11.2.3 E.2.

    Runs no tools: the platform has no credentials yet, so every tool call
    would fail for a reason the walkthrough is not about.
    """
    import httpx

    steps: list[dict[str, Any]] = []
    client = self_test_client or httpx.Client(timeout=30)
    owns = self_test_client is None
    auth_info: dict[str, Any] = {"password_changed": False}
    token_file_written = False
    try:
        # 1. authenticate, including the forced first-login password change.
        token, effective_password, changed = authenticate(
            client, dashboard_url, admin_user, admin_password, admin_new_password
        )
        auth_info["password_changed"] = changed
        # Same-process handoff for registration_flow_v3 (`--phase both`).
        # Never copy these into the report artifact.
        _PROCESS_AUTH_SESSION.clear()
        _PROCESS_AUTH_SESSION["token"] = token
        _PROCESS_AUTH_SESSION["effective_password"] = effective_password
        headers = {"Authorization": f"Bearer {token}"}

        # 2. create_platform -- idempotent. Accepted responses only; a failed
        # create must not proceed to a token issue (review C3).
        r = client.post(
            f"{dashboard_url.rstrip('/')}/api/v1/platforms",
            headers=headers,
            json={
                "platform_key": platform_key,
                "platform_type": "presto",
                "deployment": deployment,
                "display_name": platform_key,
            },
        )
        create_ok = r.status_code in (200, 201, 409)
        steps.append(
            {
                "name": "create_platform",
                "ok": create_ok,
                "status_code": r.status_code,
            }
        )
        if not create_ok:
            raise WalkthroughRefusal(
                f"create_platform for {platform_key} failed with HTTP {r.status_code}; "
                "refusing to issue a bootstrap token without an accepted create response"
            )

        # 3. the admissibility gate (F1 lives here, before any token call).
        gate_status = admissibility_gate(client, dashboard_url, headers, platform_key)

        bootstrap_token = ""
        token_issued = False
        if gate_status == "created":
            # 4. the handoff.
            def _issue() -> str:
                resp = client.post(
                    f"{dashboard_url.rstrip('/')}/api/v1/platforms/{platform_key}/bootstrap-token",
                    headers=headers,
                )
                if resp.status_code not in (200, 201):
                    raise RuntimeError(f"issue_bootstrap_token failed: {resp.status_code}")
                body = resp.json() if resp.status_code in (200, 201) else {}
                value = body.get("token") or body.get("bootstrap_token") or ""
                if not value:
                    raise RuntimeError("issue_bootstrap_token returned no token")
                return value

            bootstrap_token = handoff_bootstrap_token(
                issue=_issue,
                token_out=token_out,
                platform_key=platform_key,
                deadline_seconds=pending_timeout,
            )
            token_file_written = True
            token_issued = True
            steps.append({"name": "issue_bootstrap_token", "ok": True, "status_code": 200})

        # 5. start_probe_without_credentials.
        reached, last, polls = _poll_until(
            client,
            dashboard_url,
            headers,
            platform_key,
            "pending_credentials",
            pending_timeout,
            poll_interval,
        )
        if not reached:
            # F2 -- the token is unconsumed and now unreachable by any later
            # phase, so leaving it on disk is pure risk. Cleanup is mandatory
            # and fail-closed (review C4): a silent unlink failure left the
            # raw token on disk.
            cleanup_note = "the token file has been removed"
            if token_file_written:
                try:
                    _remove_owned_secret_file(token_out, role="token file")
                except WalkthroughRefusal as cleanup_exc:
                    raise WalkthroughRefusal(
                        f"platform {platform_key} never reached 'pending_credentials' within "
                        f"{pending_timeout:g}s (last status observed: '{last or 'unknown'}'); "
                        f"AND token-file cleanup failed: {cleanup_exc}"
                    ) from None
            raise WalkthroughRefusal(
                f"platform {platform_key} never reached 'pending_credentials' within "
                f"{pending_timeout:g}s (last status observed: '{last or 'unknown'}'); "
                f"deploy the probe WITHOUT platform credentials, then re-run phase 1 "
                f"({cleanup_note})"
            )
        steps.append(
            {
                "name": "start_probe_without_credentials",
                "status": "pending_credentials",
                "ok": True,
                "observed_at": _now(),
                "polls": polls,
            }
        )

        registration: dict[str, Any] = {
            "mode": mode,
            "pending_credentials_witnessed": True,
            "gate_status": gate_status,
            "bootstrap_token_issued": token_issued,
            "steps": steps,
            "auth": auth_info,
        }
        if token_issued:
            registration["bootstrap_token_sha256"] = _token_sha256(bootstrap_token)
        return registration
    finally:
        if owns:
            client.close()


def registration_phase_two(
    *,
    dashboard_url: str,
    platform_key: str,
    resumed: dict[str, Any],
    token_out: str,
    online_timeout: float,
    poll_interval: float,
    admin_user: str = "admin",
    admin_password: str = "admin",
    admin_new_password: str | None = None,
    self_test_client: Any | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Phase `post-credentials`: install_credentials, poll to online, tidy up.

    ``resumed`` must already be a reconstruct-from-allowlist registration dict
    (see ``load_resume_artifact`` / ``_reconstruct_registration``). This phase
    never deep-copies arbitrary caller content into the report (review C2).
    """
    import httpx

    client = self_test_client or httpx.Client(timeout=30)
    owns = self_test_client is None
    # Reconstruct from the allowlisted field set only — never copy-through.
    registration = _reconstruct_registration(resumed)
    steps: list[dict[str, Any]] = list(registration.get("steps") or [])
    try:
        if headers is None:
            token, _password, changed = authenticate(
                client, dashboard_url, admin_user, admin_password, admin_new_password
            )
            if changed:
                auth = dict(registration.get("auth") or {})
                auth["password_changed"] = True
                registration["auth"] = auth
            headers = {"Authorization": f"Bearer {token}"}

        steps.append(
            {
                "name": "install_credentials",
                "ok": True,
                "note": "operator installs the Secret / Docker secret out of band; the probe "
                "is not redeployed, because the automatic transition is what the next step "
                "exists to witness",
            }
        )

        reached, last, polls = _poll_until(
            client, dashboard_url, headers, platform_key, "online", online_timeout, poll_interval
        )
        steps.append(
            {
                "name": "assert_online",
                "status": last,
                "ok": reached,
                "observed_at": _now(),
                "polls": polls,
            }
        )

        # The token has been consumed. A missing file is the operator having
        # tidied up, not an error. An unlink failure is explicit and sanitizes
        # contents rather than leaving the secret (review C4).
        removed = False
        if os.path.exists(token_out):
            try:
                _remove_owned_secret_file(token_out, role="token file")
                removed = True
            except WalkthroughRefusal as exc:
                print(f"warning: {exc}", file=sys.stderr)
                removed = False
        registration["token_file_removed"] = removed
        registration["steps"] = steps
        return registration
    finally:
        if owns:
            client.close()


def registration_flow_v3(
    *,
    dashboard_url: str,
    platform_key: str,
    deployment: str = "k8s",
    token_out: str,
    pending_timeout: float = 900.0,
    online_timeout: float = 300.0,
    poll_interval: float = 3.0,
    admin_user: str = "admin",
    admin_password: str = "admin",
    admin_new_password: str | None = None,
    self_test_client: Any | None = None,
) -> dict[str, Any]:
    """`--phase both`: the single-process shape, with the same gate and the
    same token handoff -- it is not a way to skip either.

    Phase one may force a first-login password change. Phase two reuses the
    session token / effective password from that step (review C1) rather than
    re-authenticating with the stale original password.
    """
    import httpx

    client = self_test_client or httpx.Client(timeout=30)
    owns = self_test_client is None
    try:
        phase_one = registration_phase_one(
            dashboard_url=dashboard_url,
            platform_key=platform_key,
            deployment=deployment,
            token_out=token_out,
            pending_timeout=pending_timeout,
            poll_interval=poll_interval,
            mode="single_process",
            admin_user=admin_user,
            admin_password=admin_password,
            admin_new_password=admin_new_password,
            self_test_client=client,
        )
        # Prefer the token phase one already holds after any password change.
        token = _PROCESS_AUTH_SESSION.get("token")
        effective_password = _PROCESS_AUTH_SESSION.get("effective_password")
        if not token:
            # Fallback: re-login with the post-phase-one credential only.
            login_password = effective_password or admin_new_password or admin_password
            token, _, _ = authenticate(
                client, dashboard_url, admin_user, login_password, None
            )
        headers = {"Authorization": f"Bearer {token}"}
        # In-process: install_credentials is the operator's step, but the
        # self-test harness marks it over the API so the transition is real.
        if self_test_client is not None:
            client.patch(
                f"{dashboard_url.rstrip('/')}/api/v1/platforms/{platform_key}",
                headers=headers,
                json={"status": "online"},
            )
        return registration_phase_two(
            dashboard_url=dashboard_url,
            platform_key=platform_key,
            resumed=phase_one,
            token_out=token_out,
            online_timeout=online_timeout,
            poll_interval=poll_interval,
            self_test_client=client,
            headers=headers,
        )
    finally:
        _PROCESS_AUTH_SESSION.clear()
        if owns:
            client.close()


# Appendix B.2: pod_logs/container_logs, k8s_pods/swarm_tasks,
# k8s_describe/docker_inspect and k8s_events/docker_events are
# deployment-kind-specific names for the same RuntimeEnv operation, and the
# probe registers only the pair matching its env kind. Invoking the other
# pair against a real cluster can only fail, so it is recorded as skipped.
K8S_ONLY_TOOLS = frozenset({"pod_logs", "k8s_pods", "k8s_describe", "k8s_events"})
SWARM_ONLY_TOOLS = frozenset({"container_logs", "swarm_tasks", "docker_inspect", "docker_events"})

# Tools used to discover the arguments the remaining tools need; they run first.
TARGET_TOOLS = {"k8s": "k8s_pods", "swarm": "swarm_tasks"}
QUERY_ID_TOOL = "presto_list_queries"


def skip_reason(name: str, deployment: str | None) -> str | None:
    """Why `name` cannot be driven on `deployment` (None = drive it)."""
    if deployment is None:
        return None
    if deployment == "swarm" and name in K8S_ONLY_TOOLS:
        return "k8s-only tool; deployment=swarm (Appendix B.2 pair not registered by the probe)"
    if deployment == "k8s" and name in SWARM_ONLY_TOOLS:
        return "swarm-only tool; deployment=k8s (Appendix B.2 pair not registered by the probe)"
    return None


def build_tool_args(
    name: str,
    *,
    deployment: str | None = None,
    target: str | None = None,
    query_id: str | None = None,
) -> dict[str, Any] | None:
    """Representative valid arguments per Appendix B.1/B.2.

    Returns None when the tool needs a value this run could not discover
    (e.g. no query exists on the cluster). The caller must count that as a
    failure, not a neutral skip (review C2 / FP-SW-13): only deployment-kind
    mismatches are skipped.
    """
    kind = deployment or "k8s"
    if name in ("presto_cluster_info", "presto_session_properties"):
        return {}
    if name == "presto_nodes":
        return {"include_failed": True}
    if name == QUERY_ID_TOOL:
        return {"state": "ALL", "since": "1h", "limit": 20}
    if name == "presto_query_detail":
        if not query_id:
            return None
        return {"query_id": query_id, "sections": ["basic", "error", "stats"]}
    if name == "presto_query_json_section":
        if not query_id:
            return None
        return {"query_id": query_id, "jsonpath": "$.queryStats"}
    if name == "presto_config":
        return {"component": "coordinator", "file": "config"}
    if name == "presto_jmx":
        # `heap` is one of Appendix B.1's built-in aliases, resolved probe-side.
        return {"mbean": "heap"}
    if name in ("pod_logs", "container_logs"):
        if not target:
            return None
        return {"target": target, "since": "30m", "lines": 200}
    if name in ("k8s_pods", "swarm_tasks"):
        return {}
    if name in ("k8s_describe", "docker_inspect"):
        if not target:
            return None
        return {"target": target}
    if name in ("k8s_events", "docker_events"):
        return {"since": "1h", "type": "warning"}
    if name == "resource_usage":
        # Appendix B.1 sentinel for "every target" (see dockerenv.SelectorAll).
        return {"selector": "all"}
    if name == "jvm_thread_dump":
        if not target:
            return None
        return {"target": target}
    if name == "jvm_heap_histo":
        if not target:
            return None
        return {"target": target, "top": 20}
    _ = kind
    return {}


def _order_discovery_first(names: list[str], deployment: str | None) -> list[str]:
    """Run the tools whose output feeds other tools' arguments first."""
    first = [QUERY_ID_TOOL, TARGET_TOOLS.get(deployment or "k8s", "k8s_pods")]
    if deployment is None:
        # No deployment kind known: try both target tools, whichever answers.
        first = [QUERY_ID_TOOL, "k8s_pods", "swarm_tasks"]
    head = [n for n in first if n in names]
    return head + [n for n in names if n not in head]


def _first_query_id(data: Any) -> str | None:
    rows = data if isinstance(data, list) else (data or {}).get("queries")
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and row.get("query_id"):
            return str(row["query_id"])
    return None


def _first_target(data: Any) -> str | None:
    rows = data if isinstance(data, list) else (data or {}).get("targets")
    candidates = [r for r in (rows if isinstance(rows, list) else []) if isinstance(r, dict) and r.get("name")]
    for row in candidates:
        if row.get("ready"):
            return str(row["name"])
    return str(candidates[0]["name"]) if candidates else None


def execute_tools(
    *,
    execute_url: str,
    platform_key: str,
    tool_names: list[str] | None = None,
    self_test_envelopes: dict[str, dict] | None = None,
    client: Any | None = None,
    deployment: str | None = None,
) -> list[dict[str, Any]]:
    """Invoke every Toolpack tool via POST /internal/v1/execute.

    Each tool is driven with representative valid arguments (Appendix B.1/
    B.2); `presto_list_queries` and the deployment's pod/task tool run first
    so their output supplies the `query_id` / `target` the other tools need.
    """
    import httpx

    tools_out: list[dict[str, Any]] = []
    names = _order_discovery_first(list(tool_names or toolpack_tool_names()), deployment)
    http = client or httpx
    discovered: dict[str, str | None] = {"query_id": None, "target": None}
    for name in names:
        if self_test_envelopes is not None and name in self_test_envelopes:
            env = self_test_envelopes[name]
            tools_out.append(
                {
                    "name": name,
                    "args": env.get("args") or {},
                    "ok": env.get("exit_code", 1) == 0,
                    "envelope_valid": validate_envelope(env),
                    "error": None,
                }
            )
            continue
        reason = skip_reason(name, deployment)
        if reason:
            # Deployment-kind mismatch (Appendix B.2): neutral skip only.
            tools_out.append(
                {
                    "name": name,
                    "args": {},
                    "ok": False,
                    "envelope_valid": False,
                    "skipped": True,
                    "reason": reason,
                    "error": None,
                }
            )
            continue
        args = build_tool_args(
            name,
            deployment=deployment,
            target=discovered["target"],
            query_id=discovered["query_id"],
        )
        if args is None:
            # Missing discovery inputs are acceptance failures, not skips
            # (review C2): an empty presto_list_queries / k8s_pods result
            # must not let FP-SW-13 pass with failures=0.
            miss = (
                "no representative argument available from this cluster "
                "(discovery returned no query_id/target)"
            )
            tools_out.append(
                {
                    "name": name,
                    "args": {},
                    "ok": False,
                    "envelope_valid": False,
                    "skipped": False,
                    "reason": miss,
                    "error": miss,
                }
            )
            continue
        try:
            post_kwargs: dict[str, Any] = {
                "json": {
                    "platform_key": platform_key,
                    "task_id": str(uuid.uuid4()),
                    "kind": "tool",
                    "tool": name,
                    "args": args,
                    "timeout_seconds": 30,
                },
            }
            if client is None:
                post_kwargs["timeout"] = 60
            r = http.post(
                f"{execute_url.rstrip('/')}/internal/v1/execute",
                **post_kwargs,
            )
            try:
                data = r.json()
            except Exception:  # noqa: BLE001
                data = {}
            # Body may be the envelope itself (has tool + exit_code) or a
            # gateway wrapper {"data": <envelope>}. Prefer the envelope shape.
            if isinstance(data, dict) and "tool" in data and "exit_code" in data:
                env = data
            elif isinstance(data, dict) and isinstance(data.get("data"), dict):
                env = data["data"]
            else:
                env = data if isinstance(data, dict) else {}
            if not isinstance(env, dict) or "tool" not in env:
                # `env` here is the raw, non-envelope response body (e.g.
                # probe-gateway's reduced dispatch.go `executeResponse`:
                # {task_id, exit_code, data, redacted, truncated}) -- it
                # carries the tool's real payload under "data" even though it
                # is not a ToolResultEnvelope. Preserve that payload rather
                # than discarding it: dropping it silently starved discovery
                # (query_id/target) of real results from a tool that had
                # actually succeeded, which no envelope-shape self-test can
                # catch because `--self-test`'s in-process fake always
                # returns a real envelope with "tool" already present.
                real_data = env.get("data") if isinstance(env, dict) else None
                env = {
                    "tool": name,
                    "args": args,
                    "platform_key": platform_key,
                    "probe_id": "unknown",
                    "collected_at": _now(),
                    "exit_code": data.get("exit_code", 1) if isinstance(data, dict) else 1,
                    "truncated": False,
                    "redacted": False,
                    "data": real_data if real_data is not None else {},
                }
            # Ensure required envelope fields for validation.
            env.setdefault("tool", name)
            env.setdefault("args", args)
            env.setdefault("platform_key", platform_key)
            env.setdefault("probe_id", env.get("probe_id") or "walkthrough")
            env.setdefault("collected_at", _now())
            env.setdefault("exit_code", data.get("exit_code", 1) if isinstance(data, dict) else 1)
            env.setdefault("truncated", False)
            env.setdefault("redacted", False)
            env.setdefault("data", {})
            ok = r.status_code == 200 and int(env.get("exit_code", 1)) == 0
            if ok:
                # Feed the discovery values the later tools need.
                if name == QUERY_ID_TOOL and not discovered["query_id"]:
                    discovered["query_id"] = _first_query_id(env.get("data"))
                if name in TARGET_TOOLS.values() and not discovered["target"]:
                    discovered["target"] = _first_target(env.get("data"))
            tools_out.append(
                {
                    "name": name,
                    "args": args,
                    "ok": ok,
                    "envelope_valid": validate_envelope(env),
                    "error": None if r.status_code == 200 else str(getattr(r, "text", ""))[:200],
                }
            )
        except Exception as exc:  # noqa: BLE001
            tools_out.append(
                {"name": name, "args": args, "ok": False, "envelope_valid": False, "error": str(exc)}
            )
    return tools_out


def _pinned_presto_version() -> str:
    """Read Presto version pin from deploy/versions.env (not a magic literal)."""
    versions = REPO / "deploy" / "versions.env"
    if versions.is_file():
        for line in versions.read_text(encoding="utf-8").splitlines():
            if line.startswith("PRESTO_IMAGE="):
                image = line.split("=", 1)[1].strip().strip('"').strip("'")
                # prestodb/presto:0.298 → 0.298
                if ":" in image:
                    return image.rsplit(":", 1)[-1]
    return "unknown"


def _required_tool_args() -> dict[str, list[str]]:
    """Appendix B.1 required params per tool, read from the Toolpack schemas."""
    out: dict[str, list[str]] = {}
    for p in sorted((REPO / "probe/internal/toolpack/schemas").glob("*.schema.json")):
        data = json.loads(p.read_text(encoding="utf-8"))
        for name, schema in (data.get("tools") or {}).items():
            out[name] = list(schema.get("required") or [])
    return out


_CLI_WIRING_CHECKED = False
SELF_TEST_QUERY_ID = "20260809_101512_00042_selft"
SELF_TEST_TARGET = "presto-coordinator-0"
SELF_TEST_ADMIN_PASSWORD = "self-test-admin-pass"
SELF_TEST_NEW_PASSWORD = "self-test-new-password"


def _check_self_test_expectations(
    registration: dict[str, Any],
    tools_out: list[dict[str, Any]],
    swarm_tools_out: list[dict[str, Any]],
    version: str,
) -> None:
    """Assertions for the behaviour the self-test exists to protect."""

    def fail(msg: str) -> None:
        raise RuntimeError(f"self-test: {msg}")

    # (a) forced first-login password change was performed before any other call.
    if not registration.get("auth", {}).get("password_changed"):
        fail("must_change_password branch was not exercised")
    if any(not s.get("ok") for s in registration.get("steps", [])):
        fail(f"registration steps not all ok: {registration.get('steps')}")

    # (c) every driven tool carries representative args, and the discovered
    # query_id / target really flow into the tools that need them.
    required = _required_tool_args()
    by_name = {t["name"]: t for t in tools_out}
    for name, keys in required.items():
        entry = by_name.get(name)
        if entry is None or entry.get("skipped"):
            continue
        for key in keys:
            if key not in (entry.get("args") or {}):
                fail(f"{name} was driven without required arg {key!r}: {entry.get('args')}")
    for name in ("presto_query_detail", "presto_query_json_section"):
        if (by_name.get(name, {}).get("args") or {}).get("query_id") != SELF_TEST_QUERY_ID:
            fail(f"{name} did not reuse the query_id from {QUERY_ID_TOOL}")
    for name in ("pod_logs", "k8s_describe", "jvm_thread_dump", "jvm_heap_histo"):
        if (by_name.get(name, {}).get("args") or {}).get("target") != SELF_TEST_TARGET:
            fail(f"{name} did not reuse the target discovered from k8s_pods")
    if (by_name.get("resource_usage", {}).get("args") or {}).get("selector") != "all":
        fail("resource_usage was not driven with Appendix B.1's selector=all")
    if any(not t["ok"] or not t["envelope_valid"] for t in tools_out):
        fail(f"tool failures: {[t['name'] for t in tools_out if not t['ok']]}")

    # (c) deployment-kind pairing: on swarm the k8s-only half is skipped, and
    # only that half.
    skipped = {t["name"] for t in swarm_tools_out if t.get("skipped")}
    if skipped != set(K8S_ONLY_TOOLS):
        fail(f"deployment=swarm should skip exactly {sorted(K8S_ONLY_TOOLS)}, skipped {sorted(skipped)}")
    if any(not t["ok"] for t in swarm_tools_out if not t.get("skipped")):
        fail("deployment=swarm run had non-skipped tool failures")

    # (d) presto_version resolved, and --presto-version really reaches the
    # report (the flag existing but not being forwarded was the defect).
    if not version or version == "unknown":
        fail(f"presto_version not resolved: {version!r}")
    global _CLI_WIRING_CHECKED
    if not _CLI_WIRING_CHECKED:
        _CLI_WIRING_CHECKED = True
        import contextlib
        import io
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "cli-check.json"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(["--self-test", "--presto-version", "9.9.9-cli", "--out", str(out)])
            cli_report = json.loads(out.read_text(encoding="utf-8"))
        if rc != 0 or cli_report.get("presto_version") != "9.9.9-cli":
            fail("--presto-version is not forwarded from the CLI into the report")


def _selftest_state_path() -> str | None:
    """§11.2.3 E.5: the optional cross-invocation state file."""
    return os.environ.get("E2E_SELFTEST_STATE") or None


def _read_selftest_state() -> dict[str, Any] | None:
    path = _selftest_state_path()
    if not path:
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _record_selftest_call(name: str, body: Any = None) -> None:
    SELFTEST_CALL_LOG.append({"name": name, "body": body})


def _build_self_test_client(platform_key: str) -> Any:
    """Build the in-process fake admin API and return a sync httpx-shaped client.

    `--self-test` builds this per invocation, so two invocations would not share
    the platform's status. When `E2E_SELFTEST_STATE` names a JSON file
    ``{"credentials_installed": bool, "status_override": str | null}``, GET
    /platforms reports `status_override` if it is non-null, else
    `pending_credentials` while `credentials_installed` is false, else `online`.
    When the variable is unset the harness keeps exactly today's in-process
    behavior (create -> pending_credentials, PATCH -> online).
    """
    try:
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        import httpx
    except ImportError as exc:
        raise RuntimeError("starlette+httpx required for --self-test") from exc

    import asyncio

    state: dict[str, Any] = {
        "platforms": {},
        "tokens": {},
        # Mirrors dashboard_api.bootstrap_admin: a fresh admin carries
        # must_change_password=true, and dashboard_api.auth rejects every
        # endpoint except /auth/change-password with 403 while it is set.
        "must_change_password": True,
        "password": "self-test-admin-pass",
    }

    def _password_gate() -> JSONResponse | None:
        if state["must_change_password"]:
            return JSONResponse(
                {"error": "password_change_required", "message": "password change required"},
                status_code=403,
            )
        return None

    async def login(request: Request) -> JSONResponse:
        # Validate credentials like the real dashboard (review C1): a stale
        # password after change-password must 401, not silently succeed.
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        submitted = body.get("password") if isinstance(body, dict) else None
        user = body.get("username") if isinstance(body, dict) else None
        if user != "admin" or submitted != state["password"]:
            return JSONResponse({"error": "invalid_credentials"}, status_code=401)
        return JSONResponse(
            {
                "token": "self-test-token",
                "role": "admin",
                "must_change_password": bool(state["must_change_password"]),
            }
        )

    async def change_password(request: Request) -> JSONResponse:
        body = await request.json()
        if body.get("old_password") != state["password"]:
            return JSONResponse({"error": "invalid_credentials"}, status_code=401)
        new = body.get("new_password") or ""
        if len(new) < 12:
            return JSONResponse({"error": "password_too_short"}, status_code=400)
        state["password"] = new
        state["must_change_password"] = False
        return JSONResponse(None, status_code=204)

    async def create_platform(request: Request) -> JSONResponse:
        if (gate := _password_gate()) is not None:
            return gate
        body = await request.json()
        key = body["platform_key"]
        _record_selftest_call("create_platform", body)
        state["platforms"][key] = {
            "platform_key": key,
            "status": "pending_credentials",
            "config": {},
        }
        return JSONResponse(state["platforms"][key], status_code=201)

    async def list_platforms(request: Request) -> JSONResponse:
        if (gate := _password_gate()) is not None:
            return gate
        _record_selftest_call("GET /platforms")
        hook = SELFTEST_HOOKS.get("on_list_platforms")
        if hook is not None:
            hook(state)
        override = _read_selftest_state()
        items = list(state["platforms"].values())
        if override is not None:
            forced = override.get("status_override")
            if forced:
                status = forced
            else:
                status = "online" if override.get("credentials_installed") else "pending_credentials"
            if not items:
                items = [{"platform_key": platform_key, "status": status, "config": {}}]
            else:
                items = [dict(item, status=status) for item in items]
        return JSONResponse({"items": items})

    async def bootstrap_token(request: Request) -> JSONResponse:
        if (gate := _password_gate()) is not None:
            return gate
        key = request.path_params["key"]
        _record_selftest_call("issue_bootstrap_token", {"platform_key": key})
        hook = SELFTEST_HOOKS.get("on_issue")
        if hook is not None:
            forced = hook(state)
            if isinstance(forced, int):
                return JSONResponse({"error": "self_test_injected"}, status_code=forced)
        tok = f"boot-{uuid.uuid4().hex[:12]}"
        state["tokens"][key] = tok
        SELFTEST_HOOKS["issued_token"] = tok
        return JSONResponse({"token": tok, "bootstrap_token": tok})

    async def patch_platform(request: Request) -> JSONResponse:
        if (gate := _password_gate()) is not None:
            return gate
        key = request.path_params["key"]
        body = await request.json()
        plat = state["platforms"].setdefault(
            key, {"platform_key": key, "status": "created", "config": {}}
        )
        if "status" in body:
            plat["status"] = body["status"]
        if "config" in body:
            plat["config"] = body["config"]
        return JSONResponse(plat)

    required_args = _required_tool_args()

    async def execute(request: Request) -> JSONResponse:
        body = await request.json()
        name = body.get("tool") or "unknown"
        args = body.get("args") or {}
        # Behave like the probe: a tool whose Appendix B.1 required params
        # are missing fails, so `args: {}` for every tool cannot pass.
        missing = [k for k in required_args.get(name, []) if k not in args]
        data: Any = {"self_test": True, "tool": name}
        exit_code = 0
        if missing:
            exit_code = 1
            data = {"error": f"missing required args: {','.join(missing)}"}
        elif name == QUERY_ID_TOOL:
            data = [
                {
                    "query_id": SELF_TEST_QUERY_ID,
                    "state": "FINISHED",
                    "user": "self-test",
                    "query_text_head": "SELECT 1",
                }
            ]
        elif name in TARGET_TOOLS.values():
            data = [
                {"name": SELF_TEST_TARGET, "phase": "running", "ready": True},
                {"name": "presto-worker-0", "phase": "running", "ready": True},
            ]
        env = {
            "tool": name,
            "args": args,
            "platform_key": body.get("platform_key") or platform_key,
            "probe_id": "self-test-probe",
            "collected_at": _now(),
            "exit_code": exit_code,
            "truncated": False,
            "redacted": False,
            "data": data,
        }
        return JSONResponse(env)

    app = Starlette(
        routes=[
            Route("/api/v1/auth/login", login, methods=["POST"]),
            Route("/api/v1/auth/change-password", change_password, methods=["POST"]),
            Route("/api/v1/platforms", create_platform, methods=["POST"]),
            Route("/api/v1/platforms", list_platforms, methods=["GET"]),
            Route("/api/v1/platforms/{key}/bootstrap-token", bootstrap_token, methods=["POST"]),
            Route("/api/v1/platforms/{key}", patch_platform, methods=["PATCH"]),
            Route("/internal/v1/execute", execute, methods=["POST"]),
        ]
    )

    base = "http://self-test"

    class _SyncASGIClient:
        """Sync httpx-shaped client over ASGITransport (one event loop per call)."""

        def post(self, url: str, **kwargs: Any):
            return self._request("POST", url, **kwargs)

        def get(self, url: str, **kwargs: Any):
            return self._request("GET", url, **kwargs)

        def patch(self, url: str, **kwargs: Any):
            return self._request("PATCH", url, **kwargs)

        def _request(self, method: str, url: str, **kwargs: Any):
            async def _go():
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url=base) as c:
                    return await c.request(method, url, **kwargs)

            return asyncio.run(_go())

    return _SyncASGIClient()


SELF_TEST_BASE_URL = "http://self-test"


def _self_test_harness(
    platform_key: str,
    *,
    deployment: str = "k8s",
    token_out: str,
    pending_timeout: float,
    online_timeout: float,
    poll_interval: float,
) -> dict[str, Any]:
    """`--phase both` under `--self-test`: registration + every tool."""
    client = _build_self_test_client(platform_key)
    base = SELF_TEST_BASE_URL
    # Drive the *same* operator-facing helpers CI claims to cover (FP-M6-19),
    # including the login + forced-password-change path (no token shortcut).
    registration = registration_flow_v3(
        dashboard_url=base,
        platform_key=platform_key,
        deployment=deployment,
        token_out=token_out,
        pending_timeout=pending_timeout,
        online_timeout=online_timeout,
        poll_interval=poll_interval,
        admin_user="admin",
        admin_password=SELF_TEST_ADMIN_PASSWORD,
        admin_new_password=SELF_TEST_NEW_PASSWORD,
        self_test_client=client,
    )
    tools_out = execute_tools(
        execute_url=base,
        platform_key=platform_key,
        client=client,
    )
    # Second pass: the deployment-kind pairing (Appendix B.2) is only
    # observable when a deployment kind is supplied.
    swarm_tools_out = execute_tools(
        execute_url=base,
        platform_key=platform_key,
        client=client,
        deployment="swarm",
    )
    version = _pinned_presto_version()
    _check_self_test_expectations(registration, tools_out, swarm_tools_out, version)
    return {
        "registration": registration,
        "tools": tools_out,
        "presto_version": version,
    }


def _resolve_presto_version(presto_version: str | None) -> str:
    if presto_version:
        return presto_version
    import httpx

    presto_url = os.environ.get("PRESTO_URL") or os.environ.get("E2E_PRESTO_URL")
    if not presto_url:
        return "unknown"
    try:
        info = httpx.get(f"{presto_url.rstrip('/')}/v1/info", timeout=10).json()
        return (info.get("nodeVersion") or {}).get("version") or info.get("version") or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def _summarize(tools_out: list[dict[str, Any]], registration: dict[str, Any]) -> dict[str, Any]:
    # Only deployment-kind mismatches (Appendix B.2 k8s/swarm pairs) are
    # neutral skips. Missing discovery inputs are non-skipped failures (C2).
    skipped = [t for t in tools_out if t.get("skipped")]
    ran = [t for t in tools_out if not t.get("skipped")]
    failures = [t for t in ran if not t["ok"] or not t["envelope_valid"]]
    reg_fail = [s for s in registration.get("steps", []) if not s.get("ok")]
    return {
        "tools_total": len(tools_out),
        "tools_ok": len(ran) - len(failures),
        "tools_skipped": len(skipped),
        "failures": len(failures) + len(reg_fail),
    }


# --- Resume-artifact schema (review C2 / FP-SW-12) -------------------------
# Phase 2 must never deep-copy arbitrary content into the completed report.
# Forbidden keys are rejected (not sanitized). The report is reconstructed
# from an explicit allowlisted field set only.

FORBIDDEN_RESUME_KEYS = frozenset(
    {
        "bootstrap_token",
        "token",
        "access_token",
        "password",
        "admin_password",
        "raw_token",
        "secret",
    }
)

# Top-level keys that may appear on a phase-1 resume artifact. Unknown keys
# are ignored during reconstruction; forbidden keys (above) always refuse.
RESUME_TOP_LEVEL_ALLOWLIST = frozenset(
    {
        "phase",
        "deployment",
        "platform_key",
        "presto_version",
        "started_at",
        "finished_at",
        "tools",
        "registration",
        "summary",
    }
)

# registration.* fields that may be reconstructed into the completed report.
RESUME_REGISTRATION_ALLOWLIST = frozenset(
    {
        "mode",
        "pending_credentials_witnessed",
        "gate_status",
        "bootstrap_token_issued",
        "bootstrap_token_sha256",
        "steps",
        "auth",
    }
)

# Keys permitted inside a single registration step dict.
RESUME_STEP_ALLOWLIST = frozenset(
    {
        "name",
        "ok",
        "status_code",
        "status",
        "observed_at",
        "polls",
        "note",
    }
)

# Keys permitted inside registration.auth.
RESUME_AUTH_ALLOWLIST = frozenset({"password_changed"})


def _find_forbidden_keys(obj: Any, *, path: str = "") -> list[str]:
    """Return dotted paths of every forbidden key present recursively."""
    found: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            here = f"{path}.{key}" if path else str(key)
            if key in FORBIDDEN_RESUME_KEYS:
                found.append(here)
            found.extend(_find_forbidden_keys(value, path=here))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            found.extend(_find_forbidden_keys(item, path=f"{path}[{i}]"))
    return found


def _reconstruct_steps(raw_steps: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_steps, list):
        return []
    out: list[dict[str, Any]] = []
    for step in raw_steps:
        if not isinstance(step, dict):
            continue
        out.append({k: step[k] for k in RESUME_STEP_ALLOWLIST if k in step})
    return out


def _reconstruct_auth(raw_auth: Any) -> dict[str, Any]:
    if not isinstance(raw_auth, dict):
        return {}
    return {k: raw_auth[k] for k in RESUME_AUTH_ALLOWLIST if k in raw_auth}


def _reconstruct_registration(raw: Any) -> dict[str, Any]:
    """Build a registration dict from the allowlisted field set only."""
    if not isinstance(raw, dict):
        return {}
    reg: dict[str, Any] = {}
    for key in RESUME_REGISTRATION_ALLOWLIST:
        if key not in raw:
            continue
        if key == "steps":
            reg[key] = _reconstruct_steps(raw[key])
        elif key == "auth":
            reg[key] = _reconstruct_auth(raw[key])
        else:
            reg[key] = raw[key]
    return reg


def _reconstruct_resume_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    """Build a clean resume artifact; never copy unknown or forbidden keys."""
    clean: dict[str, Any] = {}
    for key in RESUME_TOP_LEVEL_ALLOWLIST:
        if key not in artifact:
            continue
        if key == "registration":
            clean[key] = _reconstruct_registration(artifact[key])
        elif key == "tools":
            # Phase 1 tools are empty; phase 2 rebuilds tools. Do not copy
            # arbitrary tool payloads from a planted resume artifact.
            clean[key] = []
        elif key == "summary":
            # Summary is recomputed after phase 2; drop any planted one.
            continue
        else:
            clean[key] = artifact[key]
    return clean


def load_resume_artifact(
    resume: str | None, *, platform_key: str, deployment: str
) -> dict[str, Any]:
    """The five phase-2 refusals R1-R5 (design.md §11.2.3 E.2), plus C2 schema.

    The witness cannot be manufactured by the phase that benefits from it.
    Forbidden secret-bearing keys are **rejected**, never stripped-and-
    continued. The returned artifact is reconstructed from an allowlisted
    field set only.
    """
    # R1 -- --resume not given at all.
    if not resume:
        raise WalkthroughRefusal(
            "--phase post-credentials requires --resume <report.json>: the phase-1 artifact "
            "is the only evidence that the PENDING_CREDENTIALS state was witnessed"
        )
    # R2 -- missing, unreadable, non-UTF-8, or not parseable as JSON.
    # UnicodeDecodeError is a UnicodeError (and ValueError); catch it with
    # OSError so a binary resume exits 2 as WalkthroughRefusal, not a
    # traceback (review W1).
    try:
        raw = Path(resume).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise WalkthroughRefusal(f"--resume {resume} cannot be read: {exc}") from None
    try:
        artifact = json.loads(raw)
    except ValueError as exc:
        raise WalkthroughRefusal(f"--resume {resume} is not valid JSON: {exc}") from None
    if not isinstance(artifact, dict):
        raise WalkthroughRefusal(f"--resume {resume} is not a walkthrough artifact object")

    # C2 -- forbidden keys anywhere in the tree are a hard refusal. A planted
    # bootstrap_token must not be silently sanitized into the completed report.
    forbidden = _find_forbidden_keys(artifact)
    if forbidden:
        raise WalkthroughRefusal(
            f"--resume {resume} contains forbidden key(s) {forbidden}: phase-1 artifacts "
            "must never carry raw secrets; refusing rather than sanitizing"
        )

    # R3 -- phase is anything other than pre-credentials.
    if artifact.get("phase") != "pre-credentials":
        raise WalkthroughRefusal(
            f"--resume {resume} is of phase {artifact.get('phase')!r}, not 'pre-credentials'"
        )
    # R4 -- platform_key / deployment mismatch (one message each).
    if artifact.get("platform_key") != platform_key:
        raise WalkthroughRefusal(
            f"--resume {resume} is for platform {artifact.get('platform_key')!r}, "
            f"not {platform_key!r}"
        )
    if artifact.get("deployment") != deployment:
        raise WalkthroughRefusal(
            f"--resume {resume} is for deployment {artifact.get('deployment')!r}, "
            f"not {deployment!r}"
        )
    # R5 -- the witness is absent or not exactly true. registration must be a
    # dict before we read it: a malformed shape is a named WalkthroughRefusal,
    # not an AttributeError that the CLI cannot catch (review W3 / FP-SW-12).
    registration = artifact.get("registration")
    if registration is None:
        registration = {}
    if not isinstance(registration, dict):
        raise WalkthroughRefusal(
            f"--resume {resume} has a malformed registration field "
            f"(expected an object, got {type(registration).__name__}): "
            "registration.pending_credentials_witnessed: true -- phase 1 never witnessed the "
            "PENDING_CREDENTIALS state, and phase 2 may not manufacture it"
        )
    witnessed = registration.get("pending_credentials_witnessed")
    if witnessed is not True:
        raise WalkthroughRefusal(
            f"--resume {resume} does not carry "
            "registration.pending_credentials_witnessed: true -- phase 1 never witnessed the "
            "PENDING_CREDENTIALS state, and phase 2 may not manufacture it"
        )
    return _reconstruct_resume_artifact(artifact)


def run_walkthrough(
    *,
    deployment: str,
    platform_key: str,
    dashboard_url: str,
    execute_url: str | None,
    self_test: bool = False,
    admin_user: str = "admin",
    admin_password: str = "admin",
    admin_new_password: str | None = None,
    presto_version: str | None = None,
    phase: str = "both",
    resume: str | None = None,
    token_out: str,
    pending_timeout: float = 900.0,
    online_timeout: float = 300.0,
    poll_interval: float = 3.0,
) -> dict[str, Any]:
    started = _now()
    client = _build_self_test_client(platform_key) if self_test else None
    url = SELF_TEST_BASE_URL if self_test else dashboard_url
    exec_url = SELF_TEST_BASE_URL if self_test else execute_url
    if self_test:
        # The fake admin API mirrors bootstrap_admin's must_change_password
        # account, so the split phases authenticate with the same self-test
        # credentials `--phase both` uses.
        admin_user = "admin"
        admin_password = SELF_TEST_ADMIN_PASSWORD
        admin_new_password = SELF_TEST_NEW_PASSWORD

    if phase == "pre-credentials":
        registration = registration_phase_one(
            dashboard_url=url,
            platform_key=platform_key,
            deployment=deployment,
            token_out=token_out,
            pending_timeout=pending_timeout,
            poll_interval=poll_interval,
            mode="two_phase",
            admin_user=admin_user,
            admin_password=admin_password,
            admin_new_password=admin_new_password,
            self_test_client=client,
        )
        return {
            "phase": "pre-credentials",
            "deployment": deployment,
            "platform_key": platform_key,
            "presto_version": _resolve_presto_version(presto_version) if not self_test else (
                presto_version or _pinned_presto_version()
            ),
            "started_at": started,
            "finished_at": _now(),
            "tools": [],
            "registration": registration,
            "summary": _summarize([], registration),
        }

    if phase == "post-credentials":
        artifact = load_resume_artifact(resume, platform_key=platform_key, deployment=deployment)
        registration = registration_phase_two(
            dashboard_url=url,
            platform_key=platform_key,
            resumed=artifact.get("registration") or {},
            token_out=token_out,
            online_timeout=online_timeout,
            poll_interval=poll_interval,
            admin_user=admin_user,
            admin_password=admin_password,
            admin_new_password=admin_new_password,
            self_test_client=client,
        )
        tools_out: list[dict[str, Any]] = []
        if exec_url:
            tools_out = execute_tools(
                execute_url=exec_url,
                platform_key=platform_key,
                deployment=None if self_test else deployment,
                client=client,
            )
        version = artifact.get("presto_version") or _resolve_presto_version(presto_version)
        if presto_version:
            version = presto_version
        # Reconstruct the completed report from an explicit allowlisted field
        # set — never copy-through the resume artifact (review C2).
        report: dict[str, Any] = {
            "phase": "complete",
            "deployment": deployment,
            "platform_key": platform_key,
            # Phase 1's start survives the merge; the completing phase
            # writes finished_at.
            "started_at": artifact.get("started_at") or started,
            "finished_at": _now(),
            "presto_version": version,
            "tools": tools_out,
            "registration": registration,
        }
        report["summary"] = _summarize(tools_out, registration)
        return report

    # --phase both: today's single-process shape, with the same gate and the
    # same token handoff.
    if self_test:
        harness = _self_test_harness(
            platform_key,
            deployment=deployment,
            token_out=token_out,
            pending_timeout=pending_timeout,
            online_timeout=online_timeout,
            poll_interval=poll_interval,
        )
        registration = harness["registration"]
        tools_out = harness["tools"]
        version = presto_version or harness.get("presto_version") or "0.298"
    else:
        registration = registration_flow_v3(
            dashboard_url=dashboard_url,
            platform_key=platform_key,
            deployment=deployment,
            token_out=token_out,
            pending_timeout=pending_timeout,
            online_timeout=online_timeout,
            poll_interval=poll_interval,
            admin_user=admin_user,
            admin_password=admin_password,
            admin_new_password=admin_new_password,
        )
        tools_out = []
        if execute_url:
            tools_out = execute_tools(
                execute_url=execute_url,
                platform_key=platform_key,
                deployment=deployment,
            )
        version = _resolve_presto_version(presto_version)

    return {
        "phase": "complete",
        "deployment": deployment,
        "platform_key": platform_key,
        "presto_version": version,
        "started_at": started,
        "finished_at": _now(),
        "tools": tools_out,
        "registration": registration,
        "summary": _summarize(tools_out, registration),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--deployment", choices=["k8s", "swarm"], default="k8s")
    p.add_argument("--platform-key", default="presto-walkthrough")
    p.add_argument("--dashboard-url", default="http://127.0.0.1:8081")
    p.add_argument("--execute-url", default=None)
    p.add_argument("--admin-user", default=os.environ.get("E2E_ADMIN_USER", "admin"))
    p.add_argument("--admin-password", default=os.environ.get("E2E_ADMIN_PASS", "admin"))
    p.add_argument(
        "--new-admin-password",
        default=os.environ.get("E2E_ADMIN_NEW_PASS"),
        help="password to set when the admin still carries must_change_password "
        "(default: reuse --admin-password, which the server accepts only if it "
        "meets password_min_length)",
    )
    p.add_argument(
        "--presto-version",
        default=os.environ.get("E2E_PRESTO_VERSION"),
        help="Presto version for the report; otherwise read from "
        "PRESTO_URL/E2E_PRESTO_URL /v1/info, else 'unknown'",
    )
    p.add_argument("--out", default="walkthrough-report.json")
    p.add_argument("--self-test", action="store_true")
    p.add_argument(
        "--phase",
        choices=["pre-credentials", "post-credentials", "both"],
        default="both",
        help="which half to run (design.md §11.2.3 E.2). `pre-credentials` hands the "
        "bootstrap token to the operator and polls until the platform reports "
        "pending_credentials; `post-credentials` resumes that artifact after the "
        "credentials are installed",
    )
    p.add_argument(
        "--resume",
        default=None,
        help="phase-2 input: the artifact written by phase 1 (required by "
        "--phase post-credentials, rejected with the other phases)",
    )
    p.add_argument(
        "--token-out",
        default=None,
        help="where phase 1 writes the raw bootstrap token (mode 0600) and phase 2 "
        "removes it; default <dirname(--out)>/bootstrap-token.txt for phase 1 and "
        "<dirname(--resume)>/bootstrap-token.txt for phase 2",
    )
    p.add_argument("--pending-timeout", type=float, default=900.0)
    p.add_argument("--online-timeout", type=float, default=300.0)
    p.add_argument("--poll-interval", type=float, default=3.0)
    args = p.parse_args(argv)

    if args.resume and args.phase != "post-credentials":
        print(
            f"--resume is only accepted with --phase post-credentials (got --phase {args.phase})",
            file=sys.stderr,
        )
        return 2

    if args.token_out:
        token_out = args.token_out
    elif args.phase == "post-credentials" and args.resume:
        token_out = _default_token_out(args.resume)
    else:
        token_out = _default_token_out(args.out)

    try:
        report = run_walkthrough(
            deployment=args.deployment,
            platform_key=args.platform_key,
            dashboard_url=args.dashboard_url,
            execute_url=args.execute_url,
            self_test=args.self_test,
            admin_user=args.admin_user,
            admin_password=args.admin_password,
            admin_new_password=args.new_admin_password,
            presto_version=args.presto_version,
            phase=args.phase,
            resume=args.resume,
            token_out=token_out,
            pending_timeout=args.pending_timeout,
            online_timeout=args.online_timeout,
            poll_interval=args.poll_interval,
        )
    except WalkthroughRefusal as exc:
        # No artifact is written on any refusal, so nothing can be resumed.
        print(str(exc), file=sys.stderr)
        return 2

    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"]))
    return 0 if report["summary"]["failures"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
