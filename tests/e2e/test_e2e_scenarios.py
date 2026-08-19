"""E1–E4 automated Section 13 scenarios (FP-M6-17).

These run against the kind cluster brought up by tests/e2e/run.sh. Each scenario
injects a fault (or load), drives an alert through the real ingest path, and
asserts outcomes through the real dashboard-api HTTP surface.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

REPO = Path(__file__).resolve().parents[2]
ADMIN_USER = os.environ.get("E2E_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("E2E_ADMIN_PASS", "admin-e2e-password")
HMAC_SECRET = os.environ.get("E2E_HMAC_SECRET", "e2e-hmac-secret")
PLATFORM_KEY = os.environ.get("E2E_PLATFORM_KEY", "presto-e2e")


def _login(dashboard_url: str) -> str:
    r = httpx.post(
        f"{dashboard_url.rstrip('/')}/api/v1/auth/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASS},
        timeout=30,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    token = body.get("access_token") or body.get("token")
    assert token, body
    # Clear first-login gate if still set (run.sh normally does this; self-heal for re-runs).
    if body.get("must_change_password"):
        cr = httpx.post(
            f"{dashboard_url.rstrip('/')}/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"old_password": ADMIN_PASS, "new_password": ADMIN_PASS},
            timeout=30,
        )
        assert cr.status_code in (200, 204), cr.text
        r = httpx.post(
            f"{dashboard_url.rstrip('/')}/api/v1/auth/login",
            json={"username": ADMIN_USER, "password": ADMIN_PASS},
            timeout=30,
        )
        assert r.status_code == 200, r.text
        token = r.json().get("access_token") or r.json().get("token")
        assert token
    return token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _sign(body: bytes, secret: str = HMAC_SECRET) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _post_alert(ingest_url: str, *, summary: str, extra: dict | None = None) -> dict:
    payload = {
        "source": "grafana",
        "platform_key": PLATFORM_KEY,
        "error_summary": summary,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "event_id": str(uuid.uuid4()),
        "severity": "high",
    }
    if extra:
        payload.update(extra)
    raw = json.dumps(payload).encode()
    r = httpx.post(
        f"{ingest_url.rstrip('/')}/api/v1/events",
        content=raw,
        headers={"Content-Type": "application/json", "X-Signature": _sign(raw)},
        timeout=30,
    )
    assert r.status_code in (200, 202), r.text
    return r.json()


MAX_LIST_PAGES = 20


def _find_case(dashboard_url: str, token: str, inv_id: str) -> dict | None:
    """The one case with this id, from the paged case-list surface.

    Never returns a case whose ``investigation_id`` differs from the one asked
    for.  The predicate this replaced accepted *either* the requested id *or*
    any case in a listed status, so a stale case from an earlier run — or one
    B1's burst created — could stand in for the case the scenario opened, and
    every assertion after it would validate the wrong investigation (code
    review round 5, C2).
    """
    cursor: str | None = None
    for _page in range(MAX_LIST_PAGES):
        params: dict[str, object] = {"platform_key": PLATFORM_KEY, "limit": 50}
        if cursor:
            params["cursor"] = cursor
        r = httpx.get(
            f"{dashboard_url.rstrip('/')}/api/v1/investigations",
            headers=_auth(token),
            params=params,
            timeout=30,
        )
        if r.status_code != 200:
            return None
        body = r.json()
        for it in body.get("items") or []:
            if str(it.get("investigation_id")) == inv_id:
                return it
        cursor = body.get("next_cursor")
        if not cursor:
            return None
    return None


def _wait_case(
    dashboard_url: str,
    token: str,
    *,
    investigation_id: str,
    statuses: set[str] | None = None,
    timeout: float = 180,
) -> dict:
    """Wait for **this** investigation to reach one of `statuses`.

    Identity and status are required together: a case in the wanted status is
    only ever accepted when it is the case whose id `_post_alert` returned.
    """
    inv_id = str(investigation_id or "")
    assert inv_id and inv_id.lower() != "none", (
        f"_wait_case needs the investigation id the alert opened; got {investigation_id!r}"
    )
    deadline = time.time() + timeout
    last_status = None
    while time.time() < deadline:
        found = _find_case(dashboard_url, token, inv_id)
        if found is not None:
            last_status = found.get("status")
            if statuses is None or last_status in statuses:
                assert str(found["investigation_id"]) == inv_id
                return found
        time.sleep(3)
    raise AssertionError(
        f"investigation {inv_id} did not reach {sorted(statuses) if statuses else 'the case list'} "
        f"within {timeout}s; last observed status={last_status!r}"
    )


def _case_detail(dashboard_url: str, token: str, inv_id: str) -> dict:
    r = httpx.get(
        f"{dashboard_url.rstrip('/')}/api/v1/investigations/{inv_id}",
        headers=_auth(token),
        timeout=30,
    )
    assert r.status_code == 200, r.text
    return r.json()


_APPROVAL_DECISIONS = frozenset({"approved", "denied", "need_more"})


def _approve_pending(
    dashboard_url: str,
    token: str,
    inv_id: str,
    *,
    decision: str = "approved",
    comment: str = "e2e",
) -> None:
    """Decide the pending approval for ``inv_id``.

    The dashboard accepts only ``approved`` / ``denied`` / ``need_more``
    (services.decide_approval_atomic).  Fails closed if the GET or POST is
    non-2xx, or if no undecided approval for this investigation is listed —
    a silent no-op left E1/E4 green while remediation never ran (code review
    round 6, C2).  Invalid decision strings are rejected before any request
    (code review round 7, W1).
    """
    assert decision in _APPROVAL_DECISIONS, (
        f"decision must be one of {sorted(_APPROVAL_DECISIONS)}, got {decision!r}"
    )
    r = httpx.get(
        f"{dashboard_url.rstrip('/')}/api/v1/approvals",
        headers=_auth(token),
        params={"pending": "true", "investigation_id": str(inv_id)},
        timeout=30,
    )
    assert r.status_code == 200, (
        f"GET /approvals?pending=true&investigation_id={inv_id} -> "
        f"{r.status_code}: {r.text}"
    )
    body = r.json()
    items = body.get("items") if isinstance(body, dict) else body
    if not isinstance(items, list):
        items = []
    # Filter-honour check: a server that ignores investigation_id returns
    # the unfiltered oldest-first page. Red whenever any other
    # investigation holds a pending approval (B1's burst in this suite).
    assert all(str(a.get("investigation_id")) == str(inv_id) for a in items), (
        f"GET /approvals?investigation_id={inv_id} returned items for other "
        f"investigations: "
        f"{[(a.get('approval_id'), a.get('investigation_id')) for a in items]}"
    )
    targets = [
        a
        for a in items
        if str(a.get("investigation_id")) == str(inv_id) and not a.get("decision")
    ]
    assert targets, (
        f"no pending approval for investigation {inv_id}; "
        f"listed={[(a.get('approval_id'), a.get('investigation_id'), a.get('decision')) for a in items]}"
    )
    for a in targets:
        pr = httpx.post(
            f"{dashboard_url.rstrip('/')}/api/v1/approvals/{a['approval_id']}/decision",
            headers=_auth(token),
            json={"decision": decision, "comment": comment},
            timeout=30,
        )
        assert pr.status_code in (200, 204), (
            f"POST decision {decision!r} for approval {a['approval_id']} -> "
            f"{pr.status_code}: {pr.text}"
        )


def _kubectl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["kubectl", "-n", "dbagent", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _kubectl_ok(*args: str) -> subprocess.CompletedProcess:
    """Fail closed: a scenario that cannot inject its fault has not run."""
    proc = _kubectl(*args)
    assert proc.returncode == 0, (
        f"kubectl -n dbagent {' '.join(args)} failed (rc={proc.returncode}): "
        f"{proc.stderr.strip() or proc.stdout.strip()}"
    )
    return proc


def _configmap_data(name: str) -> dict[str, str]:
    return json.loads(_kubectl_ok("get", "configmap", name, "-o", "json").stdout).get(
        "data"
    ) or {}


def _properties(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        out[key.strip()] = value.strip()
    return out


def _with_property(text: str, key: str, value: str) -> str:
    """Set one property inside a java .properties blob, preserving the rest."""
    lines = text.splitlines()
    seen = False
    for index, line in enumerate(lines):
        if line.strip().startswith(f"{key}="):
            lines[index] = f"{key}={value}"
            seen = True
    if not seen:
        lines.append(f"{key}={value}")
    return "\n".join(lines) + "\n"


def _patch_configmap_property(
    configmap: str, file_key: str, prop: str, value: str
) -> dict[str, str]:
    """Patch `data.<file_key>` itself — the only thing the pods mount — keeping
    every other property in that value. Returns the properties before the patch."""
    data = _configmap_data(configmap)
    assert file_key in data, f"{configmap} has no {file_key} key: {sorted(data)}"
    before = _properties(data[file_key])
    assert prop in before, (
        f"{configmap}/{file_key} does not carry {prop}; nothing to constrain"
    )
    updated = _with_property(data[file_key], prop, value)
    _kubectl_ok(
        "patch",
        "configmap",
        configmap,
        "--type",
        "merge",
        "-p",
        json.dumps({"data": {file_key: updated}}),
    )
    after = _properties(_configmap_data(configmap)[file_key])
    assert after[prop] == value, f"{prop}={after.get(prop)!r} after patch"
    for key, old in before.items():
        if key == prop:
            continue
        assert after.get(key) == old, (
            f"patch dropped {key}={old!r} from {configmap}/{file_key}"
        )
    return before


def _put_configmap_key(configmap: str, key: str, content: str) -> None:
    """Add or replace one whole `data` key, leaving every other key intact."""
    before = _configmap_data(configmap)
    _kubectl_ok(
        "patch",
        "configmap",
        configmap,
        "--type",
        "merge",
        "-p",
        json.dumps({"data": {key: content}}),
    )
    after = _configmap_data(configmap)
    assert after.get(key) == content, (
        f"{configmap}/{key} is {after.get(key)!r} after the patch"
    )
    for other, value in before.items():
        if other == key:
            continue
        assert after.get(other) == value, (
            f"patch dropped {other!r} from {configmap}"
        )


def _restart_and_wait(workload: str, timeout: str = "120s") -> None:
    _kubectl_ok("rollout", "restart", workload)
    _kubectl_ok("rollout", "status", workload, f"--timeout={timeout}")
    # D2: same blind spot as deploy_presto — require restartCount==0 after a
    # short settle so a crashlooping pod cannot pass rollout status alone.
    if "presto-coordinator" in workload:
        time.sleep(15)
        _kubectl_ok(
            "wait",
            "--for=condition=Ready",
            "pod",
            "-l",
            "app=presto,role=coordinator",
            f"--timeout={timeout}",
        )
        out = _kubectl_ok(
            "get",
            "pod",
            "-l",
            "app=presto,role=coordinator",
            "-o",
            "jsonpath={.items[0].status.containerStatuses[0].restartCount}",
        ).stdout.strip()
        assert out == "0", (
            f"{workload} restartCount={out!r} after settle (expected 0); "
            "coordinator is crashlooping"
        )


def _worker_pod_ips() -> set[str]:
    """Pod IPs for the current worker ReplicaSet generation."""
    out = _kubectl_ok(
        "get",
        "pod",
        "-l",
        "app=presto,role=worker",
        "-o",
        "json",
    ).stdout
    data = json.loads(out)
    ips: set[str] = set()
    for pod in data.get("items") or []:
        if not isinstance(pod, dict):
            continue
        meta = pod.get("metadata") or {}
        if meta.get("deletionTimestamp"):
            continue
        status = pod.get("status") or {}
        if status.get("phase") != "Running":
            continue
        pod_ip = status.get("podIP")
        if not pod_ip:
            continue
        conditions = status.get("conditions") or []
        ready = any(
            isinstance(c, dict)
            and c.get("type") == "Ready"
            and c.get("status") == "True"
            for c in conditions
        )
        if not ready:
            continue
        ips.add(pod_ip)
    return ips


def _node_uri_host(uri: str) -> str | None:
    from urllib.parse import urlparse

    return urlparse(uri).hostname


def _wait_presto_workers_discovered(
    presto_url: str, *, timeout: float = 120.0
) -> None:
    """Wait until the coordinator will schedule on the current worker IPs.

    Presto 0.298 keeps failed nodes in GET /v1/node until expirationGraceInterval
    (default 10 min). DiscoveryNodeManager excludes GET /v1/node/failed hosts
    from scheduling. Live workers = /v1/node hosts minus /v1/node/failed hosts.
    """
    base = presto_url.rstrip("/")
    deadline = time.time() + timeout
    last_detail = ""
    while time.time() < deadline:
        expected = _worker_pod_ips()
        if len(expected) < 2:
            last_detail = f"expected 2 worker pod IPs, got {sorted(expected)!r}"
            time.sleep(2)
            continue

        try:
            r_node = httpx.get(f"{base}/v1/node", timeout=30)
            r_failed = httpx.get(f"{base}/v1/node/failed", timeout=30)
        except httpx.HTTPError as exc:
            last_detail = f"node discovery request failed: {exc!r}"
            time.sleep(2)
            continue
        if r_node.status_code != 200:
            last_detail = (
                f"/v1/node returned status {r_node.status_code}: {r_node.text}"
            )
            time.sleep(2)
            continue
        if r_failed.status_code != 200:
            last_detail = (
                f"/v1/node/failed returned status {r_failed.status_code}: "
                f"{r_failed.text}"
            )
            time.sleep(2)
            continue
        nodes = r_node.json()
        failed_nodes = r_failed.json()
        if not isinstance(nodes, list):
            last_detail = f"/v1/node returned non-list: {r_node.text}"
            time.sleep(2)
            continue
        if not isinstance(failed_nodes, list):
            last_detail = f"/v1/node/failed returned non-list: {r_failed.text}"
            time.sleep(2)
            continue

        def _hosts_from_stats(entries: list) -> set[str]:
            hosts: set[str] = set()
            for node in entries:
                if not isinstance(node, dict) or node.get("coordinator"):
                    continue
                host = _node_uri_host(str(node.get("uri") or ""))
                if host:
                    hosts.add(host)
            return hosts

        node_hosts = _hosts_from_stats(nodes)
        failed_hosts = _hosts_from_stats(failed_nodes)
        live_hosts = node_hosts - failed_hosts

        stale = sorted(live_hosts - expected)
        missing = sorted(expected - live_hosts)
        if len(live_hosts) >= 2 and not stale and not missing:
            return

        last_detail = (
            f"expected worker IPs {sorted(expected)!r}; "
            f"live worker hosts {sorted(live_hosts)!r}; "
            f"/v1/node worker hosts {sorted(node_hosts)!r}; "
            f"/v1/node/failed worker hosts {sorted(failed_hosts)!r}; "
            f"stale={stale!r} missing={missing!r}"
        )
        time.sleep(2)

    raise AssertionError(
        f"timed out waiting for Presto worker discovery; {last_detail}"
    )


def _mounted_property(workload: str, path: str, prop: str) -> str | None:
    out = _kubectl_ok("exec", workload, "--", "cat", path).stdout
    return _properties(out).get(prop)


TERMINAL_QUERY_STATES = {"FINISHED", "FAILED", "CANCELED", "CANCELLED"}


def _wait_query_terminal(base: str, query_id: str, deadline: float) -> dict:
    """Authoritative state, read from the coordinator through the NodePort.

    Always performs the first GET even if *deadline* has already passed, so
    a follow-loop that consumed the shared budget cannot report ``{}``. A
    404 is still ``GONE``. Subsequent GETs are gated on the original
    deadline — extra query runtime past the caller's timeout is not
    granted. A terminal state observed at or after that same original
    deadline is a timeout that names the observed state, not a successful
    wait: the mandatory GET is for diagnosis, not for accepting a late
    result as on-time. Exhaustion raises, naming the timeout and the last
    observed state rather than returning an empty dict.
    """
    last: dict = {}
    first = True
    while True:
        if not first:
            if time.time() >= deadline:
                break
            time.sleep(2)
            if time.time() >= deadline:
                break
        first = False
        r = httpx.get(f"{base}/v1/query/{query_id}", timeout=30)
        observed_at = time.time()
        if r.status_code == 404:
            return {"queryId": query_id, "state": "GONE"}
        assert r.status_code == 200, r.text
        last = r.json()
        if str(last.get("state") or "").upper() in TERMINAL_QUERY_STATES:
            # Compare against the original deadline, never one recomputed
            # after this GET. A terminal seen at/after expiry is late.
            if observed_at >= deadline:
                break
            return last
    state = str(last.get("state") or "")
    raise AssertionError(
        f"timed out waiting for query {query_id} to reach a terminal state; "
        f"last state {state!r} result={last}"
    )


def _presto_query(presto_url: str, sql: str, *, timeout: float = 180.0) -> dict:
    """Run a statement to a terminal state through Presto's own REST API."""
    base = presto_url.rstrip("/")
    r = httpx.post(
        f"{base}/v1/statement",
        content=sql,
        headers={
            "X-Presto-User": "e2e",
            "X-Presto-Catalog": "tpch",
            "X-Presto-Schema": "sf1",
        },
        timeout=30,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    query_id = body.get("id")
    assert query_id, r.text
    deadline = time.time() + timeout
    # Drive the statement by following nextUri where the coordinator's
    # advertised URI is reachable from here; the state we assert on comes from
    # /v1/query/{id}, which is reachable through the NodePort either way.
    follow_exit = "exhausted"
    while body.get("nextUri") and time.time() < deadline:
        try:
            nxt = httpx.get(body["nextUri"], timeout=30)
        except Exception as exc:  # noqa: BLE001 - advertised URI may be cluster-internal
            follow_exit = f"break-on-exception:{type(exc).__name__}"
            break
        if nxt.status_code != 200:
            follow_exit = f"non-200:{nxt.status_code}"
            break
        body = nxt.json()
        if body.get("error"):
            follow_exit = "error-body"
            break
    else:
        follow_exit = "no-nextUri" if not body.get("nextUri") else "exhausted"
    # Pass the original deadline: the first /v1/query GET is mandatory even
    # after expiry, but extra runtime past *timeout* is not granted.
    try:
        result = _wait_query_terminal(base, query_id, deadline)
    except AssertionError as exc:
        raise AssertionError(
            f"{exc}; nextUri loop exited via {follow_exit}"
        ) from exc
    # Always attach the follow-loop exit reason. E1 may still reject a
    # non-FAILED terminal state (FINISHED), and without this the nextUri
    # path — the reason the diagnostic exists — is missing from that
    # failure.
    if isinstance(result, dict):
        result = dict(result)
        result["_e2e_nexturi_follow_exit"] = follow_exit
    return result


# Presto 0.298 StandardErrorCode for query.max-memory-per-node (1MB starve).
# Exact name string — not a generic "exceeded"/"memory" substring (review C2).
PRESTO_LOCAL_MEMORY_LIMIT_ERROR = "EXCEEDED_LOCAL_MEMORY_LIMIT"


def _presto_error_names(result: dict) -> list[str]:
    """Collect Presto errorCode.name values from a /v1/query payload."""
    names: list[str] = []

    def _take(obj: object) -> None:
        if not isinstance(obj, dict):
            return
        code = obj.get("errorCode")
        if isinstance(code, dict):
            name = code.get("name") or code.get("code")
            if name is not None and str(name).strip():
                names.append(str(name))
        elif isinstance(code, str) and code.strip():
            names.append(code)
        # Nested failureInfo / error objects carry the same shape.
        for key in ("failureInfo", "error", "cause"):
            if key in obj:
                _take(obj[key])

    _take(result)
    return names


def _is_presto_local_memory_limit_failure(result: dict) -> bool:
    """True only when Presto reports EXCEEDED_LOCAL_MEMORY_LIMIT.

    Rejects unrelated FAILED states such as EXCEEDED_TIME_LIMIT or a free-text
    "execution time exceeded" message that merely contains the word "exceeded".
    """
    if str(result.get("state") or "").upper() != "FAILED":
        return False
    names = {n.upper() for n in _presto_error_names(result)}
    if PRESTO_LOCAL_MEMORY_LIMIT_ERROR in names:
        return True
    # Some coordinator builds surface the enum name only in free-text message
    # fields; require the exact identifier, not a looser "memory"/"exceeded".
    blob = json.dumps(result)
    return PRESTO_LOCAL_MEMORY_LIMIT_ERROR in blob


def _rewrite_cluster_internal_origin(uri: str, public_base: str) -> str:
    """Rewrite only the origin of a cluster-internal nextUri; preserve path/query.

    Presto may advertise ``http://coordinator:8080/v1/statement/...`` which is
    unreachable from the test host. Replace scheme/host/port with the public
    ``presto_url`` origin and keep path + query intact (W1 / D3).
    """
    from urllib.parse import urlparse, urlunparse

    advertised = urlparse(uri)
    public = urlparse(public_base)
    # Cluster-internal hostnames lack a dotted public DNS name / localhost.
    host = (advertised.hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return uri
    if "." in host and not host.endswith(".svc") and not host.endswith(".local"):
        # Likely already reachable (external DNS) — leave alone.
        return uri
    return urlunparse(
        (
            public.scheme or advertised.scheme,
            public.netloc,
            advertised.path,
            advertised.params,
            advertised.query,
            advertised.fragment,
        )
    )


def _submit_query(presto_url: str, sql: str) -> str:
    """POST /v1/statement and follow nextUri once so Presto dispatches the query.

    The POST alone only queues a statement; the query is invisible to /v1/query
    until the client GETs nextUri at least once (D3). Do not drain the query —
    E3 needs it running/queued. ``/v1/query/{id}`` is NOT a substitute for the
    statement-protocol nextUri (W1).
    """
    base = presto_url.rstrip("/")
    r = httpx.post(
        f"{base}/v1/statement",
        content=sql,
        headers={
            "X-Presto-User": "e2e",
            "X-Presto-Catalog": "tpch",
            "X-Presto-Schema": "sf1",
        },
        timeout=30,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    query_id = body.get("id")
    assert query_id, r.text
    next_uri = body.get("nextUri")
    assert next_uri, f"POST /v1/statement returned no nextUri: {body}"
    follow = _rewrite_cluster_internal_origin(next_uri, base)
    got = httpx.get(follow, timeout=30)
    assert got.status_code == 200, (
        f"nextUri GET failed: status={got.status_code} uri={follow} body={got.text[:500]}"
    )
    return query_id


def _query_states(presto_url: str) -> dict[str, str]:
    r = httpx.get(f"{presto_url.rstrip('/')}/v1/query", timeout=30)
    assert r.status_code == 200, r.text
    return {
        str(q.get("queryId")): str(q.get("state") or "").upper() for q in r.json()
    }


# Object-store URLs the API hands out are presigned for the *cluster-internal*
# endpoint (http://minio:9000), which does not resolve on the test host, and the
# control-plane database has no NodePort at all. Both are read through a pod, so
# the assertions can be made against the real stored bytes rather than against a
# summary the API happened to render.
IN_CLUSTER_FETCH_WORKLOAD = os.environ.get(
    "E2E_FETCH_WORKLOAD", "deploy/dbagent-dashboard-api"
)
PG_WORKLOAD = os.environ.get("E2E_PG_WORKLOAD", "deploy/dbagent-postgresql")
PG_DSN_IN_POD = os.environ.get(
    "E2E_PG_DSN_IN_POD", "postgresql://dbagent:dbagent@127.0.0.1:5432/dbagent"
)

_FETCH_SNIPPET = (
    "import sys, urllib.request;"
    "sys.stdout.write("
    "urllib.request.urlopen(sys.argv[1], timeout=60).read()"
    ".decode('utf-8', 'replace'))"
)


def _fetch_object(url: str) -> str:
    """Download an object-store URL from inside the cluster."""
    assert url, "the API returned no download URL for a stored object"
    return _kubectl_ok(
        "exec",
        IN_CLUSTER_FETCH_WORKLOAD,
        "--",
        "python",
        "-c",
        _FETCH_SNIPPET,
        url,
    ).stdout


def _psql(sql: str) -> str:
    """One value out of the control-plane database, unformatted."""
    return _kubectl_ok(
        "exec", PG_WORKLOAD, "--", "psql", PG_DSN_IN_POD, "-At", "-c", sql
    ).stdout.strip()


def _iterations(dashboard_url: str, token: str, inv_id: str) -> list[dict]:
    """Every iteration of a case. A non-200 here is a failure, never a skip."""
    r = httpx.get(
        f"{dashboard_url.rstrip('/')}/api/v1/investigations/{inv_id}/iterations",
        headers=_auth(token),
        timeout=30,
    )
    assert r.status_code == 200, f"GET iterations -> {r.status_code}: {r.text}"
    body = r.json()
    items = body.get("items") if isinstance(body, dict) else body
    assert isinstance(items, list), body
    return items


def _evidence_refs(dashboard_url: str, token: str, inv_id: str) -> list[dict]:
    refs: list[dict] = []
    for it in _iterations(dashboard_url, token, inv_id):
        for ev in it.get("evidence") or []:
            refs.append(ev)
    return refs


def _evidence_record(dashboard_url: str, token: str, evidence_id: str) -> dict:
    r = httpx.get(
        f"{dashboard_url.rstrip('/')}/api/v1/evidence/{evidence_id}",
        headers=_auth(token),
        params={"full": "true"},
        timeout=30,
    )
    assert r.status_code == 200, f"GET evidence/{evidence_id} -> {r.status_code}: {r.text}"
    return r.json()


def _evidence_payload(dashboard_url: str, token: str, evidence_id: str) -> str:
    """The evidence object itself, as stored in S3."""
    record = _evidence_record(dashboard_url, token, evidence_id)
    url = record.get("download_url")
    assert url, f"evidence {evidence_id} exposes no download_url: {record}"
    return _fetch_object(url)


def _llm_calls(dashboard_url: str, token: str, inv_id: str) -> list[dict]:
    r = httpx.get(
        f"{dashboard_url.rstrip('/')}/api/v1/llm-calls",
        headers=_auth(token),
        params={"investigation_id": inv_id, "limit": 50},
        timeout=30,
    )
    assert r.status_code == 200, f"GET llm-calls -> {r.status_code}: {r.text}"
    items = r.json().get("items") or []
    assert isinstance(items, list)
    return items


def _audit_entries(dashboard_url: str, token: str, inv_id: str) -> list[dict]:
    r = httpx.get(
        f"{dashboard_url.rstrip('/')}/api/v1/audit",
        headers=_auth(token),
        params={"investigation_id": inv_id, "limit": 200},
        timeout=30,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    entries = body.get("items") or body.get("entries") or body
    assert isinstance(entries, list), body
    return entries


WORKER_CONFIGMAP = "presto-worker-config"
WORKER_WORKLOAD = "deploy/presto-worker"
COORDINATOR_CONFIGMAP = "presto-coordinator-config"
COORDINATOR_WORKLOAD = "deploy/presto-coordinator"
# E2's fault. The key is what k8senv.configFileToKey maps the probe tool
# argument `file: "catalog:broken"` to, so the collector reads the same bytes
# the coordinator mounts.
BROKEN_CATALOG_KEY = "catalog-broken.properties"
BROKEN_CATALOG_MOUNT = "/opt/presto-server/etc/catalog/broken.properties"
PRESTO_CONFIG_PATH = "/opt/presto-server/etc/config.properties"
MEMORY_PROP = "query.max-memory-per-node"
STARVED_MEMORY = "1MB"
# Compatible with the fixture's JVM (-Xmx1G) and with
# query.max-total-memory-per-node=256MB; it is what the E1 mock-LLM fixture
# proposes and what verify_fix reads back.
REMEDIATED_MEMORY = "128MB"


def _e1_read_memory_properties() -> dict[str, str]:
    """Capture ``query.max-memory-per-node`` without mutating the ConfigMap.

    Must run *before* ``_patch_configmap_property``: that helper applies the
    patch, then reads/asserts, so a post-patch exception never returns the
    original value to the caller (C1).
    """
    data = _configmap_data(WORKER_CONFIGMAP)
    assert "config.properties" in data, (
        f"{WORKER_CONFIGMAP} has no config.properties key: {sorted(data)}"
    )
    before = _properties(data["config.properties"])
    assert MEMORY_PROP in before, (
        f"{WORKER_CONFIGMAP}/config.properties does not carry {MEMORY_PROP}; "
        "nothing to restore"
    )
    return before


def _e1_cleanup_fault(restore_to: str) -> None:
    """State-observed, idempotent E1 memory-starve cleanup.

    Restores ``query.max-memory-per-node`` to ``restore_to`` (the value
    captured before the starve), restarts the workers, and verifies the
    mounted property. Always attempts every step; aggregates and
    propagates so a half-cleaned cluster cannot go unnoticed.
    """
    errors: list[str] = []

    try:
        _patch_configmap_property(
            WORKER_CONFIGMAP, "config.properties", MEMORY_PROP, restore_to
        )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"restore {MEMORY_PROP}: {exc}")

    try:
        _restart_and_wait(WORKER_WORKLOAD)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"restart workers: {exc}")

    try:
        mounted = _mounted_property(WORKER_WORKLOAD, PRESTO_CONFIG_PATH, MEMORY_PROP)
        if mounted != restore_to:
            errors.append(
                f"{MEMORY_PROP}={mounted!r} after cleanup, expected {restore_to!r}"
            )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"verify {MEMORY_PROP} restored: {exc}")

    if errors:
        raise RuntimeError("E1 cleanup failed: " + "; ".join(errors))


def _platform_config(dashboard_url: str, token: str) -> dict:
    pr = httpx.get(
        f"{dashboard_url.rstrip('/')}/api/v1/platforms",
        headers=_auth(token),
        timeout=30,
    )
    assert pr.status_code == 200, pr.text
    body = pr.json()
    plats = body.get("items") or body.get("platforms") or body
    assert isinstance(plats, list), body
    target = next((p for p in plats if p.get("platform_key") == PLATFORM_KEY), None)
    assert target is not None, f"platform {PLATFORM_KEY} not registered: {plats}"
    return target.get("config") or {}


@pytest.mark.e2e
def test_e1_worker_oom_to_resolved(dashboard_url, ingest_url, presto_url):
    """Worker OOM path: inject a real memory constraint into the file the pods
    actually mount, run the heavy query that trips it, and require the closed
    loop to put the real value back.  Settle window ≥15 s and <60 s proves the
    seeded platform override — not the 120 s playbook default — resolved."""
    rem_path = REPO / "tests/e2e/mockllm/fixtures/e1/remediation.json"
    rem = rem_path.read_text(encoding="utf-8")
    assert "settle_seconds" not in rem, "E1 fixture must omit settle_seconds (rev 2.4 DW4)"
    assert REMEDIATED_MEMORY in rem, (
        f"E1 fixture must propose {REMEDIATED_MEMORY} (JVM -Xmx1G, "
        "query.max-total-memory-per-node=256MB)"
    )

    token = _login(dashboard_url)

    # run.sh phase 6 seeds both the settle override and the real resource
    # locators. Fail closed if either is missing: without remediation_targets
    # the worker would patch namespace "presto", which does not exist here.
    cfg = _platform_config(dashboard_url, token)
    assert (cfg.get("remediation") or {}).get("settle_seconds") == 15, (
        f"phase 6 must seed remediation.settle_seconds=15; got {cfg.get('remediation')!r}"
    )
    targets = cfg.get("remediation_targets") or {}
    assert targets.get("namespace") == "dbagent", (
        f"phase 6 must seed remediation_targets.namespace=dbagent; got {targets!r}"
    )
    assert targets.get("worker_configmap") == WORKER_CONFIGMAP, targets
    assert targets.get("config_file_key") == "config.properties", targets

    # Fault injection: the worker mounts only the `config.properties` key (via
    # subPath), and the memory property lives *inside* that value — so the patch
    # has to rewrite the value, preserving its other properties.
    # Capture the original value *before* any mutation (C1):
    # `_patch_configmap_property` applies the patch then asserts, so a
    # post-patch exception would otherwise leave `before` unassigned and
    # skip finally's restore. Outer try/finally so a failure after the
    # starve cannot leave the cluster at 1MB for E2–E4.
    before = None
    try:
        before = _e1_read_memory_properties()
        assert before[MEMORY_PROP] != STARVED_MEMORY
        _patch_configmap_property(
            WORKER_CONFIGMAP, "config.properties", MEMORY_PROP, STARVED_MEMORY
        )
        _restart_and_wait(WORKER_WORKLOAD)
        mounted = _mounted_property(WORKER_WORKLOAD, PRESTO_CONFIG_PATH, MEMORY_PROP)
        assert mounted == STARVED_MEMORY, (
            f"the starved value never reached the worker container: {mounted!r}"
        )
        _wait_presto_workers_discovered(presto_url)

        # Trip the fault with the required heavy tpch query (Section 13.1). A hash
        # aggregation over sf1.lineitem cannot fit in 1MB per node.  Code review
        # round 6, C3: accepting FINISHED/GONE let a normally completed query
        # establish no memory fault while the canned alert still drove RCA.
        result = _presto_query(
            presto_url,
            "SELECT orderkey, count(*) AS n FROM tpch.sf1.lineitem "
            "GROUP BY orderkey ORDER BY n DESC LIMIT 10",
        )
        state = str(result.get("state") or "").upper()
        assert state == "FAILED", (
            f"E1 requires the heavy query to FAIL under the 1MB limit; got "
            f"state={state!r} result={result}"
        )
        # Presto 0.298 names local-memory exhaustion EXCEEDED_LOCAL_MEMORY_LIMIT
        # exactly. A generic word like "exceeded" alone is not a memory fault —
        # e.g. execution-time limits (code review round 7, C2).
        assert _is_presto_local_memory_limit_failure(result), (
            f"E1 requires Presto error code {PRESTO_LOCAL_MEMORY_LIMIT_ERROR} "
            f"(query.max-memory-per-node starve); got error names="
            f"{_presto_error_names(result)} result={result}"
        )

        opened = _post_alert(
            ingest_url,
            summary="worker OOM / query.max-memory-per-node exceeded",
            extra={"labels": {"scenario": "e1_oom"}},
        )
        inv_id = opened.get("investigation_id")
        assert inv_id, opened

        _wait_case(
            dashboard_url,
            token,
            investigation_id=inv_id,
            statuses={"AWAITING_APPROVAL", "EXECUTING", "VERIFYING", "RESOLVED"},
            timeout=200,
        )

        # Approve remediation when proposed.
        deadline = time.time() + 120
        while time.time() < deadline:
            detail = _case_detail(dashboard_url, token, inv_id)
            status = detail.get("status")
            if status == "AWAITING_APPROVAL":
                _approve_pending(dashboard_url, token, inv_id)
            if status == "RESOLVED":
                break
            time.sleep(3)

        detail = _case_detail(dashboard_url, token, inv_id)
        cat = ((detail.get("rca_report") or {}).get("root_cause") or {}).get("category")
        assert cat in {"resource", "configuration"}, f"RCA category={cat!r} detail={detail}"

        # design.md §13 E1: `presto.adjust_memory_config` executed, and its
        # `remediation_executions.pre_snapshot` non-empty. The previous loop passed
        # when there were no executions at all, and when every execution omitted
        # the field — which they all do, since the case-detail projection does not
        # carry that column. So require the execution, then read the row (code
        # review round 5, C4).
        executions = detail.get("executions") or []
        memory_execs = [
            ex for ex in executions if ex.get("playbook_id") == "presto.adjust_memory_config"
        ]
        assert memory_execs, (
            f"E1 must execute presto.adjust_memory_config; executions={executions}"
        )
        for ex in memory_execs:
            execution_id = ex["execution_id"]
            raw = _psql(
                "SELECT coalesce(pre_snapshot::text, '') FROM remediation_executions "
                f"WHERE execution_id = '{execution_id}'"
            )
            assert raw, f"execution {execution_id} has no pre_snapshot row value"
            snapshot = json.loads(raw)
            assert isinstance(snapshot, dict) and snapshot, (
                f"execution {execution_id} pre_snapshot must be a non-empty object; got {snapshot!r}"
            )

        # Settle window via top-level audit API (no /investigations/{id}/audit route).
        entries = _audit_entries(dashboard_url, token, inv_id)
        assert entries, "expected audit rows for investigation"
        by_action: dict[str, list] = {}
        for e in entries:
            by_action.setdefault(e.get("action"), []).append(e)
        start = None
        end = None
        for a in ("remediation_finished", "remediation_started", "remediation_proposed"):
            if by_action.get(a):
                start = by_action[a][0].get("at")
                break
        if by_action.get("verification_run"):
            end = by_action["verification_run"][0].get("at")
        assert start and end, (
            f"missing remediation/verification audit markers; actions={sorted(by_action)}"
        )
        t0 = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
        window = (t1 - t0).total_seconds()
        assert window >= 15.0, f"settle window {window}s < 15s (playbook default leaked?)"
        assert window < 60.0, f"settle window {window}s >= 60s (override not applied?)"
        assert detail.get("status") == "RESOLVED", detail.get("status")

        # The closed loop must have rewritten the real mounted value, keeping every
        # other Presto property in it (probe-side read-merge-write, FP-M6-29/S3).
        after = _properties(_configmap_data(WORKER_CONFIGMAP)["config.properties"])
        assert after[MEMORY_PROP] == REMEDIATED_MEMORY, (
            f"{MEMORY_PROP}={after.get(MEMORY_PROP)!r} after remediation, expected "
            f"{REMEDIATED_MEMORY}"
        )
        for key, value in before.items():
            if key == MEMORY_PROP:
                continue
            assert after.get(key) == value, (
                f"remediation dropped {key}={value!r} from the worker config"
            )
    finally:
        if before is not None:
            _e1_cleanup_fault(before[MEMORY_PROP])


WEBHOOK_CAPTURE_URL = os.environ.get(
    "E2E_WEBHOOK_CAPTURE_URL", "http://127.0.0.1:30084"
)


def _webhook_capture_reset() -> None:
    r = httpx.get(f"{WEBHOOK_CAPTURE_URL.rstrip('/')}/reset", timeout=15)
    assert r.status_code == 200, f"webhook capture reset -> {r.status_code}: {r.text}"


def _webhook_capture_received() -> list[dict]:
    r = httpx.get(f"{WEBHOOK_CAPTURE_URL.rstrip('/')}/", timeout=15)
    assert r.status_code == 200, f"webhook capture GET -> {r.status_code}: {r.text}"
    body = r.json()
    assert isinstance(body, list), body
    return body


def _wait_notification_for(inv_id: str, *, timeout: float = 60.0) -> list[str]:
    """Bodies the in-cluster capture received for this investigation."""
    deadline = time.time() + timeout
    last: list[dict] = []
    while time.time() < deadline:
        last = _webhook_capture_received()
        matched = [
            entry.get("body") or ""
            for entry in last
            if str(inv_id) in (entry.get("body") or "")
        ]
        if matched:
            return matched
        time.sleep(2)
    raise AssertionError(
        f"no notification payload for investigation {inv_id} within {timeout}s; "
        f"capture held {len(last)} bodies"
    )


@pytest.mark.e2e
def test_e2_broken_catalog_redacted(dashboard_url, ingest_url, presto_url):
    """Broken catalog with password sentinel — must never appear in evidence."""
    sentinel = "REDACT_SENTINEL_e2e_password_value"
    token = _login(dashboard_url)
    _webhook_capture_reset()

    # The fault lives in the coordinator's own ConfigMap, under the key the
    # probe's `presto_config` tool resolves `catalog:broken` to (k8senv
    # configFileToKey) — so what the pod mounts and what the collector reads
    # are the same bytes, and the redaction filter is genuinely on the path.
    # connector.name=hive doesn't match any factory this image ships (real
    # name is hive-hadoop2, confirmed against the actual prestodb/presto:0.298
    # image) and crashes the WHOLE coordinator rather than just this catalog,
    # which defeats the scenario -- the platform has to stay observable.
    # hive-hadoop2 itself doesn't take connection-url (it wants
    # hive.metastore.uri, no embedded credential). postgresql is a real,
    # accepted JDBC connector whose connection-url legitimately carries an
    # embedded password, which is exactly the shape this scenario needs to
    # prove gets redacted, and the coordinator stays healthy with it.
    broken = (
        f"connector.name=postgresql\n"
        f"connection-url=jdbc:postgresql://x?password={sentinel}\n"
    )
    _put_configmap_key(COORDINATOR_CONFIGMAP, BROKEN_CATALOG_KEY, broken)

    # Patch coordinator Deployment to mount that key (idempotent).
    # Fail closed: a scenario whose fault was never injected proves nothing
    # about redaction, so every kubectl step here is asserted.
    get = _kubectl_ok("get", "deploy", "presto-coordinator", "-o", "json")
    assert get.stdout, "empty deployment JSON for presto-coordinator"
    dep = json.loads(get.stdout)
    spec = dep.setdefault("spec", {}).setdefault("template", {}).setdefault("spec", {})
    volumes = {v.get("name") for v in spec.get("volumes") or []}
    assert "config" in volumes, (
        f"presto-coordinator has no 'config' volume to mount the catalog from: {volumes}"
    )
    containers = [c for c in (spec.get("containers") or []) if c.get("name") == "presto"]
    assert containers, "presto-coordinator has no container named 'presto'"
    for c in containers:
        mounts = c.setdefault("volumeMounts", [])
        if not any(m.get("mountPath") == BROKEN_CATALOG_MOUNT for m in mounts):
            mounts.append(
                {
                    "name": "config",
                    "mountPath": BROKEN_CATALOG_MOUNT,
                    "subPath": BROKEN_CATALOG_KEY,
                }
            )
    apply_dep = subprocess.run(
        ["kubectl", "-n", "dbagent", "apply", "-f", "-"],
        input=json.dumps(dep),
        capture_output=True,
        text=True,
        check=False,
    )
    assert apply_dep.returncode == 0, apply_dep.stderr
    _restart_and_wait(COORDINATOR_WORKLOAD, timeout="180s")

    # Prove the sentinel is present on the coordinator (fault really injected).
    check = _kubectl_ok(
        "exec",
        COORDINATOR_WORKLOAD,
        "--",
        "cat",
        BROKEN_CATALOG_MOUNT,
    )
    assert sentinel in (check.stdout or ""), "sentinel not mounted into coordinator"

    opened = _post_alert(
        ingest_url,
        summary="catalog broken.properties failed connection-url password leak check",
        extra={"labels": {"scenario": "e2_catalog"}},
    )
    inv_id = opened.get("investigation_id")
    assert inv_id

    # E2's remediation fixture proposes a playbook so the real worker fires
    # approval_requested (CLOSED_SUMMARY alone is not a notification event —
    # design.md §9.5.3).  Deny it to land on CLOSED_SUMMARY as the scenario
    # requires, then assert the capture holds a payload for this case with
    # the sentinel absent from the actual received bytes (code review round 6, C4).
    _wait_case(
        dashboard_url,
        token,
        investigation_id=inv_id,
        statuses={"AWAITING_APPROVAL", "CLOSED_SUMMARY", "RESOLVED", "NEEDS_HUMAN"},
        timeout=180,
    )
    deadline = time.time() + 90
    while time.time() < deadline:
        detail = _case_detail(dashboard_url, token, inv_id)
        status = detail.get("status")
        if status == "AWAITING_APPROVAL":
            _approve_pending(
                dashboard_url,
                token,
                inv_id,
                decision="denied",
                comment="e2 deny — redaction scenario only",
            )
        if status == "CLOSED_SUMMARY":
            break
        time.sleep(3)
    detail = _case_detail(dashboard_url, token, inv_id)
    assert detail.get("status") == "CLOSED_SUMMARY", detail.get("status")

    blob = json.dumps(detail)
    assert sentinel not in blob, "sentinel leaked into investigation detail"

    notif_bodies = _wait_notification_for(inv_id, timeout=60)
    # Marker-bearing subject description reaches the notification path via
    # digest/summary; the sanitizer must replace it with ***REDACTED*** so
    # both the placeholder and the raw marker are asserted (round 7, C3).
    redacted_any = False
    for body in notif_bodies:
        assert sentinel not in body, (
            f"sentinel present in a notification payload for {inv_id}: {body[:500]}"
        )
        if "***REDACTED***" in body:
            redacted_any = True
    assert redacted_any, (
        f"notification payloads for {inv_id} never carried the redaction "
        f"placeholder — marker-bearing digest was not sanitized: "
        f"{[b[:300] for b in notif_bodies]}"
    )

    # The case surfaces are summaries; redaction has to hold in the artefacts
    # they *reference*. Every response below is asserted (a non-200 used to
    # skip the sentinel check entirely) and every referenced object is
    # downloaded and searched (code review round 5, C3).
    refs = _evidence_refs(dashboard_url, token, inv_id)
    assert refs, "E2 collected no evidence; redaction was never exercised"

    collected: list[tuple[dict, dict, str]] = []
    for ref in refs:
        assert sentinel not in json.dumps(ref), f"sentinel in evidence reference {ref}"
        evidence_id = ref["evidence_id"]
        record = _evidence_record(dashboard_url, token, evidence_id)
        assert sentinel not in json.dumps(record), (
            f"sentinel in evidence record {evidence_id}"
        )
        payload = _evidence_payload(dashboard_url, token, evidence_id)
        assert payload, f"evidence {evidence_id} stored an empty payload"
        assert sentinel not in payload, (
            f"sentinel present in the stored evidence object for {evidence_id} "
            f"(tool={record.get('tool_name')!r}, {len(payload)} bytes)"
        )
        collected.append((ref, record, payload))

    # The file the sentinel lives in must actually have been read: "the
    # sentinel is absent" is worth nothing if nothing ever collected it.
    catalog = [
        (record, payload)
        for _ref, record, payload in collected
        if record.get("tool_name") == "presto_config"
        and (record.get("args") or {}).get("file") == "catalog:broken"
    ]
    assert catalog, (
        "E2 never collected the broken catalog through presto_config; "
        f"tools collected={[r.get('tool_name') for _x, r, _y in collected]}"
    )
    for record, payload in catalog:
        assert record.get("redacted") is True, (
            f"evidence {record.get('evidence_id')} read the credential-bearing "
            f"catalog but is not flagged redacted: {record}"
        )
        assert "connection-url" in payload, (
            f"the collected catalog payload is not the broken catalog: {payload[:400]}"
        )
        assert "***REDACTED***" in payload, (
            f"the credential was not replaced by the redaction placeholder: {payload[:400]}"
        )

    calls = _llm_calls(dashboard_url, token, inv_id)
    assert calls, "E2 made no LLM calls; the prompt surface was never exercised"
    downloaded = 0
    for call in calls:
        role = call.get("agent_role")
        # The remediation fixture plants password=<sentinel> so the approval
        # notification digest exercises the sanitizer (round 7, C3).  That
        # planted response is intentionally marker-bearing; prompts and every
        # other role must still be clean.
        row_blob = json.dumps(call)
        if role != "remediation":
            assert sentinel not in row_blob, f"sentinel in llm-call row {call}"
        urls = {"prompt_url": call.get("prompt_url")}
        if not call.get("error"):
            urls["response_url"] = call.get("response_url")
        for field, url in urls.items():
            assert url, f"llm-call {call.get('call_id')} has no {field}"
            body = _fetch_object(url)
            assert body, f"llm-call {call.get('call_id')} {field} stored no bytes"
            if role == "remediation" and field == "response_url":
                assert sentinel in body, (
                    "remediation fixture must plant the marker for the "
                    "notification redaction path"
                )
                downloaded += 1
                continue
            assert sentinel not in body, (
                f"sentinel present in the stored {field} of llm-call "
                f"{call.get('call_id')} (agent_role={role!r})"
            )
            downloaded += 1
    assert downloaded >= 2, f"only {downloaded} LLM artefact(s) were inspected"

    entries = _audit_entries(dashboard_url, token, inv_id)
    assert entries, "expected audit rows for the redaction case"
    assert sentinel not in json.dumps(entries), "sentinel leaked into the audit trail"

    cat = ((detail.get("rca_report") or {}).get("root_cause") or {}).get("category")
    assert cat == "configuration", f"RCA category={cat!r}"


RESOURCE_GROUP_MANAGER_PROP = "resource-groups.configuration-manager"
RESOURCE_GROUP_FILE_PROP = "resource-groups.config-file"
RESOURCE_GROUP_FILE = "/opt/presto-server/etc/resource-groups.json"
# These two properties are NOT config.properties keys: Presto's core Bootstrap
# injector validates config.properties against only its own modules and fails
# startup ("Configuration property ... was not used") if they are appended
# there instead of their own etc/resource-groups.properties file -- confirmed
# against the real prestodb/presto:0.298 image (docs:
# https://prestodb.io/docs/current/admin/resource-groups.html).
# The key and its volumeMount are ABSENT by default: Presto 0.298 hard-fails
# on a present-but-empty resource-groups.properties (D1). E3 adds the
# ConfigMap key + mount when injecting the fault and removes both on cleanup.
RESOURCE_GROUPS_PROPERTIES_KEY = "resource-groups.properties"
RESOURCE_GROUPS_PROPERTIES_PATH = "/opt/presto-server/etc/resource-groups.properties"
E3_LONG_QUERY = (
    "SELECT count(*) FROM tpch.sf1.lineitem l "
    "JOIN tpch.sf1.orders o ON l.orderkey = o.orderkey"
)
E3_CONCURRENT_QUERIES = 6


def _patch_coordinator_rg_mount(*, present: bool) -> None:
    """Add or remove the resource-groups.properties volumeMount on the coordinator."""
    get = _kubectl_ok("get", "deploy", "presto-coordinator", "-o", "json")
    dep = json.loads(get.stdout)
    containers = (
        dep.setdefault("spec", {})
        .setdefault("template", {})
        .setdefault("spec", {})
        .setdefault("containers", [])
    )
    assert containers, "presto-coordinator has no containers"
    c0 = containers[0]
    mounts = list(c0.get("volumeMounts") or [])
    mounts = [
        m
        for m in mounts
        if m.get("mountPath") != RESOURCE_GROUPS_PROPERTIES_PATH
        and m.get("subPath") != RESOURCE_GROUPS_PROPERTIES_KEY
    ]
    if present:
        mounts.append(
            {
                "name": "config",
                "mountPath": RESOURCE_GROUPS_PROPERTIES_PATH,
                "subPath": RESOURCE_GROUPS_PROPERTIES_KEY,
            }
        )
    c0["volumeMounts"] = mounts
    patched = json.dumps(dep)
    apply = subprocess.run(
        ["kubectl", "-n", "dbagent", "apply", "-f", "-"],
        input=patched,
        text=True,
        capture_output=True,
        check=False,
    )
    assert apply.returncode == 0, (
        f"patch resource-groups mount failed: {apply.stderr or apply.stdout}"
    )


def _wait_for_states(
    presto_url: str, wanted: str, *, at_least: int, timeout: float
) -> dict[str, str]:
    deadline = time.time() + timeout
    states: dict[str, str] = {}
    while time.time() < deadline:
        try:
            states = _query_states(presto_url)
        except AssertionError:
            states = {}
        if sum(1 for s in states.values() if s == wanted) >= at_least:
            return states
        time.sleep(2)
    return states


def _e3_cm_key_present() -> bool:
    """State-observed: is the fault ConfigMap key currently present?

    Returns False only after a *successful* read proves the key is absent.
    Observation / kubectl failures propagate (review W1) so cleanup cannot
    treat "could not observe" as "already clean".
    """
    get = _kubectl_ok("get", "configmap", COORDINATOR_CONFIGMAP, "-o", "json")
    cm = json.loads(get.stdout)
    return RESOURCE_GROUPS_PROPERTIES_KEY in (cm.get("data") or {})


def _e3_mount_present() -> bool:
    """State-observed: is the resource-groups volumeMount currently present?

    Returns False only after a *successful* read proves the mount is absent.
    Observation / kubectl failures propagate (review W1).
    """
    get = _kubectl_ok("get", "deploy", "presto-coordinator", "-o", "json")
    dep = json.loads(get.stdout)
    containers = (
        dep.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("containers", [])
    )
    if not containers:
        return False
    mounts = containers[0].get("volumeMounts") or []
    return any(
        m.get("mountPath") == RESOURCE_GROUPS_PROPERTIES_PATH
        or m.get("subPath") == RESOURCE_GROUPS_PROPERTIES_KEY
        for m in mounts
    )


def _e3_remove_cm_key() -> None:
    """Idempotent: delete the fault ConfigMap key if present.

    The key is added by ``_put_configmap_key`` via merge-patch, which does
    not write last-applied-configuration. ``kubectl apply`` therefore cannot
    delete it (H-A). A JSON Merge Patch null is the matching removal.
    """
    if not _e3_cm_key_present():
        return
    _kubectl_ok(
        "patch",
        "configmap",
        COORDINATOR_CONFIGMAP,
        "--type",
        "merge",
        "-p",
        json.dumps({"data": {RESOURCE_GROUPS_PROPERTIES_KEY: None}}),
    )


def _e3_cleanup_fault() -> None:
    """State-observed, idempotent E3 fault cleanup (review W1).

    Always attempts every restoration regardless of setup flags; verifies the
    key and mount are absent; restarts the coordinator; aggregates and
    propagates failures so a half-cleaned cluster cannot go unnoticed.
    """
    errors: list[str] = []

    try:
        _patch_coordinator_rg_mount(present=False)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"remove mount: {exc}")

    try:
        _e3_remove_cm_key()
    except Exception as exc:  # noqa: BLE001
        errors.append(f"remove cm key: {exc}")

    try:
        _restart_and_wait(COORDINATOR_WORKLOAD, timeout="180s")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"restart coordinator: {exc}")

    # Verify restoration — state-observed, not flag-driven.
    try:
        if _e3_cm_key_present():
            errors.append(
                f"ConfigMap key {RESOURCE_GROUPS_PROPERTIES_KEY!r} still present "
                f"after cleanup"
            )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"verify cm key absent: {exc}")

    try:
        if _e3_mount_present():
            errors.append(
                f"volumeMount for {RESOURCE_GROUPS_PROPERTIES_PATH!r} still "
                f"present after cleanup"
            )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"verify mount absent: {exc}")

    if errors:
        raise RuntimeError("E3 cleanup failed: " + "; ".join(errors))


@pytest.mark.e2e
def test_e3_queue_saturation_closed_summary(dashboard_url, ingest_url, presto_url):
    """Section 13.5: constrain concurrency, submit N long queries, and prove the
    queued backlog exists through Presto's own API *before* the alert is posted;
    then prove it drains once the constraint is removed."""
    token = _login(dashboard_url)

    # Fault injection: switch the coordinator to the file resource-group
    # manager, whose shipped root group runs one query at a time. These two
    # properties live in their own resource-groups.properties key/file, never
    # in config.properties. The key and mount are ABSENT by default (D1) —
    # add both for the fault, remove both on cleanup.
    #
    # Whole installation is under outer try/finally so a failure mid-setup
    # still tears down whatever cluster state was mutated (W1: cleanup is
    # state-observed, not dependent on post-success flags).
    try:
        _put_configmap_key(
            COORDINATOR_CONFIGMAP,
            RESOURCE_GROUPS_PROPERTIES_KEY,
            f"{RESOURCE_GROUP_MANAGER_PROP}=file\n{RESOURCE_GROUP_FILE_PROP}={RESOURCE_GROUP_FILE}\n",
        )
        _patch_coordinator_rg_mount(present=True)
        _restart_and_wait(COORDINATOR_WORKLOAD, timeout="180s")

        mounted = _mounted_property(
            COORDINATOR_WORKLOAD, RESOURCE_GROUPS_PROPERTIES_PATH, RESOURCE_GROUP_MANAGER_PROP
        )
        assert mounted == "file", (
            f"resource-group constraint never reached the coordinator: {mounted!r}"
        )

        submitted = [
            _submit_query(presto_url, E3_LONG_QUERY)
            for _ in range(E3_CONCURRENT_QUERIES)
        ]
        assert len(set(submitted)) == E3_CONCURRENT_QUERIES, submitted

        states = _wait_for_states(presto_url, "QUEUED", at_least=1, timeout=90)
        queued = [
            qid
            for qid, state in states.items()
            if state == "QUEUED" and qid in set(submitted)
        ]
        assert queued, (
            "E3 fault not established: none of this scenario's queries is "
            f"QUEUED on the coordinator; submitted={submitted} states={states}"
        )

        opened = _post_alert(
            ingest_url,
            summary=(
                f"queue saturation: {len(queued)} queries QUEUED behind the "
                "global resource group"
            ),
            extra={"labels": {"scenario": "e3_queue"}},
        )
        inv_id = opened.get("investigation_id")
        assert inv_id
        _e3_assert_case(dashboard_url, token, inv_id, queued=queued)
    finally:
        _e3_cleanup_fault()

    drained_deadline = time.time() + 120
    remaining = {}
    while time.time() < drained_deadline:
        remaining = {
            qid: state
            for qid, state in _query_states(presto_url).items()
            if state == "QUEUED"
        }
        if not remaining:
            break
        time.sleep(3)
    assert not remaining, f"queued backlog did not drain after recovery: {remaining}"


def _e3_assert_case(
    dashboard_url: str, token: str, inv_id: str, *, queued: list[str]
) -> None:
    _wait_case(
        dashboard_url,
        token,
        investigation_id=inv_id,
        statuses={"CLOSED_SUMMARY", "NEEDS_HUMAN", "RESOLVED"},
        timeout=180,
    )
    detail = _case_detail(dashboard_url, token, inv_id)
    assert detail.get("status") == "CLOSED_SUMMARY", detail.get("status")
    cat = ((detail.get("rca_report") or {}).get("root_cause") or {}).get("category")
    assert cat == "capacity", f"RCA category={cat!r}"
    # No playbook / remediation execution on capacity-closed path.
    executions = detail.get("executions") or []
    assert not executions or all(
        (ex.get("status") or "").upper() in {"SKIPPED", "NONE", ""} for ex in executions
    ), executions
    # Capacity recommendation present on the case surface.
    rca = detail.get("rca_report") or {}
    surface = json.dumps(rca).lower()
    assert (
        "concurrent" in surface
        or "capacity" in surface
        or "queue" in surface
        or rca.get("recommendation")
    ), rca

    # §11.1.3 E3: `presto_list_queries` evidence shows *this scenario's* queued
    # backlog. Matching the word "queued" anywhere in the serialized iterations
    # also matched the canned RCA prose, so the check passed with no evidence
    # at all; the tool name is now exact and its stored payload is read (code
    # review round 5, C5).
    refs = [
        ref
        for ref in _evidence_refs(dashboard_url, token, inv_id)
        if ref.get("tool_name") == "presto_list_queries"
    ]
    assert refs, (
        "E3 has no evidence entry with tool_name == 'presto_list_queries'; "
        f"collected={[r.get('tool_name') for r in _evidence_refs(dashboard_url, token, inv_id)]}"
    )
    listed: dict[str, str] = {}
    for ref in refs:
        payload = _evidence_payload(dashboard_url, token, ref["evidence_id"])
        for entry in _iter_query_rows(json.loads(payload)):
            qid = str(entry.get("query_id") or entry.get("queryId") or "")
            if qid:
                listed[qid] = str(entry.get("state") or "").upper()
    assert listed, f"presto_list_queries evidence carried no query rows: {refs}"
    correlated = {qid: listed[qid] for qid in queued if qid in listed}
    assert correlated, (
        "presto_list_queries evidence does not contain any of the queries this "
        f"scenario established as QUEUED: queued={queued} listed={sorted(listed)[:10]}"
    )
    assert any(state == "QUEUED" for state in correlated.values()), (
        f"the collected evidence shows no queued backlog for this scenario: {correlated}"
    )


def _iter_query_rows(payload: object):
    """Every query row in a `presto_list_queries` payload, whatever envelope
    the probe wrapped it in."""
    if isinstance(payload, list):
        for item in payload:
            yield from _iter_query_rows(item)
    elif isinstance(payload, dict):
        if "query_id" in payload or "queryId" in payload:
            yield payload
            return
        for value in payload.values():
            if isinstance(value, (list, dict)):
                yield from _iter_query_rows(value)


@pytest.mark.e2e
def test_e4_runaway_query_killed(dashboard_url, ingest_url, presto_url):
    token = _login(dashboard_url)
    # Start a long query on Presto; require a real query_id.
    r = httpx.post(
        f"{presto_url.rstrip('/')}/v1/statement",
        content="SELECT count(*) FROM tpch.sf1.lineitem CROSS JOIN tpch.sf1.lineitem",
        headers={
            "X-Presto-User": "e2e",
            "X-Presto-Catalog": "tpch",
            "X-Presto-Schema": "sf1",
        },
        timeout=10,
    )
    assert r.status_code == 200, r.text
    query_id = r.json().get("id")
    assert query_id, r.text

    # `labels` is the one alert field the ingest normalizer preserves verbatim
    # (gateway/ingest.py), so it is what carries the runaway id into the
    # planner prompt — and from there into the remediation fixture's
    # `${query_id}` placeholder.
    opened = _post_alert(
        ingest_url,
        summary=f"runaway query {query_id}",
        extra={
            "query_id": query_id,
            "labels": {"scenario": "e4_runaway", "query_id": query_id},
        },
    )
    inv_id = opened.get("investigation_id")
    assert inv_id
    _wait_case(
        dashboard_url,
        token,
        investigation_id=inv_id,
        statuses={"AWAITING_APPROVAL", "RESOLVED", "EXECUTING"},
        timeout=120,
    )
    deadline = time.time() + 90
    while time.time() < deadline:
        detail = _case_detail(dashboard_url, token, inv_id)
        if detail.get("status") == "AWAITING_APPROVAL":
            _approve_pending(dashboard_url, token, inv_id)
        if detail.get("status") == "RESOLVED":
            break
        time.sleep(3)
    detail = _case_detail(dashboard_url, token, inv_id)
    assert detail.get("status") == "RESOLVED", detail.get("status")

    # The kill must be *this* query's. Matching the id anywhere in the case
    # surface matched the alert that opened the case, which proves nothing
    # about what was executed, so the execution row and the audit trail are
    # correlated by query_id here (code review round 5, C6).
    executions = detail.get("executions") or []
    kills = [
        ex
        for ex in executions
        if ex.get("playbook_id") == "presto.kill_query"
        and str((ex.get("params") or {}).get("query_id")) == query_id
    ]
    assert kills, (
        f"no presto.kill_query execution targets {query_id!r}; "
        f"executions={executions}"
    )
    assert all((ex.get("status") or "").lower() == "succeeded" for ex in kills), kills

    entries = _audit_entries(dashboard_url, token, inv_id)
    kill_audits = [
        e
        for e in entries
        if e.get("action") in {"remediation_started", "remediation_finished"}
        and query_id in json.dumps(e.get("detail") or {})
    ]
    assert kill_audits, (
        f"audit trail records no remediation carrying {query_id!r}; "
        f"actions={sorted({e.get('action') for e in entries})}"
    )

    qr = httpx.get(f"{presto_url.rstrip('/')}/v1/query/{query_id}", timeout=10)
    # Gone (404) or cancelled/failed is success. FINISHED is *not*: a query
    # that completed on its own before remediation acted would otherwise green
    # a scenario in which nothing was killed.
    if qr.status_code == 404:
        return
    assert qr.status_code == 200, qr.text
    state = (qr.json().get("state") or "").upper()
    assert state in {"FAILED", "CANCELED", "CANCELLED"}, (
        f"query {query_id} is in state {state!r}; E4 requires it gone or "
        "cancelled/failed by the remediation, not merely terminal"
    )
