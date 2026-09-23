"""FP-IG-20 runtime sibling: Section 11's expected process topology.

Enumerates each product container's live tree **from the kind node**
(``crictl`` for the init PID, then AA's ``/proc/<pid>/task/*/children``
walk on the node). No in-container tooling — the Go images are distroless.

Against the unfixed ingest image: red (1 process, no supervisor/tracker/
workers). dashboard-web and the four singletons are positive controls
against the shipped images (step 0).
"""
from __future__ import annotations

import json
import os
import subprocess
from collections import Counter
from pathlib import Path

import yaml

KIND_CLUSTER = "rca-e2e"
KIND_NODE = "rca-e2e-control-plane"
NAMESPACE = "dbagent"
REPO_ROOT = Path(__file__).resolve().parents[2]
VALUES = REPO_ROOT / "deploy" / "charts" / "dbagent" / "values.yaml"

# (k8s component label, table row id)
PRODUCT_COMPONENTS = (
    "ingest-gateway",
    "dashboard-web",
    "dashboard-api",
    "temporal-worker",
    "probe-gateway",
    "probe",
)


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _node_exec(*args: str) -> str:
    proc = _run(["docker", "exec", KIND_NODE, *args])
    if proc.returncode != 0:
        raise RuntimeError(
            f"docker exec {KIND_NODE} {args!r} failed: {proc.stderr or proc.stdout}"
        )
    return proc.stdout


# Command identity for Section 11's four singleton rows (shape, not a
# full argv match — image paths prefix the binary).
SINGLETON_CMDLINE = {
    "dashboard-api": "dbagent-dashboard-api",
    "temporal-worker": "worker.worker_main",
    "probe-gateway": "probe-gateway",
    "probe": "/probe",
}


def _classify_node(comm: str, cmdline: str) -> str:
    cmd = cmdline or ""
    c = (comm or "").lower()
    if "multiprocessing.resource_tracker" in cmd:
        return "resource_tracker"
    if "multiprocessing.spawn" in cmd:
        return "spawn_worker"
    if "nginx" in c or comm == "nginx":
        if "worker process" in cmd:
            return "nginx_worker"
        return "nginx_master"
    if "gateway.main" in cmd:
        return "supervisor"
    if "probe-gateway" in c or "probe-gateway" in cmd:
        return "probe-gateway"
    if c == "probe" or cmd.rstrip().endswith("/probe"):
        return "probe"
    return c or "unknown"


def assert_ingest_tree(nodes: list[dict], workers: int) -> None:
    """Exact ingest-gateway role multiset: 1 supervisor + 1 tracker + W workers.

    The remaining process after tracker and workers must be the uvicorn
    supervisor identified by ``python -m gateway.main``, not an arbitrary
    filler that merely makes the count ``W + 2``.
    """
    roles = [n["role"] for n in nodes]
    expected = Counter(
        {"supervisor": 1, "resource_tracker": 1, "spawn_worker": workers}
    )
    assert Counter(roles) == expected, (
        f"ingest-gateway want {dict(expected)}, got {roles}"
    )
    supervisor = next(n for n in nodes if n["role"] == "supervisor")
    assert "gateway.main" in (supervisor.get("cmdline") or ""), supervisor


def assert_singleton_tree(component: str, nodes: list[dict]) -> None:
    """Exactly one process whose cmdline carries the image's command identity."""
    assert len(nodes) == 1, f"{component} want 1 process, got {nodes}"
    needle = SINGLETON_CMDLINE[component]
    cmd = nodes[0].get("cmdline") or ""
    if component == "probe":
        assert "probe-gateway" not in cmd, nodes[0]
        assert cmd.rstrip().endswith(needle) or nodes[0].get("comm") == "probe", (
            f"{component} cmdline {cmd!r} does not identify the probe binary"
        )
        return
    assert needle in cmd, (
        f"{component} cmdline {cmd!r} does not contain {needle!r}"
    )


def _walk_tree_on_node(init_pid: int) -> list[dict]:
    """Walk /proc on the kind node. Identity from comm/cmdline."""
    seen: set[int] = set()
    nodes: list[dict] = []
    queue = [init_pid]
    while queue:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        comm = _node_exec("cat", f"/proc/{pid}/comm").strip()
        raw = _node_exec("cat", f"/proc/{pid}/cmdline")
        cmdline = raw.replace("\x00", " ").strip()
        children_txt = ""
        # Concatenate every task's children file.
        listing = _node_exec(
            "sh", "-c", f"cat /proc/{pid}/task/*/children 2>/dev/null || true"
        )
        children_txt = listing.strip()
        children = [int(t) for t in children_txt.split() if t]
        nodes.append(
            {
                "pid": pid,
                "comm": comm,
                "cmdline": cmdline,
                "role": _classify_node(comm, cmdline),
                "children": children,
            }
        )
        queue.extend(c for c in children if c not in seen)
    return nodes


def _container_init_pid(pod: str, container: str) -> int:
    """Resolve the container's PID 1 on the kind node via crictl.

    Only ``CONTAINER_RUNNING`` entries are eligible. After a pod restart
    ``crictl ps -a`` still lists the exited sibling; binding to it yields
    ``pid: 0`` or a stale tree. A target that is not running is a hard
    error rather than a walk of a plausible-looking dead tree.
    """
    ps = _node_exec("crictl", "ps", "-o", "json")
    data = json.loads(ps)
    matches = []
    for c in data.get("containers") or []:
        if c.get("state") != "CONTAINER_RUNNING":
            continue
        meta = c.get("metadata") or {}
        labels = c.get("labels") or {}
        name = meta.get("name") or ""
        pod_name = labels.get("io.kubernetes.pod.name") or ""
        if container in name and pod in pod_name:
            matches.append(c)
    if not matches:
        raise RuntimeError(
            f"no running crictl container matching pod={pod!r} "
            f"container={container!r}"
        )
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one running container matching "
            f"pod={pod!r} container={container!r}, got {len(matches)}"
        )
    cid = matches[0]["id"]
    inspect = json.loads(_node_exec("crictl", "inspect", cid))
    info = inspect.get("info") or inspect
    pid = info.get("pid") or (info.get("runtimeSpec") or {}).get("pid")
    if not pid:
        # containerd: info.pid
        raise RuntimeError(f"crictl inspect {cid} had no pid: {list(info)[:12]}")
    return int(pid)


def _kubectl_json(*args: str) -> dict:
    proc = _run(["kubectl", "-n", NAMESPACE, *args, "-o", "json"])
    if proc.returncode != 0:
        raise RuntimeError(f"kubectl {args} failed: {proc.stderr or proc.stdout}")
    return json.loads(proc.stdout)


def test_runtime_process_topology_matches_the_packaging_table():
    """Section 11 table, row by row, from the kind node's /proc."""
    if not os.environ.get("E2E_INGEST_URL") and _run(["kubectl", "cluster-info"]).returncode != 0:
        raise RuntimeError(
            "kind/kubectl not available; this test runs in the e2e job "
            "and must not skip"
        )
    workers = int(
        yaml.safe_load(VALUES.read_text(encoding="utf-8"))["ingestGateway"]["workers"]
    )
    pods = _kubectl_json("get", "pods")
    by_component: dict[str, dict] = {}
    for pod in pods.get("items") or []:
        labels = pod.get("metadata", {}).get("labels") or {}
        comp = labels.get("app.kubernetes.io/component")
        if comp in PRODUCT_COMPONENTS:
            by_component.setdefault(comp, pod)

    # probe lives in its own chart; accept either label.
    if "probe" not in by_component:
        for pod in pods.get("items") or []:
            name = pod.get("metadata", {}).get("name", "")
            if "probe" in name and "gateway" not in name:
                by_component["probe"] = pod
                break

    missing = [c for c in PRODUCT_COMPONENTS if c not in by_component]
    assert not missing, f"missing product pods: {missing}"

    observed: dict[str, list[dict]] = {}
    for comp, pod in by_component.items():
        pod_name = pod["metadata"]["name"]
        cname = pod["spec"]["containers"][0]["name"]
        init_pid = _container_init_pid(pod_name, cname)
        observed[comp] = _walk_tree_on_node(init_pid)

    # ingest-gateway: W+2 classified (1 supervisor, 1 tracker, W workers).
    assert_ingest_tree(observed["ingest-gateway"], workers)

    # dashboard-web: one nginx master + >= 1 nginx workers, all nginx.
    dw = observed["dashboard-web"]
    assert all("nginx" in n["comm"].lower() for n in dw), [n["comm"] for n in dw]
    masters = [n for n in dw if n["role"] == "nginx_master"]
    workers_n = [n for n in dw if n["role"] == "nginx_worker"]
    assert len(masters) == 1, dw
    assert len(workers_n) >= 1, dw

    for singleton in ("dashboard-api", "temporal-worker", "probe-gateway", "probe"):
        assert_singleton_tree(singleton, observed[singleton])


def _node(comm: str, cmdline: str) -> dict:
    return {
        "comm": comm,
        "cmdline": cmdline,
        "role": _classify_node(comm, cmdline),
    }


def test_ingest_role_multiset_rejects_unclassified_filler():
    """C3: sleep + tracker + W workers is not a legal ingest tree.

    Against a count-only assertion this stays green (len == W+2, one
    tracker, W workers). Red only when the remaining process must be
    the supervisor identified by ``python -m gateway.main``.
    """
    workers = 4
    legal = [
        _node("python", "python -m gateway.main"),
        _node(
            "python",
            "/opt/venv/bin/python -B -c from multiprocessing.resource_tracker import main;main(6)",
        ),
    ] + [
        _node(
            "python",
            f"/opt/venv/bin/python -B -c from multiprocessing.spawn import spawn_main; spawn_main({i}) --multiprocessing-fork",
        )
        for i in range(workers)
    ]
    assert_ingest_tree(legal, workers)

    forged = [
        _node("sleep", "sleep 3600"),
        legal[1],
        *legal[2:],
    ]
    try:
        assert_ingest_tree(forged, workers)
    except AssertionError:
        return
    raise AssertionError(
        "sleep + tracker + W workers stayed green; the remaining process "
        "was never required to be the gateway supervisor"
    )


def _install_crictl(monkeypatch, containers: list[dict], pids_by_id: dict[str, int]) -> None:
    """Drive ``_container_init_pid`` without a kind node."""

    def fake_node_exec(*args: str) -> str:
        if args and args[0] == "crictl" and "ps" in args:
            return json.dumps({"containers": containers})
        if len(args) >= 3 and args[0] == "crictl" and args[1] == "inspect":
            cid = args[2]
            return json.dumps({"info": {"pid": pids_by_id[cid]}})
        raise RuntimeError(f"unexpected node exec {args!r}")

    monkeypatch.setattr(f"{__name__}._node_exec", fake_node_exec)


def _crictl_container(cid: str, *, state: str, pod: str, name: str) -> dict:
    return {
        "id": cid,
        "state": state,
        "metadata": {"name": name},
        "labels": {"io.kubernetes.pod.name": pod},
    }


def test_container_init_pid_does_not_bind_to_exited_sibling(monkeypatch):
    """W2: an exited sibling must not supply the walk's init pid.

    ``crictl ps -a`` lists the dead container first after a restart.
    Taking ``matches[0]`` with no state filter walks a stale tree
    (or ``pid: 0``). Red against that form; green only when enumeration
    is restricted to ``CONTAINER_RUNNING``.
    """
    pod, name = "ingest-gateway-abc", "ingest-gateway"
    _install_crictl(
        monkeypatch,
        [
            _crictl_container("dead", state="CONTAINER_EXITED", pod=pod, name=name),
            _crictl_container("live", state="CONTAINER_RUNNING", pod=pod, name=name),
        ],
        {"dead": 99, "live": 42},
    )
    pid = _container_init_pid(pod, name)
    assert pid == 42, (
        f"bound to pid {pid} (exited sibling is 99); "
        "crictl -a took the first match without a running-state filter"
    )


def test_container_init_pid_fails_when_target_is_not_running(monkeypatch):
    """W2: a target that is not running is a hard error, not a stale walk."""
    pod, name = "ingest-gateway-abc", "ingest-gateway"
    _install_crictl(
        monkeypatch,
        [_crictl_container("dead", state="CONTAINER_EXITED", pod=pod, name=name)],
        {"dead": 99},
    )
    try:
        pid = _container_init_pid(pod, name)
    except RuntimeError as exc:
        msg = str(exc).lower()
        assert "running" in msg, exc
        return
    raise AssertionError(
        f"exited container yielded pid {pid}; "
        "enumeration accepted a non-running target"
    )


def test_container_init_pid_requires_exactly_one_running_match(monkeypatch):
    """W2: two running matches must not silently take ``matches[0]``."""
    pod, name = "ingest-gateway-abc", "ingest-gateway"
    _install_crictl(
        monkeypatch,
        [
            _crictl_container("a", state="CONTAINER_RUNNING", pod=pod, name=name),
            _crictl_container("b", state="CONTAINER_RUNNING", pod=pod, name=name),
        ],
        {"a": 11, "b": 22},
    )
    try:
        pid = _container_init_pid(pod, name)
    except RuntimeError:
        return
    raise AssertionError(
        f"two running matches returned pid {pid}; "
        "took matches[0] instead of requiring exactly one"
    )


def test_singleton_rows_require_command_identity():
    """C3: a singleton row is the named program, not any one process."""
    legal = {
        "dashboard-api": _node(
            "dbagent-dashboa",
            "/opt/venv/bin/python /opt/venv/bin/dbagent-dashboard-api",
        ),
        "temporal-worker": _node("python", "python -m worker.worker_main"),
        "probe-gateway": _node("probe-gateway", "/usr/local/bin/probe-gateway"),
        "probe": _node("probe", "/usr/local/bin/probe"),
    }
    for component, node in legal.items():
        assert_singleton_tree(component, [node])

    for component in legal:
        try:
            assert_singleton_tree(component, [_node("sleep", "sleep 1")])
        except AssertionError:
            continue
        raise AssertionError(
            f"{component} accepted an arbitrary sleep process; "
            "only cardinality was checked"
        )
