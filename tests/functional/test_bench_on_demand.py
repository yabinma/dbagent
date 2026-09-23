"""bench-on-demand: the launcher's retired targets, and the runbook (FP-BOD-2/6).

Three function tests and the unit coverage of the launcher exits behind them.
Every literal is declared here, independently of the files it pins: a check
derived from its own subject detects nothing.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = REPO_ROOT / "scripts" / "integration-test.sh"
RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "bench-on-demand.md"

#: The three targets this slice deletes. Each must be refused with the
#: launcher's ordinary unknown-target status, BEFORE the relay gate: a target
#: that merely fails later is still a target.
RETIRED_TARGETS = ("b1", "b1_latency_basis", "b1_topology_probe")
#: The target that stays, and the one the usage text must still offer.
PRODUCT_TARGET = "b1_product"
UNKNOWN_TARGET_EXIT = 2
HELP_EXIT = 0

#: The release trigger's two commands and the record path, as the runbook must
#: spell them.
RUNBOOK_B1_COMMAND = "/opt/gitspace/dbagent/scripts/integration-test.sh b1_product"
RUNBOOK_B11_COMMAND = (
    "tests/benchmark/test_pg_scale.py::test_b11_audit_llm_insert_throughput"
)
RUNBOOK_RESULTS_PATH = "docs/runbooks/bench-on-demand-results.txt"
#: The performance-investigation trigger's two named product paths.
RUNBOOK_INVESTIGATION_PATHS = (
    "services/gateway/gateway/ingest.py",
    "services/gateway/gateway/merge_commit.py",
)
#: The release procedure, clause by clause.
RUNBOOK_RELEASE_CLAUSES = (
    "git status --porcelain",
    "git rev-parse HEAD",
    "measured_sha",
    "only when both commands exited 0",
    "Commit only that file",
    "Push the commit to `main`",
    "Tag that commit",
)
#: The clean-tree precondition: TRACKED changes only. The jail dotfiles at the
#: repo root are untracked and never committed, so a bare porcelain check could
#: never pass on the host that runs the procedure.
RUNBOOK_PORCELAIN_BARE = "git status --porcelain"
RUNBOOK_PORCELAIN_TRACKED = "git status --porcelain --untracked-files=no"
#: The two sections that state the precondition.
RUNBOOK_PRECONDITION_SECTIONS = ("## The two commands", "## Release steps")
#: The B11 alternative for a sandboxed shell: the declared runner-image route.
RUNBOOK_B11_HOST_VENV = "services/worker/.venv/bin/python -m pytest"
#: The connection mode is load-bearing: inside a container testcontainers
#: otherwise ignores the override and dials the Docker gateway (observed
#: 2026-09-23: "connection to server at 172.17.0.1 ... Connection refused").
RUNBOOK_B11_SANDBOX_TOKENS = (
    "docker run --rm --network host",
    "TESTCONTAINERS_CONNECTION_MODE=docker_host",
    "TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1",
    "TESTCONTAINERS_RYUK_DISABLED=true",
    "dbagent-review-runner:latest",
    RUNBOOK_B11_COMMAND,
    "-v -s",
)


def _run_launcher(target: str) -> subprocess.CompletedProcess:
    """Invoke the tracked launcher with one argument, in a clean environment.

    The relay gate is deliberately NOT satisfied here: the point of the test
    is that an unknown target is refused by the argument `case` before the
    gate runs at all, so a sandboxed environment reaches the same verdict a
    developer host does.
    """
    return subprocess.run(
        ["bash", str(LAUNCHER), target],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_integration_test_sh_rejects_retired_b1_targets():
    """FP-BOD-2 [function test]: the launcher still accepts `b1` or the probe.

    Named for a launcher that kept a CI-scale or recorded route. Each retired
    name is INVOKED and must exit 2 -- the ordinary unknown-target status --
    and the usage text must not list it.

    Grepping for the absence of the letters `topology` would be red on a
    comment that describes the deletion, and green on a target that still
    exists under another spelling. The exit status is the target's own answer
    to "do you exist", so that is what is read.
    """
    assert LAUNCHER.is_file()

    for target in RETIRED_TARGETS:
        result = _run_launcher(target)
        assert result.returncode == UNKNOWN_TARGET_EXIT, (
            f"{target!r} exited {result.returncode}: "
            f"{result.stdout[-400:]!r} {result.stderr[-400:]!r}"
        )
        assert f"unknown target '{target}'" in result.stderr, result.stderr

    # ...and the help path, which runs before the relay gate too, no longer
    # offers them.
    help_result = _run_launcher("--help")
    assert help_result.returncode == HELP_EXIT, help_result.stderr
    usage = help_result.stdout
    assert PRODUCT_TARGET in usage, usage
    for target in RETIRED_TARGETS:
        assert f"|{target}|" not in usage, f"usage still offers {target!r}"
        assert f"| {target} |" not in usage, f"usage still offers {target!r}"
        assert f"\n  {target} " not in usage, f"usage still describes {target!r}"

    # The surviving target is still a `case` arm, not just usage prose.
    source = LAUNCHER.read_text(encoding="utf-8")
    assert f"  {PRODUCT_TARGET}) run_step " in source, source[:0] or "case arm missing"
    for target in RETIRED_TARGETS:
        assert f"  {target}) run_step " not in source, f"{target} still dispatches"
    # The relay override admits exactly the two targets that remain.
    assert "    preflight|b1_product) return 0 ;;" in source
    assert 'echo "  admitted targets    : preflight b1_product"' in source


def test_bench_on_demand_runbook_names_triggers_and_commands():
    """FP-BOD-6 [function test]: the runbook says WHEN, WHAT and WHERE.

    Named for a runbook that exists and does not say when a run is required or
    which command to use. A file that merely mentions B1 would pass a
    existence check and leave an operator with no procedure, so every clause
    of the release procedure, both investigation paths, both commands and the
    results path are required by name.
    """
    assert RUNBOOK.is_file(), f"{RUNBOOK} is missing"
    text = RUNBOOK.read_text(encoding="utf-8")

    # (1) The two triggers.
    assert "Release" in text and "v*" in text
    assert "Performance investigation" in text
    for path in RUNBOOK_INVESTIGATION_PATHS:
        assert path in text, f"the investigation trigger does not name {path}"

    # (2) The two commands and the results path.
    assert RUNBOOK_B1_COMMAND in text, "the B1 command is missing"
    assert RUNBOOK_B11_COMMAND in text, "the B11 node id is missing"
    assert RUNBOOK_RESULTS_PATH in text, "the results path is missing"

    # (3) The release procedure, clause by clause, in order.
    positions = []
    for clause in RUNBOOK_RELEASE_CLAUSES:
        assert clause in text, f"the release procedure omits {clause!r}"
        positions.append(text.index(clause))
    # "copy only after both commands exited 0" must precede the commit and the
    # tag: a runbook that commits first documents the wrong procedure.
    copy_at = text.index("only when both commands exited 0")
    assert copy_at < text.index("Commit only that file")
    assert text.index("Commit only that file") < text.index("Tag that commit")

    # (4) It adds no third benchmark, no skip flag and no way to tag without
    # the record.
    for forbidden in ("--skip", "SKIP_BENCH", "without the record", "b1_latency_basis"):
        assert forbidden not in text, f"the runbook offers {forbidden!r}"


def _runbook_section(text: str, heading: str) -> str:
    """The body of one `## ` section, up to the next `## ` heading."""
    start = text.index(heading)
    end = text.find("\n## ", start + len(heading))
    return text[start:] if end == -1 else text[start:end]


def _fenced_blocks(text: str) -> list[str]:
    """Every fenced code block's body, in document order."""
    blocks = []
    lines = text.splitlines()
    opened = None
    for number, line in enumerate(lines):
        if line.startswith("```"):
            if opened is None:
                opened = number
            else:
                blocks.append("\n".join(lines[opened + 1:number]))
                opened = None
    return blocks


def test_bench_on_demand_runbook_is_followable_from_this_host():
    """FP-BOD-6 [function test]: the procedure can be followed where it runs.

    Named for two wording defects (fix.md, 2026-09-23). The clean-tree
    precondition must demand no TRACKED changes: a bare
    `git status --porcelain` also lists the untracked jail dotfiles that are
    never committed, so it never prints nothing on this host. Every occurrence
    of the porcelain command is read, so one bare survivor in either section
    is red.

    And a sandboxed shell cannot reach a published testcontainers port, so the
    B11 command must have its runner-image alternative. The tokens are read
    from the ONE fenced block that holds `docker run`, so the host-venv block's
    node id cannot satisfy the alternative's.
    """
    text = RUNBOOK.read_text(encoding="utf-8")

    # (1) Every porcelain check is the tracked-only one, in both sections.
    occurrences = []
    at = text.find(RUNBOOK_PORCELAIN_BARE)
    while at != -1:
        occurrences.append(at)
        at = text.find(RUNBOOK_PORCELAIN_BARE, at + 1)
    assert len(occurrences) >= len(RUNBOOK_PRECONDITION_SECTIONS), occurrences
    for at in occurrences:
        found = text[at:at + len(RUNBOOK_PORCELAIN_TRACKED)]
        assert found == RUNBOOK_PORCELAIN_TRACKED, (
            f"a bare porcelain check at offset {at} still demands an empty "
            f"untracked set: {text[at:at + 80]!r}"
        )
    for heading in RUNBOOK_PRECONDITION_SECTIONS:
        section = _runbook_section(text, heading)
        assert RUNBOOK_PORCELAIN_TRACKED in section, (
            f"{heading!r} does not state the tracked-only precondition"
        )
    assert "never committed" in text, "the untracked-file allowance is unqualified"

    # (2) The host-venv command stays primary; the runner-image route follows.
    blocks = _fenced_blocks(text)
    host = [b for b in blocks if RUNBOOK_B11_HOST_VENV in b and RUNBOOK_B11_COMMAND in b]
    sandbox = [b for b in blocks if "docker run" in b]
    assert len(host) == 1, "the host-venv B11 command is missing or repeated"
    assert len(sandbox) == 1, f"expected one runner-image B11 block, found {len(sandbox)}"
    assert blocks.index(host[0]) < blocks.index(sandbox[0]), (
        "the runner-image route must follow the primary host-venv command"
    )
    for token in RUNBOOK_B11_SANDBOX_TOKENS:
        assert token in sandbox[0], f"the runner-image B11 block omits {token!r}"
