"""Sanity checks for the benchmark/functional checkpoint manifests
(design.md Section 14.3/14.4). FP-M6-26: honesty rules enforced in code.

Errata passes 11-21 / design.md section 11.1.3: linked covered tests must
contain an executable threshold assertion (parser-backed), with L0 binding
resolution, collection/skip/dead/swallowed rules, and CI-pin machinery.
"""
from __future__ import annotations

import ast
import configparser
import copy
import json
import os
import re
import shlex
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]

EXPECTED_BENCHMARK_IDS = {f"B{i}" for i in range(1, 15)}
EXPECTED_CHECKPOINT_IDS = {f"F{i}" for i in range(1, 19)}
VALID_STATUSES = {"covered", "partial", "deferred"}
SHIPPED_MILESTONES = {"M1", "M2", "M3", "M4", "M5", "M6"}

GO_GUARD = "tests/functional/manifest_honesty/thresholds_test.go"
GO_GUARD_FUNC = "func TestManifestGoTestsAssertTheirThresholds("

_FORWARD_PHRASES = [
    r"needs",
    r"remains a",
    r"remains an",
    r"remains the",
    r"is deferred",
    r"are deferred",
    r"deferred to",
    r"still deferred",
    r"still partial",
    r"revisit at",
    r"revisited at",
    r"will be covered",
    r"will be addressed",
    r"to be covered",
    r"not built yet",
    r"not yet built",
    r"TODO",
]
_PHRASE_RE = re.compile(
    r"\b(?:" + "|".join(_FORWARD_PHRASES) + r")\b",
    re.IGNORECASE,
)
_MILESTONE_RE = re.compile(r"\bM[1-9]\b")

_ORDERED_OPS = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)
_NUMERIC_BINOPS = (ast.Add, ast.Sub, ast.Mult, ast.Div)
_NESTED_SCOPE = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_NUMERIC_DEPTH_CAP = 3

THRESHOLD_REASONS: frozenset[str] = frozenset({
    "missing_file",
    "unknown_suffix",
    "missing_go_guard",
    "build_context",
    "not_collected",
    "nonexistent_linked_test",
    "ambiguous_test_name",
    "skipped",
    "no_candidate",
    "dead_candidate",
    "not_a_threshold_comparison",
    "swallowed_candidate",
    "no_fail_in_branch",
    "both_operands_numeric",
    "star_import",
    "unresolved_identifier",
    "no_numeric_term",
    "not_testify",
    "bad_testing_t",
    "spread_operand",
    "bad_tolerance",
    "dot_import",
})
assert len(THRESHOLD_REASONS) == 22

CI_PIN_REASONS: frozenset[str] = frozenset({
    "go_build_tag_flag",
    "go_race_or_short_flag",
    "go_env_key",
    "go_version_mismatch",
    "missing_setup_go",
    "go_runner_drift",
    "go_test_job_inventory",
    "job_inventory",
    "python_optimize_flag",
    "python_env_key",
    "github_env_write",
    "e2e_command_drift",
    "missing_e2e_hygiene_gate",
    "pytest_collection_override",
    "setup_go_ordering",
    "run_not_recognized",
    "go_test_command_unparsed",
    "github_path_write_drift",
    "pytest_config_inventory",
    "conftest_collection_hook",
    "pytest_command_drift",
    "pytest_config_unreadable",
    "step_envelope_drift",
    "guarded_step_shape",
    "command_operand_drift",
    "go_test_command_drift",
    "needs_graph_drift",
    "guard_context_drift",
})
assert len(CI_PIN_REASONS) == 28
assert THRESHOLD_REASONS & CI_PIN_REASONS == set()

EXPECTED_CI_JOBS = {
    "lint",
    "manifest-guard",
    "unit-rca-common",
    "unit-worker",
    "unit-gateway",
    "unit-dashboard-api",
    "unit-web",
    "unit-go",
    "functional",
    "benchmark",
    "images",
    "e2e",
    # bench-on-demand FP-BOD-5: the `v*` tag gate. Conditional, and upstream of
    # `images` so a red record stops the push.
    "release-bench-record",
}
GO_TEST_JOBS = {"unit-go", "functional", "benchmark", "manifest-guard"}
GO_TOOLCHAIN_ENV_NAMES = {"CC", "CXX", "FC", "AR", "PKG_CONFIG"}
PYTHON_OPT_JOBS = {"functional", "benchmark", "e2e", "manifest-guard"}
RACE_SHORT_BAN_JOBS = {"functional", "benchmark", "manifest-guard"}

GUARDED_STEPS: dict[str, list[int]] = {
    "unit-rca-common": [3],
    "unit-worker": [3],
    "unit-gateway": [3],
    "unit-dashboard-api": [3],
    "unit-go": [7],
    # bench-on-demand FP-BOD-1: index 9 is the measured pytest step, which is
    # now an unparsed reviewable literal (see EXPECTED_FUNCTIONAL_PYTEST_RUN),
    # so the guarded-step envelope covers the Go step alone.
    "functional": [10],
    # bench-on-demand FP-BOD-1: the two B1 wrapper steps are deleted, so the
    # benchmark job has no bash-wrapper step left at all and its indices close
    # up. Steps 16 and 17 are the A10(v) hygiene gate and the B2/B10 node-id
    # pytest; 18 is the sizing-ledger provenance gate.
    "benchmark": [7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18],
    "manifest-guard": [5, 6],
}

EXPECTED_NEEDS_GRAPH: dict[str, tuple[str, ...]] = {
    "lint": (),
    "manifest-guard": (),
    "unit-rca-common": ("lint",),
    "unit-worker": ("lint",),
    "unit-gateway": ("lint",),
    "unit-dashboard-api": ("lint",),
    "unit-web": ("lint",),
    "unit-go": ("lint",),
    "functional": (
        "unit-dashboard-api",
        "unit-gateway",
        "unit-go",
        "unit-rca-common",
        "unit-web",
        "unit-worker",
    ),
    "benchmark": ("functional",),
    # bench-on-demand FP-BOD-5: `images` waits for the tag gate as well as
    # lint, so a `v*` tag whose bench record is missing, stale or failing
    # never reaches the GHCR push.
    "images": ("lint", "release-bench-record"),
    "e2e": ("functional",),
    # No edge at all: the record job reads a committed file and runs no
    # benchmark, so nothing gates it and it gates only `images` through the
    # `needs` above.
    "release-bench-record": (),
}
assert set(EXPECTED_NEEDS_GRAPH) == EXPECTED_CI_JOBS

EXPECTED_GO_TEST_COMMANDS: dict[str, list[tuple[str | None, str]]] = {
    "unit-go": [(None, "go test ./... -race -timeout 300s -p 1")],
    "functional": [(None, "go test ./tests/functional/... -v -timeout 300s")],
    "benchmark": [
        (None, "go test ./services/probe-gateway/internal/gwserver/... -run TestB3 -v -timeout 60s"),
        (None, "go test ./services/probe-gateway/internal/gwserver/... -run TestB4 -v -timeout 60s"),
        (None, "go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s"),
        (None, "go test ./probe/internal/adapter/presto/... -run TestB9 -v -timeout 60s"),
    ],
    "manifest-guard": [
        (None, "go test ./tests/functional/manifest_honesty/... -v -timeout 300s"),
    ],
}
assert set(EXPECTED_GO_TEST_COMMANDS) == GO_TEST_JOBS

EXPECTED_PYTEST_COMMANDS: dict[str, list[tuple[str | None, str]]] = {
    "unit-rca-common": [(
        "libs/py/rca_common",
        ".venv/bin/python -m pytest tests/ --cov=rca_common "
        "--cov-report=term-missing --cov-fail-under=81",
    )],
    "unit-worker": [(
        "services/worker",
        ".venv/bin/python -m pytest tests/ --cov=worker --cov=scripts "
        "--cov-report=term-missing --cov-fail-under=81",
    )],
    "unit-gateway": [(
        "services/gateway",
        ".venv/bin/python -m pytest tests/ --cov=gateway "
        "--cov-report=term-missing --cov-fail-under=81 "
        "--ignore=tests/test_b1_ingest_burst.py",
    )],
    "unit-dashboard-api": [(
        "services/dashboard-api",
        ".venv/bin/python -m pytest tests/ --cov=dashboard_api "
        "--cov-report=term-missing --cov-fail-under=81",
    )],
    "benchmark": [
        (None, "services/worker/.venv/bin/python -m pytest tests/functional/test_manifests.py -v"),
        (None, "services/worker/.venv/bin/python -m pytest "
         "libs/py/rca_common/tests/test_rawcmd.py::test_b6_static_validator_under_5ms -v"),
        (None, "services/worker/.venv/bin/python -m pytest "
         "services/dashboard-api/tests/test_b12_hot_endpoints.py -v"),
        (None, "services/worker/.venv/bin/python -m pytest "
         "services/worker/tests/test_investigation_workflow.py"
         "::test_b13_round_loop_overhead_under_1s -v"),
        (None, "services/worker/.venv/bin/python -m pytest "
         "services/worker/tests/test_context_assembly.py"
         "::test_b14_prompt_build_under_200ms_and_no_latest_truncation -v"),
        (None, "services/worker/.venv/bin/python -m pytest "
         "tests/benchmark/test_pg_scale.py::test_b2_fingerprint_correlation_p99_under_20ms "
         "tests/benchmark/test_pg_scale.py::test_b10_partitioned_list_and_filter_p99 "
         "tests/benchmark/test_pg_scale.py::test_b11_host_parser_reuse_is_direct "
         "tests/benchmark/test_pg_scale.py::test_b11_host_diagnostics_read_declared_sources "
         "tests/benchmark/test_pg_scale.py::test_b11_host_reader_observes_real_proc_stat "
         "tests/benchmark/test_pg_scale.py"
         "::test_b11_storage_identity_reads_target_postgres_container "
         "tests/benchmark/test_pg_scale.py"
         "::test_b11_storage_identity_fails_soft_without_substituting_another_mount "
         "tests/benchmark/test_pg_scale.py"
         "::test_b11_diagnostics_schema_is_canonical_and_comma_safe "
         "tests/benchmark/test_pg_scale.py"
         "::test_b11_diagnostic_sampling_brackets_the_timed_window -v -s"),
        (None, "services/worker/.venv/bin/python -m pytest "
         "tests/delivery/test_delivery_sizing_ledger.py -v"),
    ],
    "manifest-guard": [
        (None, "services/worker/.venv/bin/python -m pytest tests/functional/test_manifests.py -v"),
    ],
}
assert set(GUARDED_STEPS) == GO_TEST_JOBS | set(EXPECTED_PYTEST_COMMANDS)

# bench-on-demand FP-BOD-1: EMPTY, and the emptiness is the pin. Every
# `scripts/integration-test.sh` wrapper step is deleted -- the CI-scale gate,
# the CPU-basis oracle and the topology sweep alike -- so no CI job delegates a
# B1 run to the launcher at all. A re-added wrapper is extra, and
# `test_ci_does_not_run_b1_or_b11` names it by target.
EXPECTED_BASH_WRAPPER_COMMANDS: dict[str, list[tuple[int, str]]] = {}

EXPECTED_E2E_PYTEST_COMMAND = "python3 -m pytest tests/e2e -v --tb=short"
EXPECTED_E2E_HYGIENE_COMMAND = (
    'bad="$(awk \'BEGIN { for (k in ENVIRON) { p = substr(k, 1, 6); '
    'if (p != "PYTHON" && p != "PYTEST") continue; print k } }\')"; '
    'if [ -n "$bad" ]; then printf \'e2e env hygiene: forbidden PYTHON*/PYTEST* '
    'environment key present before the measured invocation:\\n%s\\n\' "$bad" >&2; exit 1; fi'
)
EXPECTED_CI_HYGIENE_RUN = (
    'bad="$(awk \'BEGIN { for (k in ENVIRON) { p = substr(k, 1, 6); '
    'if (p != "PYTHON" && p != "PYTEST") continue; print k } }\')"; '
    'if [ -n "$bad" ]; then printf \'FP-M6-31 A10(v): forbidden PYTHON*/PYTEST* '
    'environment key present before the measured invocation:\\n%s\\n\' "$bad" >&2; exit 1; fi'
)
EXPECTED_E2E_GITHUB_PATH_LINES = {
    'echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"',
}

# bench-on-demand FP-BOD-1/5 (design.md §3.2): the functional job's measured
# step. It carries THREE pytest invocations in one body -- the broad functional
# run, the tag-gate script's own branch-coverage run, and the B1 harness
# coverage phase that moved here out of the deleted driver container -- because
# FP-M6-31 A10(v) pins exactly one measured pytest STEP per guarded job,
# immediately after the hygiene gate.
#
# It is pinned as an UNPARSED REVIEWABLE LITERAL, for the same reason the
# images push body below is: the closed `run:` grammar refuses a quoted word
# containing whitespace, and `-m "not b1_live and not b1_product"` is exactly
# that. Byte equality is the stronger pin -- a pipe, a redirect, a command
# substitution, a dropped `--ignore` or a widened marker expression all change
# these bytes -- and `_b1_route_failures` plus
# `test_on_demand_tier_is_covered_asserted_and_absent_from_ci` read the same
# step for the B1 clauses specifically.
EXPECTED_FUNCTIONAL_PYTEST_RUN = (
    'services/worker/.venv/bin/python -m pytest \\\n'
    '  services/worker/tests services/gateway/tests \\\n'
    '  services/dashboard-api/tests \\\n'
    '  tests/functional tests/delivery tests/mocks/llm -v \\\n'
    '  --ignore=tests/functional/m2_probe_link \\\n'
    '  --ignore=services/gateway/tests/test_b1_ingest_burst.py \\\n'
    '  --ignore=tests/delivery/test_delivery_sizing_ledger.py\n'
    'services/worker/.venv/bin/python -m pytest \\\n'
    '  tests/functional/test_release_bench_record.py -v \\\n'
    '  --cov=check_release_bench_record --cov-branch --cov-fail-under=81\n'
    'env -u PYTHON_VERSION -u PYTHON_PIP_VERSION -u PYTHON_GET_PIP_URL -u PYTHON_GET_PIP_SHA256 \\\n'
    '  services/worker/.venv/bin/python -B -m coverage run --branch \\\n'
    '  --data-file="$RUNNER_TEMP/b1-harness.coverage" \\\n'
    '  -m pytest services/gateway/tests/test_b1_ingest_burst.py -v \\\n'
    '  -m "not b1_live and not b1_product"\n'
    'services/worker/.venv/bin/python -B -m coverage report --data-file="$RUNNER_TEMP/b1-harness.coverage" --fail-under=81 --include=services/gateway/tests/b1_reference_profile.py,services/gateway/tests/test_b1_ingest_burst.py,scripts/b1-affinity-helper.py\n'
    'services/worker/.venv/bin/python -B -m coverage report --data-file="$RUNNER_TEMP/b1-harness.coverage" --fail-under=81 --include=services/gateway/tests/b1_reference_profile.py\n'
    'services/worker/.venv/bin/python -B -m coverage report --data-file="$RUNNER_TEMP/b1-harness.coverage" --fail-under=81 --include=services/gateway/tests/test_b1_ingest_burst.py\n'
    'services/worker/.venv/bin/python -B -m coverage report --data-file="$RUNNER_TEMP/b1-harness.coverage" --fail-under=81 --include=scripts/b1-affinity-helper.py'
)

# (AG)(5): the images GHCR-push body is pinned as a reviewable literal — never
# derived from the workflow file it is supposed to protect (review C2).
EXPECTED_IMAGES_PUSH_RUN = (
    "set -euo pipefail\n"
    "source deploy/versions.env\n"
    'echo "${{ secrets.GITHUB_TOKEN }}" | docker login ghcr.io -u "${{ github.actor }}" --password-stdin\n'
    'SHORT_SHA="${GITHUB_SHA::12}"\n'
    "for c in ingest-gateway temporal-worker probe-gateway dashboard-api dashboard-web probe; do\n"
    '  docker push "${REGISTRY}/${c}:${APP_VERSION}"\n'
    '  docker push "${REGISTRY}/${c}:sha-${SHORT_SHA}"\n'
    "done"
)

#: bench-on-demand FP-BOD-5: the tag gate's two bodies, byte-pinned. `git` and
#: `python3` are outside the closed command-word grammar on purpose -- nothing
#: else in this workflow runs either -- so the job's steps are pinned here
#: instead of parsed.
EXPECTED_RELEASE_RECORD_FETCH_RUN = "git fetch origin main:refs/remotes/origin/main"
EXPECTED_RELEASE_RECORD_CHECK_RUN = "python3 scripts/check_release_bench_record.py"

#: (AG)(5) exception list, bound beside the literals it names.
PINNED_EXECUTABLE_RUNS = frozenset({
    EXPECTED_FUNCTIONAL_PYTEST_RUN,
    EXPECTED_RELEASE_RECORD_CHECK_RUN,
})

UNPARSED_RUN_STEPS: dict[str, list[str]] = {
    "functional": [EXPECTED_CI_HYGIENE_RUN, EXPECTED_FUNCTIONAL_PYTEST_RUN],
    # bench-on-demand FP-BOD-1: one hygiene gate, not two -- the gate that
    # existed only immediately before the deleted B1 step went with it.
    "benchmark": [EXPECTED_CI_HYGIENE_RUN],
    "manifest-guard": [EXPECTED_CI_HYGIENE_RUN],
    "images": [EXPECTED_IMAGES_PUSH_RUN],
    "release-bench-record": [
        EXPECTED_RELEASE_RECORD_FETCH_RUN,
        EXPECTED_RELEASE_RECORD_CHECK_RUN,
    ],
}


RUN_COMMAND_WORDS = frozenset({
    "go",
    "bash",
    "echo",
    "python",
    "npm",
    "set",
    "source",
    "export",
    "curl",
    "tar",
    "sudo",
    "chmod",
    "helm",
    ".venv/bin/pip",
    ".venv/bin/python",
    "services/worker/.venv/bin/pip",
    "services/worker/.venv/bin/python",
    "services/gateway/.venv/bin/pip",
    "services/dashboard-api/.venv/bin/pip",
    # bench-on-demand FP-BOD-1 (design.md §3.2): the B1 harness coverage
    # command runs under `env -u PYTHON_VERSION …`, exactly as the deleted
    # driver container ran it. Admitting the word does not admit a shape: the
    # guarded-step checks below still reject a pipe, a redirect, a command
    # substitution and an inline assignment in the same step.
    "env",
})
assert len(RUN_COMMAND_WORDS) == 20

GUARDED_STEP_COMMAND_WORDS = frozenset({
    "go", "bash", ".venv/bin/python", "services/worker/.venv/bin/python", "env",
})
BASH_SCRIPTS = frozenset({
    # GC-1 FP-GC1-2: the B1 benchmark step is a wrapper around the tracked
    # launcher, so the bash operand grammar must admit it by name. Without
    # this admission the workflow parser rejects the step outright and the
    # route pin never gets to compare it.
    "scripts/integration-test.sh",
    "scripts/gen-proto.sh",
    "scripts/go-coverage-check.sh",
    "../../scripts/py-coverage-check.sh",
    "../../../scripts/py-coverage-check.sh",
    "deploy/docker/build.sh",
    "tests/e2e/run.sh",
})
SUDO_NESTED_COMMANDS = frozenset({"mv"})
PYTHON_MODULES = frozenset({"pytest", "venv", "compileall"})
GO_INSTALL_TARGETS = frozenset({
    "google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.5",
    "google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1",
})
COMMAND_OPERANDS = RUN_COMMAND_WORDS | SUDO_NESTED_COMMANDS

EXPECTED_CHAIN_CONFIG_FILES = frozenset({
    "pytest.ini",
    "libs/py/rca_common/alembic.ini",
    "libs/py/rca_common/pyproject.toml",
    "services/gateway/pyproject.toml",
    "services/worker/pyproject.toml",
    "services/dashboard-api/pyproject.toml",
})
# `markers` joins the allowlist for GC-1's three routing markers. It is not a
# collection override: registering a marker name changes no selection, no
# rootdir, no python_files/python_functions pattern and no ignore set -- it
# only stops pytest warning about an unknown mark. The exact three names are
# pinned independently by test_ci_and_local_b1_route_are_identical.
PYTEST_OPTION_ALLOWLIST = frozenset({"asyncio_mode", "markers"})
ADMITTED_DECORATOR_ORIGINS = frozenset({"pytest.fixture", "pytest_asyncio.fixture"})
SKIP_MARKERS = frozenset({
    "skip", "skipif", "xfail", "expectedFailure", "skipIf", "skipUnless",
})
SUPPRESSOR_CM = frozenset({"raises", "warns", "suppress", "xfail"})
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_LITERAL_OK = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./:=@+-")
# (AG)(1)(4) braced expansions: default-deny. Accept only bare ${NAME} and the
# numeric-offset form ${NAME::digits} / ${NAME:offset:length} that ci.yml uses
# (e.g. ${GITHUB_SHA::12}). Reject @P/@Q/… transforms, :-/:=/:?/:+ defaults,
# #/%// pattern ops, ${!indirection}, ${#length}, and every other transform.
_BRACED_PARAM_RE = re.compile(
    r"\A[A-Za-z_][A-Za-z0-9_]*"
    r"(?:"
    r":[0-9]*:[0-9]+"  # :offset:length, including empty offset (::12)
    r"|"
    r":[0-9]+"  # :offset alone
    r")?\Z"
)

CONDITIONAL_JOBS = {
    # bench-on-demand FP-BOD-5: the tag gate, and nothing else. The condition
    # is on the ref alone -- it is not a condition on B1 or B11, which this
    # job never runs.
    "release-bench-record": "startsWith(github.ref, 'refs/tags/v')",
    # bench-on-demand FP-BOD-5: `always()` is what lets `images` run on a pull
    # request, where the record job is skipped. A FAILED record job is neither
    # `success` nor `skipped`, so the images job does not build and does not
    # push. This is the `v*` tag gate, pinned by equality.
    "images": (
        "always() && needs.lint.result == 'success' && "
        "(needs.release-bench-record.result == 'success' || "
        "needs.release-bench-record.result == 'skipped')"
    ),
    "e2e": (
        "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || "
        "startsWith(github.ref, 'refs/tags/') || github.event_name == 'pull_request' || "
        "github.ref == 'refs/heads/main'"
    ),
}
CONDITIONAL_STEPS = {
    "images": [(7, "github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')")],
    # bench-on-demand FP-BOD-8: the success-only B1 diagnostics upload is
    # deleted with the module that wrote its file, so the failure upload
    # shifts back to index 7. It is LAST in the job and after the e2e command,
    # so it cannot convert that command's exit status into success.
    "e2e": [(7, "failure()")],
}


#: The command words a PINNED body may begin a line with. It is the ordinary
#: closed set plus the two the tag gate needs: the record checker runs on the
#: runner's own stdlib interpreter, and the release branch is fetched with
#: git. Neither word is admitted anywhere the grammar parses, so neither can
#: enter the workflow except through a byte-pinned literal above.
#: The command words a PINNED line may BEGIN with. Deliberately far narrower
#: than COMMAND_OPERANDS: the parsed grammar admits `curl`, `tar`, `sudo`,
#: `source`, `helm`, `npm` and friends because setup steps legitimately need
#: them, and a MEASURED step never does. Only these five can head a line in a
#: body that skips the parser.
PINNED_BODY_COMMAND_WORDS = frozenset({
    "bash", "env", "git", "python3",
    ".venv/bin/python", "services/worker/.venv/bin/python",
})
#: The only modules a pinned body may select with python's own `-m`.
PINNED_BODY_PYTHON_MODULES = frozenset({"pytest", "coverage"})
#: `git`'s only admitted subcommand here: the tag gate fetches the release
#: branch so ancestry is answerable, and does nothing else.
PINNED_BODY_GIT_SUBCOMMANDS = frozenset({"fetch"})
#: Flags that turn any of the heads above into a general interpreter. `-c`
#: is the whole point of the S1 gap: `bash -c '…'`, `python3 -c '…'` and
#: `sh -c '…'` all run arbitrary text that no operand rule can read.
PINNED_BODY_FORBIDDEN_FLAGS = frozenset({
    "-c", "--command", "-exec", "--exec", "-e", "--eval", "-i", "--interactive",
})


def _pinned_body_is_python(word: str) -> bool:
    base = word.rsplit("/", 1)[-1]
    return base in {"python", "python3"} or base.startswith("python3.")


def _pinned_body_operand_failures(tokens: "list[str]") -> list[str]:
    """The operand grammar, restated for one line of a pinned body.

    `_check_operands` decides this for every PARSED step; a pinned body never
    reaches it, so the same questions are asked here. It is not a paraphrase
    of that function -- it is stricter, because the shapes a measured step may
    take are a small subset of the shapes a setup step may take.
    """
    fails: list[str] = []
    head = tokens[0]
    for flag in tokens:
        if flag in PINNED_BODY_FORBIDDEN_FLAGS:
            fails.append(f"carries the interpreter flag {flag!r}")
    if head == "bash":
        script = next((t for t in tokens[1:] if not t.startswith("-")), None)
        if script not in BASH_SCRIPTS:
            fails.append(f"bash runs {script!r}, which is not an admitted script")
        # bench-on-demand FP-BOD-1: the parsed grammar admits the tracked
        # launcher because a setup step legitimately may call it. A MEASURED
        # step may not: no CI job delegates a B1 run any more.
        if script == "scripts/integration-test.sh":
            fails.append("a measured body delegates to the tracked launcher")
        return fails
    if head == "git":
        subcommand = tokens[1] if len(tokens) > 1 else None
        if subcommand not in PINNED_BODY_GIT_SUBCOMMANDS:
            fails.append(f"git runs {subcommand!r}")
        return fails
    rest = tokens
    if head == "env":
        index = 1
        while index < len(rest) and rest[index] == "-u":
            index += 2  # `-u NAME`: an UNSET, never a binding
        if index >= len(rest) or not _pinned_body_is_python(rest[index]):
            fails.append("env does not wrap an admitted interpreter")
            return fails
        rest = rest[index:]
    if not _pinned_body_is_python(rest[0]):
        fails.append(f"line head {head!r} is not an admitted command word")
        return fails
    # A python-family command either selects an admitted module with `-m`, or
    # runs exactly one tracked `.py` file and nothing else.
    module_flags = [i for i, t in enumerate(rest) if t == "-m"]
    if not module_flags:
        positional = [t for t in rest[1:] if not t.startswith("-")]
        if len(positional) != 1 or not positional[0].endswith(".py"):
            fails.append(f"python runs {positional!r}, not one tracked script")
        return fails
    seen_pytest = False
    for i in module_flags:
        value = rest[i + 1] if i + 1 < len(rest) else None
        if seen_pytest:
            continue  # pytest's own `-m`: a marker expression, not a module
        if value not in PINNED_BODY_PYTHON_MODULES:
            fails.append(f"python -m selects {value!r}")
        seen_pytest = seen_pytest or value == "pytest"
        seen_pytest = seen_pytest or "pytest" in rest[: i + 1]
    return fails


def _pinned_body_escape_failures(body: str) -> list[str]:
    """Every property the closed grammar would have decided, on raw bytes.

    A pinned body skips `_shell_words`, so this restates the rules rather than
    trusting the pin alone: the byte equality says the body did not change,
    and this says the body that was pinned is admissible in the first place.
    Shape first (no metacharacter can build a second command), then the
    operand grammar line by line.
    """
    fails: list[str] = []
    collapsed = _delete_continuations(body)
    for token in ("|", ">", "<", "`", "$(", "&", ";", "(", ")", "{", "}"):
        if token in collapsed:
            fails.append(f"carries {token!r}")
    for escape in ("--deselect", "continue-on-error", "|| true", "-p ", " -O", "--pdb",
                   "--exitfirst", "-x ", "pytest.mark.skip", "pytest.mark.xfail"):
        if escape in collapsed:
            fails.append(f"carries the escape {escape!r}")
    for line in collapsed.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        head = stripped.split(" ", 1)[0]
        if head not in PINNED_BODY_COMMAND_WORDS:
            fails.append(f"line head {head!r} is not an admitted command word")
            continue
        if "=" in head:
            fails.append(f"inline assignment {head!r}")
            continue
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            fails.append(f"line does not tokenise: {stripped[:60]!r}")
            continue
        fails.extend(_pinned_body_operand_failures(tokens))
    # A PYTHON*/PYTEST* key may only be UNSET here, never bound.
    for word in collapsed.split():
        if "=" in word:
            name = word.split("=", 1)[0].lstrip("-")
            if _is_forbidden_py_env_key(name) or _is_forbidden_go_env_key(name):
                fails.append(f"binds the forbidden env key {name!r}")
    return fails


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _normalize_ws(s: str) -> str:
    return " ".join(str(s).split())



def test_thresholds_yaml_lists_every_benchmark_exactly_once():
    data = _load(REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml")
    ids = [b["id"] for b in data["benchmarks"]]
    assert set(ids) == EXPECTED_BENCHMARK_IDS
    assert len(ids) == len(set(ids)), "duplicate benchmark id"


def test_checkpoints_yaml_lists_every_checkpoint_exactly_once():
    data = _load(REPO_ROOT / "tests" / "functional" / "checkpoints.yaml")
    ids = [c["id"] for c in data["checkpoints"]]
    assert set(ids) == EXPECTED_CHECKPOINT_IDS
    assert len(ids) == len(set(ids)), "duplicate checkpoint id"


def test_checkpoint_inventory_covers_f1_through_f18():
    data = _load(REPO_ROOT / "tests" / "functional" / "checkpoints.yaml")
    ids = {c["id"] for c in data["checkpoints"]}
    assert ids == {f"F{i}" for i in range(1, 19)}


def test_every_benchmark_has_a_valid_status_and_owning_milestone():
    data = _load(REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml")
    for b in data["benchmarks"]:
        assert b["status"] in VALID_STATUSES, b["id"]
        assert b["owning_milestone"].startswith("M"), b["id"]
        if b["status"] != "deferred":
            assert b["tests"], f"{b['id']} is not deferred but has no linked test"


def test_every_checkpoint_has_a_valid_status_and_owning_milestone():
    data = _load(REPO_ROOT / "tests" / "functional" / "checkpoints.yaml")
    for c in data["checkpoints"]:
        assert c["status"] in VALID_STATUSES, c["id"]
        assert c["owning_milestone"].startswith("M"), c["id"]
        if c["status"] != "deferred":
            assert c["tests"] or c.get("notes"), (
                f"{c['id']} is not deferred but has no linked test or explanatory notes"
            )


def test_m1_checkpoint_f14_links_to_the_real_m1_functional_test():
    data = _load(REPO_ROOT / "tests" / "functional" / "checkpoints.yaml")
    f14 = next(c for c in data["checkpoints"] if c["id"] == "F14")
    assert f14["owning_milestone"] == "M1"
    assert any("test_m1_foundation.py" in t for t in f14["tests"])


def test_no_deferred_or_partial_entry_for_a_shipped_milestone():
    failures: list[str] = []
    for path, key in [
        (REPO_ROOT / "tests/benchmark/thresholds.yaml", "benchmarks"),
        (REPO_ROOT / "tests/functional/checkpoints.yaml", "checkpoints"),
    ]:
        data = _load(path)
        for entry in data[key]:
            owner = entry.get("owning_milestone")
            status = entry.get("status")
            if owner in SHIPPED_MILESTONES and status in {"deferred", "partial"}:
                failures.append(
                    f"{entry['id']}: owning_milestone={owner} status={status}"
                )
    assert not failures, "shipped-milestone honesty failures:\n" + "\n".join(failures)


def test_notes_do_not_promise_work_for_a_shipped_milestone():
    failures: list[str] = []
    for path, key in [
        (REPO_ROOT / "tests/benchmark/thresholds.yaml", "benchmarks"),
        (REPO_ROOT / "tests/functional/checkpoints.yaml", "checkpoints"),
    ]:
        data = _load(path)
        for entry in data[key]:
            owner = entry.get("owning_milestone")
            if owner not in SHIPPED_MILESTONES:
                continue
            notes = entry.get("notes") or ""
            for sentence in re.split(r"[.;\n]+", notes):
                s = sentence.strip()
                if not s:
                    continue
                if _PHRASE_RE.search(s) and _MILESTONE_RE.search(s):
                    failures.append(f"{entry['id']}: {s!r}")
    assert not failures, "notes promise work for a shipped milestone:\n" + "\n".join(failures)


# ---------------------------------------------------------------------------
# L0 binding enumeration (restated; do not import from B11 guard)
# ---------------------------------------------------------------------------


def _name_targets(tgt: ast.AST) -> list[ast.Name]:
    if isinstance(tgt, ast.Name):
        return [tgt]
    if isinstance(tgt, (ast.Tuple, ast.List)):
        out: list[ast.Name] = []
        for elt in tgt.elts:
            out.extend(_name_targets(elt))
        return out
    if isinstance(tgt, ast.Starred):
        return _name_targets(tgt.value)
    return []


def _binding_occurrences(tree: ast.Module) -> dict[str, list[ast.AST]]:
    """L0 exhaustive: every binding occurrence of every name, every scope."""
    occ: dict[str, list[ast.AST]] = {}

    def add(name: str, node: ast.AST) -> None:
        occ.setdefault(name, []).append(node)

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                add(alias.asname or alias.name.split(".")[0], node)
        elif isinstance(node, ast.Assign):
            for tgt in node.targets:
                for n in _name_targets(tgt):
                    add(n.id, node)
        elif isinstance(node, ast.AnnAssign):
            if node.target is not None:
                for n in _name_targets(node.target):
                    add(n.id, node)
        elif isinstance(node, ast.AugAssign):
            for n in _name_targets(node.target):
                add(n.id, node)
        elif isinstance(node, ast.NamedExpr):
            for n in _name_targets(node.target):
                add(n.id, node)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            for n in _name_targets(node.target):
                add(n.id, node)
        elif isinstance(node, ast.comprehension):
            for n in _name_targets(node.target):
                add(n.id, node)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    for n in _name_targets(item.optional_vars):
                        add(n.id, node)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                add(node.name, node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            add(node.name, node)
        elif isinstance(node, ast.ClassDef):
            add(node.name, node)
        elif isinstance(node, ast.arguments):
            for arg in [*node.posonlyargs, *node.args, *node.kwonlyargs]:
                add(arg.arg, arg)
            for arg in (node.vararg, node.kwarg):
                if arg is not None:
                    add(arg.arg, arg)
        elif isinstance(node, ast.MatchAs) and node.name:
            add(node.name, node)
        elif isinstance(node, ast.MatchStar) and node.name:
            add(node.name, node)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            add(node.rest, node)
        elif isinstance(node, ast.Global):
            for n in node.names:
                add(n, node)
        elif isinstance(node, ast.Nonlocal):
            for n in node.names:
                add(n, node)
        elif isinstance(node, ast.Delete):
            for tgt in node.targets:
                for n in _name_targets(tgt):
                    add(n.id, node)
    return occ


def _file_has_star_import(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    return True
    return False


def _stmt_of(node: ast.AST, parents: dict[int, tuple[ast.AST, str]]) -> ast.AST:
    cur: ast.AST = node
    while not isinstance(cur, ast.stmt):
        info = parents.get(id(cur))
        if info is None:
            return node
        cur = info[0]
    return cur


def _resolve_module_binding(tree: ast.Module, name: str) -> ast.stmt | None:
    """(H): star poison; exactly one occurrence anywhere; must be direct tree.body."""
    if _file_has_star_import(tree):
        return None
    occ = _binding_occurrences(tree)
    nodes = occ.get(name) or []
    if len(nodes) != 1:
        return None
    parents = _build_parent_map(tree)
    holder = _stmt_of(nodes[0], parents)
    if holder not in tree.body:
        return None
    return holder  # type: ignore[return-value]


def _numeric_name_bindings(tree: ast.Module) -> dict[str, ast.AST]:
    result: dict[str, ast.AST] = {}
    for name in _binding_occurrences(tree):
        stmt = _resolve_module_binding(tree, name)
        if stmt is None:
            continue
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            t = stmt.targets[0]
            if isinstance(t, ast.Name):
                result[name] = stmt.value
        elif (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and stmt.value is not None
        ):
            result[name] = stmt.value
    return result


def _resolves_to_pytest(tree: ast.Module, p: str) -> bool:
    stmt = _resolve_module_binding(tree, p)
    if not isinstance(stmt, ast.Import):
        return False
    for a in stmt.names:
        bound = a.asname or a.name.split(".")[0]
        if bound == p and a.name == "pytest":
            return True
    return False


def _resolves_to_pytest_fail(tree: ast.Module, f: str) -> bool:
    stmt = _resolve_module_binding(tree, f)
    if not isinstance(stmt, ast.ImportFrom):
        return False
    if stmt.level != 0 or stmt.module != "pytest":
        return False
    for a in stmt.names:
        if a.name == "fail" and (a.asname or a.name) == f:
            return True
    return False


# ---------------------------------------------------------------------------
# Constant-folding dead-branch predicates
# ---------------------------------------------------------------------------


def _is_constant_true(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return bool(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _is_constant_false(node.operand)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        return all(_is_constant_true(v) for v in node.values)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        return any(_is_constant_true(v) for v in node.values)
    return False


def _is_constant_false(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return not bool(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _is_constant_true(node.operand)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        return any(_is_constant_false(v) for v in node.values)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        return all(_is_constant_false(v) for v in node.values)
    return False


def _is_numeric_term(node: ast.AST, bindings: dict[str, ast.AST], depth: int = 0) -> bool:
    if depth > _NUMERIC_DEPTH_CAP:
        return False
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (int, float)) and not isinstance(node.value, bool)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        return _is_numeric_term(node.operand, bindings, depth + 1)
    if isinstance(node, ast.BinOp) and isinstance(node.op, _NUMERIC_BINOPS):
        return (
            _is_numeric_term(node.left, bindings, depth + 1)
            and _is_numeric_term(node.right, bindings, depth + 1)
        )
    if isinstance(node, ast.Name) and node.id in bindings:
        return _is_numeric_term(bindings[node.id], bindings, depth + 1)
    return False


def _operand_reasons(
    operands: list[ast.AST],
    bindings: dict[str, ast.AST],
    tree: ast.Module,
    func: ast.AST,
) -> str | None:
    """Row 8/9: both_operands_numeric or the no-numeric three-way split."""
    flags = [_is_numeric_term(op, bindings) for op in operands]
    if all(flags):
        return "both_operands_numeric"
    if any(flags):
        return None  # qualifies on operands
    # row 9: no numeric term
    if _file_has_star_import(tree):
        return "star_import"
    # any bare Name operand bound outside the linked function?
    body_ids = {id(s) for s in tree.body}
    for op in operands:
        if not isinstance(op, ast.Name):
            continue
        name = op.id
        occ = _binding_occurrences(tree).get(name) or []
        for n in occ:
            # binding outside the linked function: direct tree.body member
            # walk up to stmt
            parents = _build_parent_map(tree)
            holder = _stmt_of(n, parents)
            if holder in tree.body:
                return "unresolved_identifier"
    return "no_numeric_term"


def _is_threshold_compare_shape(node: ast.AST) -> bool:
    """Condition (i) only: is an ordering Compare."""
    if not isinstance(node, ast.Compare) or not node.ops:
        return False
    return all(isinstance(op, _ORDERED_OPS) for op in node.ops)


def _stmt_explicitly_fails(stmt: ast.stmt, tree: ast.Module) -> bool:
    if isinstance(stmt, ast.Raise):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        func = stmt.value.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.attr == "fail" and _resolves_to_pytest(tree, func.value.id):
                return True
        if isinstance(func, ast.Name) and _resolves_to_pytest_fail(tree, func.id):
            return True
    return False


def _body_has_explicit_fail(body: list[ast.stmt], tree: ast.Module) -> bool:
    return any(_stmt_explicitly_fails(s, tree) for s in body)


def _build_parent_map(tree: ast.AST) -> dict[int, tuple[ast.AST, str]]:
    parents: dict[int, tuple[ast.AST, str]] = {}
    for parent in ast.walk(tree):
        for field, value in ast.iter_fields(parent):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        parents[id(item)] = (parent, field)
            elif isinstance(value, ast.AST):
                parents[id(value)] = (parent, field)
    return parents


def _ancestor_chain(node: ast.AST, func: ast.AST, parents: dict) -> list[tuple[ast.AST, str]]:
    chain: list[tuple[ast.AST, str]] = []
    cur: ast.AST = node
    while cur is not func:
        info = parents.get(id(cur))
        if info is None:
            break
        parent, field = info
        chain.append((parent, field))
        cur = parent
    return chain


def _in_nested_scope(node: ast.AST, func: ast.AST, parents: dict) -> bool:
    for parent, _field in _ancestor_chain(node, func, parents):
        if isinstance(parent, _NESTED_SCOPE) and parent is not func:
            return True
    return False


def _in_constantly_dead_branch(node: ast.AST, func: ast.AST, parents: dict) -> bool:
    for parent, field in _ancestor_chain(node, func, parents):
        if isinstance(parent, (ast.If, ast.While)):
            if field == "body" and _is_constant_false(parent.test):
                return True
            if isinstance(parent, ast.If) and field == "orelse" and _is_constant_true(parent.test):
                return True
    return False


def _decorator_final_name(dec: ast.AST) -> str | None:
    cur = dec
    if isinstance(cur, ast.Call):
        cur = cur.func
    if isinstance(cur, ast.Name):
        return cur.id
    if isinstance(cur, ast.Attribute):
        return cur.attr
    return None


def _is_skip_decorator(dec: ast.AST) -> bool:
    return _decorator_final_name(dec) in SKIP_MARKERS


def _pytestmark_opaque(value: ast.AST) -> bool:
    """True when the pytestmark RHS cannot be fully inspected for skip markers.

    (R)(3): a call result or bare name disqualifies conservatively; a plain
    Attribute (e.g. ``pytest.mark.e2e``) or a list/tuple of inspectable
    Attributes is fully inspectable.
    """
    if isinstance(value, ast.Name):
        return True
    if isinstance(value, ast.Call):
        return True
    if isinstance(value, ast.Attribute):
        return False
    if isinstance(value, (ast.List, ast.Tuple)):
        return any(_pytestmark_opaque(elt) for elt in value.elts)
    # Any other form (f-string, binop, …) is opaque.
    return True


def _pytestmark_value_skips(value: ast.AST) -> bool:
    """True if *value* is a skip marker or cannot be fully inspected."""
    for n in ast.walk(value):
        if isinstance(n, ast.Name) and n.id in SKIP_MARKERS:
            return True
        if isinstance(n, ast.Attribute) and n.attr in SKIP_MARKERS:
            return True
    return _pytestmark_opaque(value)


def _module_scope_pytestmark_values(tree: ast.Module) -> list[ast.AST | None]:
    """Collect RHS values for every module-scope ``pytestmark`` binding.

    Module-scope by construction: recurse into the nested statement blocks of
    **every** compound statement reachable at module scope by walking child
    nodes generically (not a fixed per-type container branch list). Nested
    statement containers that are not ``ast.stmt`` themselves — ``ExceptHandler``
    (covers both ``try``/``except`` and ``try``/``except*`` / ``TryStar``),
    ``match_case``, and ``withitem`` — are handled in that generic child walk so
    new compound statement types that hold ordinary statement lists keep working
    without a new hand-listed branch.

    **Excluded** (non-module scopes): bodies of ``FunctionDef`` /
    ``AsyncFunctionDef`` / ``ClassDef`` / ``Lambda``. Their **module-evaluated
    surfaces** are still scanned (decorators, argument defaults / kw_defaults,
    annotations, class bases/keywords, comprehension/generator outer
    expressions).

    **ClassDef exception:** a class-body ``global pytestmark`` reopens the
    module binding for that name; same-name assignments in *that* class scope
    (including nested control flow) are module bindings evaluated at class
    definition time. Ordinary class attributes without ``global``, and bodies
    of nested functions (even with their own ``global pytestmark`` — uncalled
    at import), are still excluded.

    **withitem.optional_vars** is both a binding target (``as pytestmark``) and
    an expression surface (walrus in a subscript/as-target); both are scanned.

    **Wildcard imports** (``from x import *``, ``alias.name == "*"``) are
    default-denied without resolving ``__all__`` or the imported module.

    For every other statement, binding bookkeeping never early-returns past
    the generic expression walk: RHS values, ``AnnAssign.annotation``, and
    evaluated target expressions (``Assign`` / ``AnnAssign`` / ``AugAssign`` /
    ``Delete``) are all scanned for walrus bindings.

    Each entry is either an inspectable RHS expression, or ``None`` when the
    binding shape itself makes the final value unknowable (import, augassign,
    destructure, for target, with-as, except-as, annotation-only, PEP 695
    ``type`` alias, …) — callers treat ``None`` as opaque / default-deny.
    """
    values: list[ast.AST | None] = []

    def note_simple(value: ast.AST | None) -> None:
        values.append(value)

    def note_opaque() -> None:
        values.append(None)

    def bind_from_target(tgt: ast.AST, value: ast.AST | None, *, simple_ok: bool) -> None:
        """Record a binding of ``pytestmark`` via *tgt*.

        When *simple_ok* and *tgt* is a bare ``Name`` (and for Assign, a single
        non-destructuring target), the RHS is inspectable; otherwise opaque.
        """
        names = _name_targets(tgt)
        if not any(n.id == "pytestmark" for n in names):
            return
        if simple_ok and isinstance(tgt, ast.Name) and tgt.id == "pytestmark" and value is not None:
            note_simple(value)
        else:
            note_opaque()

    def note_match_pattern_bindings(pattern: ast.AST) -> None:
        # match patterns can bind names — treat pytestmark binds as opaque
        for n in ast.walk(pattern):
            if isinstance(n, ast.MatchAs) and n.name == "pytestmark":
                note_opaque()
            if isinstance(n, ast.MatchStar) and n.name == "pytestmark":
                note_opaque()
            if isinstance(n, ast.MatchMapping) and n.rest == "pytestmark":
                note_opaque()

    def visit_arguments(args: ast.arguments) -> None:
        """Scan module-evaluated argument defaults and annotations only."""
        for d in args.defaults:
            visit_expr(d)
        for d in args.kw_defaults:
            visit_expr(d)
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            visit_expr(arg.annotation)
        if args.vararg is not None:
            visit_expr(args.vararg.annotation)
        if args.kwarg is not None:
            visit_expr(args.kwarg.annotation)

    def visit_comprehension_like(
        elt_or_key_value: tuple[ast.AST, ...] | tuple[ast.AST, ast.AST],
        generators: list[ast.comprehension],
    ) -> None:
        """Comprehension/genexp: targets are local; elt/iters/ifs are outer."""
        for part in elt_or_key_value:
            visit_expr(part)
        for gen in generators:
            visit_expr(gen.iter)
            for if_ in gen.ifs:
                visit_expr(if_)

    def visit_expr(node: ast.AST | None) -> None:
        """Walk expressions for walrus bindings; skip nested function bodies."""
        if node is None:
            return
        if isinstance(node, ast.Lambda):
            # Defaults evaluate at definition time in the enclosing scope;
            # the lambda body does not.
            visit_arguments(node.args)
            return
        if isinstance(node, ast.GeneratorExp):
            visit_comprehension_like((node.elt,), node.generators)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp)):
            visit_comprehension_like((node.elt,), node.generators)
            return
        if isinstance(node, ast.DictComp):
            visit_comprehension_like((node.key, node.value), node.generators)
            return
        if isinstance(node, ast.NamedExpr):
            bind_from_target(node.target, node.value, simple_ok=True)
            visit_expr(node.value)
            return
        for child in ast.iter_child_nodes(node):
            visit_expr(child)

    def visit_stmts(stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            visit_stmt(stmt)

    def _class_scope_declares_global_pytestmark(stmts: list[ast.stmt]) -> bool:
        """True if this class scope has ``global pytestmark`` (not nested def/class)."""
        stack: list[ast.AST] = list(stmts)
        while stack:
            node = stack.pop()
            if isinstance(node, ast.Global) and "pytestmark" in node.names:
                return True
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Nested scopes own their own global declarations.
                continue
            if isinstance(node, ast.ExceptHandler):
                stack.extend(node.body)
                continue
            if isinstance(node, ast.match_case):
                stack.extend(node.body)
                continue
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.stmt, ast.ExceptHandler, ast.match_case)):
                    stack.append(child)
        return False

    def _visit_nested_classdefs_only(stmts: list[ast.stmt]) -> None:
        """Without class-scope global, only nested ClassDef may reopen module binds."""
        stack: list[ast.AST] = list(stmts)
        while stack:
            node = stack.pop()
            if isinstance(node, ast.ClassDef):
                visit_stmt(node)
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(node, ast.ExceptHandler):
                stack.extend(node.body)
                continue
            if isinstance(node, ast.match_case):
                stack.extend(node.body)
                continue
            if isinstance(node, ast.stmt):
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, (ast.stmt, ast.ExceptHandler, ast.match_case)):
                        stack.append(child)

    def visit_module_child(node: ast.AST) -> None:
        """Generic module-scope descent for one AST child of a compound stmt.

        Statement nodes recurse via ``visit_stmt``. Statement-containing
        non-stmt containers (``ExceptHandler``, ``match_case``, ``withitem``)
        expose their nested statement blocks here so ``Try`` / ``TryStar`` /
        ``Match`` / ``With`` need no per-type body branches. Everything else
        is an expression surface (walrus, etc.).
        """
        if isinstance(node, ast.stmt):
            visit_stmt(node)
            return
        if isinstance(node, ast.ExceptHandler):
            # Shared by ast.Try and ast.TryStar (except*); name is a string bind.
            if node.name == "pytestmark":
                note_opaque()
            visit_expr(node.type)
            visit_stmts(node.body)
            return
        if isinstance(node, ast.match_case):
            note_match_pattern_bindings(node.pattern)
            visit_expr(node.guard)
            visit_stmts(node.body)
            return
        if isinstance(node, ast.withitem):
            visit_expr(node.context_expr)
            if node.optional_vars is not None:
                # Binding target (``as pytestmark`` / destructure) — opaque.
                bind_from_target(node.optional_vars, None, simple_ok=False)
                # Expression surface too: walrus in as-target subscripts etc.
                # (e.g. ``as d[0 if (pytestmark := …) else 0]``).
                visit_expr(node.optional_vars)
            return
        visit_expr(node)

    def visit_stmt(stmt: ast.stmt) -> None:
        # ---- Non-module scopes: surfaces only, never bodies ----
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Nested scope: the def name is module-scoped, but the body is not.
            # Decorators, defaults, and annotations *are* evaluated at def time
            # in the enclosing (module) scope — scan those without entering body.
            # An uncalled nested def with ``global pytestmark`` does NOT bind
            # at import time; its body is never entered here.
            if stmt.name == "pytestmark":
                note_opaque()
            for dec in stmt.decorator_list:
                visit_expr(dec)
            visit_arguments(stmt.args)
            visit_expr(stmt.returns)
            return
        if isinstance(stmt, ast.ClassDef):
            # Class body is normally a nested scope; bases/keywords/decorators
            # are module-evaluated. Exception: class-body ``global pytestmark``
            # makes same-name assignments in *this* class scope module bindings
            # (executed at class definition / import time).
            if stmt.name == "pytestmark":
                note_opaque()
            for dec in stmt.decorator_list:
                visit_expr(dec)
            for base in stmt.bases:
                visit_expr(base)
            for kw in stmt.keywords:
                visit_expr(kw.value)
            if _class_scope_declares_global_pytestmark(stmt.body):
                # Re-enter as module-like for this class scope only. Nested
                # FunctionDef still excludes its body (uncalled at import);
                # nested ClassDef re-checks its own global.
                visit_stmts(stmt.body)
            else:
                # Ordinary class attrs (pytestmark without global) stay local.
                # Nested classes may still declare global pytestmark.
                _visit_nested_classdefs_only(stmt.body)
            return

        # ---- Binding forms at this statement (not driven by child walk) ----
        # Binding bookkeeping must NEVER early-return for Assign / AnnAssign /
        # AugAssign / Delete: after noting the bind, fall through so the generic
        # child walk visits EVERY module-evaluated expression surface — RHS
        # value, AnnAssign.annotation, and evaluated target expressions
        # (e.g. subscript/walrus in ``d[(pytestmark:=...)] = 1``). Only Import
        # and Global/Nonlocal (no expression children) and FunctionDef /
        # ClassDef (body exclusion, surfaces already scanned) return early.
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for alias in stmt.names:
                # Default-deny star imports: may rebind pytestmark via __all__
                # without resolving the imported module.
                if alias.name == "*":
                    note_opaque()
                    continue
                bound = alias.asname or alias.name.split(".")[0]
                if bound == "pytestmark":
                    note_opaque()
            return
        if isinstance(stmt, ast.Assign):
            # Multi-target chain ``a = b = x`` shares one RHS; destructure is opaque.
            for tgt in stmt.targets:
                names = _name_targets(tgt)
                if not any(n.id == "pytestmark" for n in names):
                    continue
                if isinstance(tgt, ast.Name) and tgt.id == "pytestmark":
                    note_simple(stmt.value)
                else:
                    note_opaque()
            # Fall through: value + evaluated targets (subscript/walrus).
        elif isinstance(stmt, ast.AnnAssign):
            if isinstance(stmt.target, ast.Name) and stmt.target.id == "pytestmark":
                if stmt.value is not None:
                    note_simple(stmt.value)
                else:
                    note_opaque()  # annotation-only: value unknown
            elif any(n.id == "pytestmark" for n in _name_targets(stmt.target)):
                note_opaque()
            # Fall through: annotation + value + evaluated target.
        elif isinstance(stmt, ast.AugAssign):
            if any(n.id == "pytestmark" for n in _name_targets(stmt.target)):
                note_opaque()
            # Fall through: value + evaluated target.
        elif isinstance(stmt, ast.Delete):
            for tgt in stmt.targets:
                if any(n.id == "pytestmark" for n in _name_targets(tgt)):
                    note_opaque()
            # Fall through: evaluated target expressions (subscript/walrus).
        elif isinstance(stmt, (ast.Global, ast.Nonlocal)):
            if "pytestmark" in stmt.names:
                note_opaque()
            return
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            # For/AsyncFor loop targets bind in the enclosing scope. The target
            # is an expression node, so the generic child walk would not record
            # it as a binding — note it here, then fall through to descent.
            bind_from_target(stmt.target, None, simple_ok=False)
        elif isinstance(stmt, ast.TypeAlias):
            # PEP 695 ``type Name = …`` binds *name* at this scope (module, or
            # class-with-global-pytestmark). The value is a type expression /
            # type-alias object, never a pytest Mark — real pytest aborts
            # collection with TypeError if pytestmark is a TypeAlias. Always
            # opaque; do not interpret the value as a marker. Fall through so
            # value / type_params are scanned for walrus like other surfaces.
            bind_from_target(stmt.name, None, simple_ok=False)

        # ---- Generic compound descent (any depth, no per-type body list) ----
        # if/for/while/with/try/try*/match/assert/expr/assign/annassign/… :
        # walk every child. Nested stmt lists and ExceptHandler/match_case/
        # withitem bodies are reached via visit_module_child;
        # FunctionDef/ClassDef/Lambda bodies stay excluded by the early
        # returns above and visit_expr's Lambda.
        for child in ast.iter_child_nodes(stmt):
            visit_module_child(child)

    visit_stmts(tree.body)
    return values


def _pytestmark_skips(tree: ast.Module) -> bool:
    """True if any module-scope ``pytestmark`` binding skips the module.

    Scan **every** module-scope binding (pytest rebinds win): a later
    ``pytestmark = pytest.mark.skip`` after a non-skip marker still skips,
    including bindings nested in module-level control flow. Opaque RHS or
    unknowable binding shape → conservative True. Fully inspectable non-skip
    bindings do not short-circuit the scan.
    """
    for value in _module_scope_pytestmark_values(tree):
        if value is None:
            return True  # unknowable shape → default-deny
        if _pytestmark_value_skips(value):
            return True
        # Inspectable non-skip binding — keep scanning for a later rebind.
    return False


def _is_block_exit(stmt: ast.stmt, tree: ast.Module) -> bool:
    if isinstance(stmt, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        func = stmt.value.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.attr in {"skip", "xfail", "exit"} and _resolves_to_pytest(tree, func.value.id):
                return True
        if isinstance(func, ast.Name):
            # bare skip/xfail/exit from from pytest import ...
            for name in ("skip", "xfail", "exit"):
                if func.id == name or True:
                    stmt_b = _resolve_module_binding(tree, func.id)
                    if (
                        isinstance(stmt_b, ast.ImportFrom)
                        and stmt_b.level == 0
                        and stmt_b.module == "pytest"
                    ):
                        for a in stmt_b.names:
                            if a.name in {"skip", "xfail", "exit"} and (a.asname or a.name) == func.id:
                                return True
                    break
    return False


def _candidate_is_dead(node: ast.AST, func: ast.AST, parents: dict, tree: ast.Module) -> bool:
    """(R)(1): preceded by unconditional block exit at any ancestor list level."""
    # Build statement-list membership
    cur: ast.AST = node
    while cur is not func:
        info = parents.get(id(cur))
        if info is None:
            return False
        parent, field = info
        # if cur is a stmt in a list on parent
        if isinstance(cur, ast.stmt):
            lst = getattr(parent, field, None) if isinstance(field, str) else None
            if isinstance(lst, list) and cur in lst:
                idx = lst.index(cur)
                for earlier in lst[:idx]:
                    if isinstance(earlier, ast.stmt) and _is_block_exit(earlier, tree):
                        return True
        cur = parent
    return False


def _failure_type_of_candidate(node: ast.AST, tree: ast.Module) -> str | None:
    """Return failure type name, or None for unknown (any handler disqualifies)."""
    if isinstance(node, ast.Assert):
        return "AssertionError"
    if isinstance(node, ast.If):
        for s in node.body:
            if isinstance(s, ast.Raise):
                if s.exc is None:
                    return None  # bare raise → unknown
                exc = s.exc
                if isinstance(exc, ast.Call):
                    exc = exc.func
                if isinstance(exc, ast.Name):
                    return exc.id
                if isinstance(exc, ast.Attribute):
                    return exc.attr
                return None
            if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
                func = s.value.func
                if isinstance(func, ast.Attribute) and func.attr == "fail":
                    return "BaseException"  # pytest.Failed
                if isinstance(func, ast.Name) and _resolves_to_pytest_fail(tree, func.id):
                    return "BaseException"
    return "AssertionError"


def _handler_can_catch(handler: ast.ExceptHandler, fail_type: str | None, tree: ast.Module) -> bool:
    if handler.type is None:
        return True
    def final_name(t: ast.AST) -> str | None:
        if isinstance(t, ast.Name):
            return t.id
        if isinstance(t, ast.Attribute):
            return t.attr
        return None

    def one_catches(t: ast.AST) -> bool:
        if isinstance(t, ast.Tuple):
            return any(one_catches(e) for e in t.elts)
        name = final_name(t)
        if name is None:
            return True  # unclassifiable
        if name == "BaseException":
            return True
        if name == "Exception":
            return fail_type != "BaseException"
        if fail_type is None:
            return True
        if name == fail_type:
            return True
        # Name with a binding occurrence → unclassifiable alias
        if isinstance(t, ast.Name):
            occ = _binding_occurrences(tree).get(t.id) or []
            if occ:
                return True
        return False

    return one_catches(handler.type)


def _handler_reraises(handler: ast.ExceptHandler) -> bool:
    if not handler.body:
        return False
    return isinstance(handler.body[-1], ast.Raise)


def _candidate_failure_is_swallowed(
    node: ast.AST, func: ast.AST, parents: dict, tree: ast.Module
) -> bool:
    # (R)(2) try handlers
    fail_type = _failure_type_of_candidate(node, tree)
    for parent, field in _ancestor_chain(node, func, parents):
        if isinstance(parent, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            if field != "body":
                continue
            for h in parent.handlers:
                if _handler_can_catch(h, fail_type, tree) and not _handler_reraises(h):
                    return True
        # (R)(2b) suppressing with
        if isinstance(parent, (ast.With, ast.AsyncWith)) and field == "body":
            for item in parent.items:
                expr = item.context_expr
                if isinstance(expr, ast.Call):
                    fn = expr.func
                    final = None
                    if isinstance(fn, ast.Name):
                        final = fn.id
                    elif isinstance(fn, ast.Attribute):
                        final = fn.attr
                    if final in SUPPRESSOR_CM:
                        return True
    return False


def _python_basename_collected(path: Path) -> bool:
    name = path.name
    return (name.startswith("test_") and name.endswith(".py")) or name.endswith("_test.py")


def _python_qualifying_comparison(
    tree: ast.Module,
    test_name: str,
    *,
    operators: tuple[type, ...],
    operand_rule: Callable[[ast.Compare], bool],
) -> list[ast.AST]:
    """Shared seam: §11.1.3 candidacy + reachability + *is-a-comparison* (FP-IG-19).

    Steps (design.md §11.3 FP-IG-19):
      1. locate the collected top-level ``test*`` function over tree.body
      2. enumerate candidate ``ast.Assert`` / ``ast.If`` nodes with the
         ancestor-chain filter (no nested FunctionDef/AsyncFunctionDef/Lambda/ClassDef)
      3. reject dead branches via ``_is_constant_false`` / ``_is_constant_true``
      4. qualify: an Assert whose ``test`` *is* a comparison over ``operators``,
         or an If whose ``test`` *is* one and whose body holds a statement-level
         Raise or ``fail(...)`` call. *Is*, not *contains*.

    ``operand_rule`` is applied to the comparison node. Equality admission and
    named-quantity matching are call-site concerns (FP-IG-19 only); the manifest
    checker passes the ordering set and the numeric-term rule.
    """
    if not isinstance(tree, ast.Module):
        return []
    matches = [
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == test_name
    ]
    if not matches:
        return []
    func = matches[0]
    parents = _build_parent_map(tree)

    def _is_cmp_over(node: ast.AST) -> bool:
        if not isinstance(node, ast.Compare) or not node.ops:
            return False
        return all(isinstance(op, operators) for op in node.ops)

    def _qualifies(node: ast.AST) -> bool:
        if isinstance(node, ast.Assert):
            test = node.test
            if not _is_cmp_over(test):
                return False
            assert isinstance(test, ast.Compare)
            return bool(operand_rule(test))
        if isinstance(node, ast.If):
            test = node.test
            if not _is_cmp_over(test):
                return False
            if not _body_has_explicit_fail(node.body, tree):
                return False
            assert isinstance(test, ast.Compare)
            return bool(operand_rule(test))
        return False

    out: list[ast.AST] = []
    for node in ast.walk(func):
        if not isinstance(node, (ast.Assert, ast.If)):
            continue
        if _in_nested_scope(node, func, parents):
            continue
        if _in_constantly_dead_branch(node, func, parents):
            continue
        if _qualifies(node):
            out.append(node)
    out.sort(key=lambda n: getattr(n, "lineno", 0) or 0)
    return out


def _python_test_asserts_threshold(
    src: str, name: str, *, path: Path | None = None
) -> tuple[bool, str | None]:
    """Return (ok, reason_or_None) with exact threshold vocabulary tokens.

    Real caller of ``_python_qualifying_comparison`` with the ordering operator
    set and the numeric-term operand rule (design.md FP-IG-19 seam). Full
    reason vocabulary (skip / dead / swallowed / …) is preserved for the
    fixture table: dead/swallowed filters and detailed reasons run around the
    shared core, which alone decides *is-a-threshold-comparison*.
    """
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return False, "nonexistent_linked_test"
    if not isinstance(tree, ast.Module):
        return False, "nonexistent_linked_test"

    if path is not None and not _python_basename_collected(path):
        return False, "not_collected"

    # (M) identity over Module.body only
    matches = [
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
    ]
    if not matches:
        return False, "nonexistent_linked_test"
    if len(matches) > 1:
        return False, "ambiguous_test_name"
    func = matches[0]

    # (M) python_functions default test*
    if not name.startswith("test"):
        return False, "not_collected"

    # (R)(3) skipped
    if any(_is_skip_decorator(d) for d in func.decorator_list):
        return False, "skipped"
    if _pytestmark_skips(tree):
        # Module-scope ``from x import *`` is pytestmark-opaque (walker) *and*
        # poisons numeric-name resolution (H). Prefer the dedicated
        # ``star_import`` vocabulary token so the pinned (H) fixture keeps its
        # reason; the pytestmark default-deny still holds via the walker.
        if _file_has_star_import(tree):
            return False, "star_import"
        return False, "skipped"

    bindings = _numeric_name_bindings(tree)
    parents = _build_parent_map(tree)

    # Shared seam: candidacy + reachability + *is-a-comparison* (FP-IG-19).
    # Operand rule is the numeric-term rule; equality is NOT admitted here.
    def _manifest_operand_rule(cmp: ast.Compare) -> bool:
        operands: list[ast.AST] = [cmp.left, *cmp.comparators]
        return _operand_reasons(operands, bindings, tree, func) is None

    qualifying = _python_qualifying_comparison(
        tree,
        name,
        operators=_ORDERED_OPS,
        operand_rule=_manifest_operand_rule,
    )
    # Seam does not encode dead-after-return / swallowed; filter those here so
    # the shared core is the comparison qualifier and vocabulary stays intact.
    # Acceptance is *only* via a live shared-seam result (review C3): an empty
    # or fully-filtered seam must never be rescued into success by the
    # diagnostic fallback below.
    for node in qualifying:
        if _candidate_is_dead(node, func, parents, tree):
            continue
        if _candidate_failure_is_swallowed(node, func, parents, tree):
            continue
        return True, None

    # No live qualifier from the shared seam — reject. Emit the first failing
    # reason from the full candidate set (including constantly-dead branches
    # the seam skipped) so the fixture table's vocabulary is unchanged. The
    # fallback may diagnose; it must never turn an empty shared result into
    # acceptance.
    candidates: list[ast.AST] = []
    for node in ast.walk(func):
        if not isinstance(node, (ast.Assert, ast.If)):
            continue
        if _in_nested_scope(node, func, parents):
            continue
        candidates.append(node)
    candidates.sort(key=lambda n: getattr(n, "lineno", 0) or 0)

    if not candidates:
        return False, "no_candidate"

    first_reason: str | None = None
    for cand in candidates:
        reason = _evaluate_candidate(cand, func, parents, tree, bindings)
        if reason is None:
            # Qualifies under evaluate but was absent/filtered from the seam —
            # never accept; keep scanning for a vocabulary reason.
            continue
        if first_reason is None:
            first_reason = reason
    return False, first_reason or "not_a_threshold_comparison"


def _evaluate_candidate(
    cand: ast.AST,
    func: ast.AST,
    parents: dict,
    tree: ast.Module,
    bindings: dict[str, ast.AST],
) -> str | None:
    """Return None if qualifies, else first failing reason in (W)(3) order."""
    # 1 dead_candidate
    if _candidate_is_dead(cand, func, parents, tree):
        return "dead_candidate"
    # 1a constantly dead branch
    if _in_constantly_dead_branch(cand, func, parents):
        return "not_a_threshold_comparison"
    # 2 swallowed
    if _candidate_failure_is_swallowed(cand, func, parents, tree):
        return "swallowed_candidate"
    # 3 form
    if isinstance(cand, ast.Assert):
        test = cand.test
        if not _is_threshold_compare_shape(test):
            return "not_a_threshold_comparison"
        operands: list[ast.AST] = [test.left, *test.comparators]
        op_reason = _operand_reasons(operands, bindings, tree, func)
        if op_reason is not None:
            return op_reason
        return None
    else:
        assert isinstance(cand, ast.If)
        test = cand.test
        if not _is_threshold_compare_shape(test):
            return "not_a_threshold_comparison"
        # 5 fail branch
        if not _body_has_explicit_fail(cand.body, tree):
            return "no_fail_in_branch"
        operands = [test.left, *test.comparators]
        op_reason = _operand_reasons(operands, bindings, tree, func)
        if op_reason is not None:
            return op_reason
        return None


def _go_guard_present(root: Path = REPO_ROOT) -> bool:
    guard = root / GO_GUARD
    if not guard.is_file():
        return False
    return GO_GUARD_FUNC in guard.read_text(encoding="utf-8")


def _resolve_test_file(link: str, root: Path = REPO_ROOT) -> Path | None:
    path_part = link.split("::", 1)[0].strip()
    if not path_part:
        return None
    candidate = root / path_part
    if candidate.is_file():
        return candidate
    return None


def _link_test_name(link: str) -> str | None:
    if "::" not in link:
        return None
    name = link.split("::", 1)[1].strip()
    return name.split(".")[-1] if name else None


def _link_names_benchmark(link: str, bench_id: str) -> bool:
    lower = link.lower()
    bid = bench_id.lower()
    if "::" in link:
        name = link.split("::", 1)[1].lower()
        if bid in name or f"test_{bid}" in name or f"test{bid}" in name:
            return True
    return f"test_{bid}" in lower or f"bench_{bid}" in lower or f"/{bid.lower()}_" in lower


def _link_asserts_threshold(link: str, root: Path = REPO_ROOT) -> tuple[bool, str | None]:
    path = _resolve_test_file(link, root)
    if path is None:
        return False, "missing_file"
    test_name = _link_test_name(link)
    if test_name is None:
        return False, "nonexistent_linked_test"
    suffix = path.suffix.lower()
    if suffix == ".py":
        src = path.read_text(encoding="utf-8")
        return _python_test_asserts_threshold(src, test_name, path=path)
    if suffix == ".go":
        if not _go_guard_present(root):
            return False, "missing_go_guard"
        return True, None
    return False, "unknown_suffix"


def _entry_link_failures(entry: dict, root: Path = REPO_ROOT) -> list[str]:
    failures: list[str] = []
    bid = entry["id"]
    links = entry.get("tests") or []
    if not links:
        failures.append(f"{bid}: covered but tests list empty")
        return failures
    named = [lnk for lnk in links if _link_names_benchmark(lnk, bid)]
    if not named:
        failures.append(
            f"{bid}: covered but no linked test names the benchmark id; links={links}"
        )
        return failures
    checked = 0
    for lnk in named:
        checked += 1
        ok, reason = _link_asserts_threshold(lnk, root)
        if reason:
            failures.append(f"{bid}: {lnk}: {reason}")
        elif not ok:
            failures.append(f"{bid}: {lnk}: no qualifying threshold assertion")
    assert checked == len(named), "early exit in link loop"
    return failures


def test_covered_benchmarks_link_to_threshold_asserting_tests():
    data = _load(REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml")
    failures: list[str] = []
    for b in data["benchmarks"]:
        if b["status"] != "covered":
            continue
        failures.extend(_entry_link_failures(b, REPO_ROOT))
    assert not failures, "\n".join(failures)


# ---------------------------------------------------------------------------
# Shell grammar (AG) + CI pin machinery
# ---------------------------------------------------------------------------


@dataclass
class Word:
    literal_value: str
    literal_prefix: str
    is_dynamic: bool
    raw_text: str = ""


@dataclass
class SimpleCommand:
    assignments: list[Word] = field(default_factory=list)
    command_word: Word | None = None
    args: list[Word] = field(default_factory=list)
    redirections: list[tuple[str, Word]] = field(default_factory=list)


def _delete_continuations(s: str) -> str:
    return s.replace("\\\n", "")


def _shell_words(script: str) -> list[Word] | None:
    """(AG)(1) closed grammar. Returns None → run_not_recognized."""
    s = _delete_continuations(script)
    words: list[Word] = []
    i = 0
    n = len(s)
    state = "unquoted"  # unquoted | single | double

    def fail():
        return None

    while i < n:
        # skip unquoted whitespace / newlines (separators handled as ops)
        if state == "unquoted" and s[i] in " \t":
            i += 1
            continue
        # comment
        if state == "unquoted" and s[i] == "#":
            # start of word?
            if i == 0 or s[i - 1] in " \t\n":
                while i < n and s[i] != "\n":
                    i += 1
                continue
            return fail()
        # operators in unquoted
        if state == "unquoted":
            # refused ops first: ||, <<, <<<, & variants etc.
            if s.startswith("||", i):
                return fail()  # (AK)(3) refuse ||
            if s.startswith("&&", i):
                words.append(Word("&&", "&&", False, "&&"))
                i += 2
                continue
            if s.startswith(">>", i):
                words.append(Word(">>", ">>", False, ">>"))
                i += 2
                continue
            if s[i] in ";|\n>":
                ch = s[i]
                words.append(Word(ch, ch, False, ch))
                i += 1
                continue
            # refused single chars / multi
            if s[i] in "&(){}[]<>`!*?~,":
                return fail()
            if s.startswith("<<", i):
                return fail()

        # start a word
        lit_parts: list[str] = []
        lit_prefix_parts: list[str] = []
        raw_parts: list[str] = []
        is_dynamic = False
        prefix_closed = False

        while i < n:
            c = s[i]
            if state == "unquoted":
                if c in " \t":
                    break
                if c in ";|\n" or s.startswith("&&", i) or s.startswith("||", i) or s.startswith(">>", i):
                    break
                if c in "&(){}[]<>`!*?~,":
                    return fail()
                if c == "#":
                    return fail()
                if c == "'":
                    raw_parts.append(c)
                    i += 1
                    state = "single"
                    continue
                if c == '"':
                    raw_parts.append(c)
                    i += 1
                    state = "double"
                    continue
                if c == "$":
                    # expansions
                    dyn, ni, raw = _parse_dollar(s, i)
                    if dyn is None:
                        return fail()
                    is_dynamic = True
                    prefix_closed = True
                    raw_parts.append(raw)
                    i = ni
                    continue
                if c == "\\":
                    return fail()  # backslash not after continuation deletion
                if c not in _LITERAL_OK:
                    return fail()
                lit_parts.append(c)
                if not prefix_closed:
                    lit_prefix_parts.append(c)
                raw_parts.append(c)
                i += 1
                continue
            if state == "single":
                if c == "'":
                    raw_parts.append(c)
                    i += 1
                    state = "unquoted"
                    continue
                lit_parts.append(c)
                if not prefix_closed:
                    lit_prefix_parts.append(c)
                raw_parts.append(c)
                i += 1
                continue
            if state == "double":
                if c == '"':
                    raw_parts.append(c)
                    i += 1
                    state = "unquoted"
                    continue
                if c in "`\\":
                    return fail()
                if c == "$":
                    dyn, ni, raw = _parse_dollar(s, i)
                    if dyn is None:
                        return fail()
                    is_dynamic = True
                    prefix_closed = True
                    raw_parts.append(raw)
                    i = ni
                    continue
                lit_parts.append(c)
                if not prefix_closed:
                    lit_prefix_parts.append(c)
                raw_parts.append(c)
                i += 1
                continue
        if state != "unquoted":
            return fail()
        lit = "".join(lit_parts)
        pref = "".join(lit_prefix_parts)
        raw = "".join(raw_parts)
        if not raw:
            continue
        # whitespace in literal value refused
        if any(ch.isspace() for ch in lit):
            return fail()
        words.append(Word(lit, pref, is_dynamic, raw))
    if state != "unquoted":
        return fail()
    return words


def _parse_dollar(s: str, i: int) -> tuple[bool | None, int, str]:
    """Return (ok_dynamic, new_index, raw). ok_dynamic False-ish as None on fail."""
    assert s[i] == "$"
    n = len(s)
    if i + 1 >= n:
        return None, i, ""
    nxt = s[i + 1]
    # ANSI-C / special refused
    if nxt in "'\"0123456789@*?#!$-":
        return None, i, ""
    if nxt == "{":
        # ${ ... } balanced, no $ ` ( ); content default-deny (review C1).
        j = i + 2
        depth = 1
        while j < n and depth:
            c = s[j]
            if c in "$`()":
                return None, i, ""
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            j += 1
        if depth:
            return None, i, ""
        # Content between the outer braces (excludes the closing `}`).
        content = s[i + 2 : j - 1]
        # Only bare ${NAME} and numeric offset/length forms used by ci.yml.
        # Rejects @P (prompt expansion / command execution), :-/:=/:?/:+,
        # #/%// pattern ops, ${!x} indirection, ${#x} length, nested braces.
        if not _BRACED_PARAM_RE.fullmatch(content):
            return None, i, ""
        return True, j, s[i:j]
    if nxt == "(":
        # $( ... ) recursive: full closed parser, fail closed (AG)(1)(4) / review C1
        j = i + 2
        depth = 1
        while j < n and depth:
            c = s[j]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            j += 1
        if depth:
            return None, i, ""
        inner = s[i + 2 : j - 1]
        # Recursively apply the full closed parser (words + command-word allowlist
        # + operand grammar). Inner parse failure propagates as outer refusal.
        if _parse_run(inner) is None:
            return None, i, ""
        return True, j, s[i:j]
    # $NAME
    if nxt.isalpha() or nxt == "_":
        j = i + 2
        while j < n and (s[j].isalnum() or s[j] == "_"):
            j += 1
        return True, j, s[i:j]
    return None, i, ""


def _split_simple_commands(words: list[Word]) -> list[SimpleCommand] | None:
    """Split on ; && | newline. Refuse bad redirections."""
    seps = {";", "&&", "|", "\n"}
    ops_redir = {">", ">>"}
    commands: list[SimpleCommand] = []
    cur: list[Word] = []

    def flush(seq: list[Word]) -> SimpleCommand | None:
        if not seq:
            return SimpleCommand()  # empty discarded later
        cmd = SimpleCommand()
        i = 0
        # leading assignments
        while i < len(seq) and _ASSIGN_RE.match(seq[i].literal_prefix or seq[i].literal_value):
            # assignment words use literal prefix matching
            if not _ASSIGN_RE.match(seq[i].literal_prefix):
                break
            cmd.assignments.append(seq[i])
            i += 1
        if i >= len(seq):
            return cmd  # assignment-only
        # optional: redirection before command is refused
        if seq[i].literal_value in ops_redir:
            return None
        cmd.command_word = seq[i]
        i += 1
        while i < len(seq):
            if seq[i].literal_value in ops_redir:
                if i + 1 >= len(seq):
                    return None
                cmd.redirections.append((seq[i].literal_value, seq[i + 1]))
                i += 2
                continue
            cmd.args.append(seq[i])
            i += 1
        return cmd

    for w in words:
        if w.literal_value in seps and not w.is_dynamic:
            c = flush(cur)
            if c is None:
                return None
            if c.command_word is not None or c.assignments:
                commands.append(c)
            cur = []
        else:
            cur.append(w)
    c = flush(cur)
    if c is None:
        return None
    if c.command_word is not None or c.assignments:
        commands.append(c)
    return commands


def _parse_run(script: str) -> list[SimpleCommand] | None:
    words = _shell_words(script)
    if words is None:
        return None
    cmds = _split_simple_commands(words)
    if cmds is None:
        return None
    # validate command words
    for cmd in cmds:
        if cmd.command_word is None:
            continue
        cw = cmd.command_word
        if cw.is_dynamic:
            return None
        if cw.literal_value not in RUN_COMMAND_WORDS:
            return None
        for a in cmd.args:
            if a.literal_value == "go":
                return None
        for _op, tgt in cmd.redirections:
            if tgt.literal_value == "go":
                return None
    return cmds


def _flag_name(word: Word) -> str | None:
    pref = word.literal_prefix
    if not pref.startswith("-"):
        return None
    t = pref.lstrip("-")
    if "=" in t:
        t = t.split("=", 1)[0]
    return t or None


def _inline_assign_name(word: Word) -> str | None:
    pref = word.literal_prefix
    m = _ASSIGN_RE.match(pref)
    if not m:
        return None
    return pref.split("=", 1)[0]


def _is_go_test_cmd(cmd: SimpleCommand) -> bool:
    if cmd.command_word is None:
        return False
    if cmd.command_word.literal_value != "go":
        return False
    if not cmd.args:
        return False
    return cmd.args[0].literal_value == "test" and not cmd.args[0].is_dynamic


def _is_pytest_cmd(cmd: SimpleCommand) -> bool:
    if cmd.command_word is None:
        return False
    base = cmd.command_word.literal_value.rsplit("/", 1)[-1]
    if base == "pytest":
        return True
    for a in cmd.args:
        if a.literal_value == "pytest":
            return True
    return False


def _norm_cmd(cmd: SimpleCommand) -> str:
    parts: list[str] = []
    if cmd.command_word:
        parts.append(cmd.command_word.raw_text or cmd.command_word.literal_value)
    for a in cmd.args:
        parts.append(a.raw_text or a.literal_value)
    # Prefer literal values for pin equality (design: words raw texts)
    # Use literal_value with original spacing intent: join single spaces
    parts2: list[str] = []
    if cmd.command_word:
        parts2.append(cmd.command_word.literal_value)
    for a in cmd.args:
        parts2.append(a.literal_value)
    return " ".join(parts2)


def _option_word(w: Word) -> bool:
    return w.literal_prefix.startswith("-")


def _basename(w: Word) -> str:
    v = w.literal_value
    return v.rsplit("/", 1)[-1]


def _check_operands(cmd: SimpleCommand) -> bool:
    """(AL)(2). True if ok."""
    if cmd.command_word is None:
        return True
    cw = cmd.command_word.literal_value
    args = cmd.args
    if cw == "go":
        if not args:
            return False
        if args[0].is_dynamic:
            return False
        first = args[0].literal_value
        if first not in {"test", "install", "env", "vet"}:
            return False
        if first == "env":
            if [a.literal_value for a in args] != ["env", "GOPATH"]:
                return False
            if any(a.is_dynamic or _option_word(a) for a in args):
                return False
            return True
        if first == "vet":
            if [a.literal_value for a in args] != ["vet", "./..."]:
                return False
            if any(a.is_dynamic for a in args):
                return False
            return True
        if first == "install":
            if len(args) != 2:
                return False
            if args[1].is_dynamic or _option_word(args[1]):
                return False
            if args[1].literal_value not in GO_INSTALL_TARGETS:
                return False
            for a in args:
                base = _basename(a).split("@", 1)[0]
                if base in {"go", "python", "python3", "pytest"}:
                    return False
            return True
        # test: closed by EXPECTED_GO_TEST_COMMANDS later; operands free here
        return True
    if cw == "bash":
        if not args:
            return False
        if any(_option_word(a) for a in args):
            return False
        if args[0].is_dynamic or args[0].literal_value not in BASH_SCRIPTS:
            return False
        return True
    if cw in {"python", ".venv/bin/python", "services/worker/.venv/bin/python"}:
        if len(args) < 2:
            return False
        if args[0].is_dynamic or args[0].literal_value != "-m":
            return False
        if args[1].is_dynamic or args[1].literal_value not in PYTHON_MODULES:
            return False
        if any(a.literal_value == "-c" for a in args):
            return False
        return True
    if cw == "npm":
        if len(args) != 1 or args[0].is_dynamic:
            return False
        return args[0].literal_value in {"ci", "test"}
    if cw == "set":
        return [a.literal_value for a in args] == ["-euo", "pipefail"]
    if cw == "source":
        return len(args) == 1 and not args[0].is_dynamic and args[0].literal_value == "deploy/versions.env"
    if cw == "export":
        if not args:
            return False
        return all(_ASSIGN_RE.match(a.literal_prefix) for a in args)
    if cw == "echo":
        return True
    if cw == "curl":
        return all((not _option_word(a)) or a.literal_value in {"-fsSL", "-o", "-O"} for a in args)
    if cw == "tar":
        return all((not _option_word(a)) or a.literal_value in {"-xzf", "-xz", "-C"} for a in args)
    if cw == "sudo":
        if not args or any(_option_word(a) for a in args):
            return False
        if args[0].is_dynamic or args[0].literal_value not in SUDO_NESTED_COMMANDS:
            return False
        # nested mv
        nested = SimpleCommand(command_word=args[0], args=list(args[1:]))
        return _check_operands(nested)
    if cw == "mv":
        if len(args) != 2:
            return False
        if any(a.is_dynamic or _option_word(a) for a in args):
            return False
        for a in args:
            if _basename(a) in {"go", "python", "python3", "pytest"}:
                return False
        return True
    if cw == "chmod":
        if not args:
            return False
        if any(a.is_dynamic or _option_word(a) for a in args):
            return False
        return True
    if cw == "helm":
        if not args or args[0].is_dynamic:
            return False
        if args[0].literal_value not in {"version"}:
            return False
        if any(a.literal_value.startswith("--") for a in args):
            return False
        return True
    if cw.endswith("/pip") or cw in {
        ".venv/bin/pip",
        "services/worker/.venv/bin/pip",
        "services/gateway/.venv/bin/pip",
        "services/dashboard-api/.venv/bin/pip",
    }:
        if len(args) < 2:
            return False
        if args[0].is_dynamic or args[0].literal_value != "install":
            return False
        for a in args:
            if _option_word(a) and a.literal_value not in {"--upgrade", "-e"}:
                return False
            if not _option_word(a) and a is not args[0]:
                if a.is_dynamic or a.literal_value.startswith("/") or "://" in a.literal_value:
                    return False
        return True
    return False


def _go_mod_version(root: Path) -> str | None:
    text = (root / "go.mod").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("go "):
            return line.split()[1]
    return None


def _go_mod_toolchain(root: Path) -> str | None:
    text = (root / "go.mod").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("toolchain "):
            return line.split()[1].removeprefix("go")
    return None


def _env_keys(mapping) -> list[str]:
    if not mapping or not isinstance(mapping, dict):
        return []
    return list(mapping.keys())


def _is_forbidden_go_env_key(k: str) -> bool:
    return k.startswith("GO") or k.startswith("CGO") or k in GO_TOOLCHAIN_ENV_NAMES


def _is_forbidden_py_env_key(k: str) -> bool:
    return k.startswith("PYTHON") or k.startswith("PYTEST")


def _job_steps(job: dict) -> list[dict]:
    return list(job.get("steps") or [])


def _step_run(step: dict) -> str | None:
    r = step.get("run")
    return r if isinstance(r, str) else None


def _collect_run_parse(workflow: dict) -> dict[str, list[tuple[int, str, list[SimpleCommand] | None]]]:
    """job -> list of (step_index, run_text, parsed_or_None)."""
    out: dict[str, list[tuple[int, str, list[SimpleCommand] | None]]] = {}
    for jn, job in (workflow.get("jobs") or {}).items():
        rows = []
        for i, step in enumerate(_job_steps(job)):
            run = _step_run(step)
            if run is None:
                continue
            parsed = _parse_run(run)
            rows.append((i, run, parsed))
        out[jn] = rows
    return out


def _expand_commands_with_subs(
    cmds: list[SimpleCommand], run: str
) -> list[SimpleCommand] | None:
    """Collect simple commands inside every $( ) region, recursively.

    Returns None (fail closed) if any substitution fails the full closed
    parser — (AG)(1)(4) / review C1. Nested commands join the inventory for
    every command-word, operand, flag, assignment and guarded-step rule.
    """
    extra: list[SimpleCommand] = []
    s = _delete_continuations(run)
    i = 0
    while i < len(s):
        if s.startswith("$(", i):
            j = i + 2
            depth = 1
            while j < len(s) and depth:
                if s[j] == "(":
                    depth += 1
                elif s[j] == ")":
                    depth -= 1
                j += 1
            if depth:
                return None
            inner = s[i + 2 : j - 1]
            sub = _parse_run(inner)
            if sub is None:
                return None
            nested = _expand_commands_with_subs(sub, inner)
            if nested is None:
                return None
            extra.extend(nested)
            i = j
        else:
            i += 1
    return list(cmds) + extra


def _words_from_commands(cmds: list[SimpleCommand]) -> list[Word]:
    """Flatten assignment, command-word, argument and redirection-target words."""
    out: list[Word] = []
    for cmd in cmds:
        out.extend(cmd.assignments)
        if cmd.command_word is not None:
            out.append(cmd.command_word)
        out.extend(cmd.args)
        for _op, tgt in cmd.redirections:
            out.append(tgt)
    return out


def _ci_pin_failures(workflow: dict, root: Path = REPO_ROOT) -> list[str]:
    fails: list[str] = []

    def add(token: str, msg: str = "") -> None:
        fails.append(token if not msg else f"{token}:{msg}")

    jobs = workflow.get("jobs") or {}
    if set(jobs) != EXPECTED_CI_JOBS:
        add("job_inventory")

    # shell: / defaults: (AG)(6)
    if "defaults" in workflow:
        add("run_not_recognized", "workflow defaults")
    for jn, job in jobs.items():
        if "defaults" in job:
            add("run_not_recognized", f"{jn} defaults")
        if "strategy" in job:
            add("step_envelope_drift", f"{jn} strategy")
        if "continue-on-error" in job:
            add("step_envelope_drift", f"{jn} continue-on-error")
        for i, step in enumerate(_job_steps(job)):
            if "shell" in step:
                add("run_not_recognized", f"{jn}[{i}] shell")
            if "continue-on-error" in step:
                add("step_envelope_drift", f"{jn}[{i}] continue-on-error")

    # needs graph
    computed_needs: dict[str, tuple[str, ...]] = {}
    for jn, job in jobs.items():
        needs = job.get("needs")
        if needs is None:
            computed_needs[jn] = ()
        elif isinstance(needs, str):
            computed_needs[jn] = (needs,)
        else:
            computed_needs[jn] = tuple(sorted(needs))
    if computed_needs != EXPECTED_NEEDS_GRAPH:
        add("needs_graph_drift")
    if computed_needs.get("manifest-guard") != ():
        add("needs_graph_drift", "manifest-guard must have empty needs")

    # (AX) guard context
    mg = jobs.get("manifest-guard")
    if mg is not None:
        if mg.get("name") != "manifest-guard":
            add("guard_context_drift", f"name={mg.get('name')!r}")
    for jn, job in jobs.items():
        if jn != "manifest-guard" and job.get("name") == "manifest-guard":
            add("guard_context_drift", f"{jn} steals name")

    # conditional jobs/steps
    for jn, job in jobs.items():
        if "if" in job:
            text = _normalize_ws(job["if"])
            expected = CONDITIONAL_JOBS.get(jn)
            if expected is None or _normalize_ws(expected) != text:
                add("step_envelope_drift", f"job if {jn}")
        elif jn in CONDITIONAL_JOBS:
            add("step_envelope_drift", f"missing job if {jn}")
        # absolute: guarded jobs cannot be conditional
        if jn in GUARDED_STEPS and "if" in job:
            add("step_envelope_drift", f"guarded job if {jn}")
        if jn == "manifest-guard" and "if" in job:
            add("step_envelope_drift", "manifest-guard if")

    for jn, pairs in CONDITIONAL_STEPS.items():
        job = jobs.get(jn)
        if not job:
            add("step_envelope_drift", f"missing job {jn}")
            continue
        steps = _job_steps(job)
        found = []
        for i, step in enumerate(steps):
            if "if" in step:
                found.append((i, _normalize_ws(step["if"])))
        expected = [(i, _normalize_ws(t)) for i, t in pairs]
        if found != expected:
            # allow only the expected ones; extra ifs elsewhere in other jobs checked below
            pass
        for i, t in expected:
            if i >= len(steps) or "if" not in steps[i] or _normalize_ws(steps[i]["if"]) != t:
                add("step_envelope_drift", f"step if {jn}[{i}]")

    for jn, job in jobs.items():
        steps = _job_steps(job)
        for i, step in enumerate(steps):
            if "if" not in step:
                continue
            allowed = {(jn2, idx) for jn2, pairs in CONDITIONAL_STEPS.items() for idx, _ in pairs}
            if (jn, i) not in allowed:
                add("step_envelope_drift", f"unexpected if {jn}[{i}]")
            if jn in GUARDED_STEPS and i in GUARDED_STEPS[jn]:
                add("step_envelope_drift", f"if on guarded step {jn}[{i}]")

    # env scopes
    for k in _env_keys(workflow.get("env")):
        if _is_forbidden_go_env_key(k):
            add("go_env_key", f"workflow {k}")
        if _is_forbidden_py_env_key(k):
            add("python_env_key", f"workflow {k}")

    run_data = _collect_run_parse(workflow)

    # UNPARSED equality — pin is a hard-coded literal (AG)(5) / review C2
    unparsed_expected: dict[str, list[str]] = dict(UNPARSED_RUN_STEPS)

    for jn, rows in run_data.items():
        refused = [run.strip() for i, run, parsed in rows if parsed is None]
        expected = unparsed_expected.get(jn, [])
        if [r.strip() for r in refused] != [e.strip() for e in expected]:
            add("run_not_recognized", f"{jn} unparsed mismatch")

    # (AG)(5) belt: no *pinned* unreadable string may contain lowercase
    # go / python / pytest (case-sensitive), because an unparsed body escapes
    # the operand grammar. Hygiene legitimately holds PYTHON/PYTEST uppercase
    # only.
    #
    # bench-on-demand (FP-BOD-1/5) introduces exactly two exceptions, both
    # named constants and both byte-pinned above. They exist because the
    # closed grammar refuses a quoted word containing whitespace, and the B1
    # harness selection `-m "not b1_live and not b1_product"` is exactly that
    # -- as is every pytest marker expression, since `not X` has a space in
    # it. Rather than drop the belt, each exception is put through
    # `_pinned_body_escape_failures`, which restates, on the same bytes, every
    # property the grammar would have decided: no pipe, redirect, command
    # substitution, backquote, `&&`, `;`, `||`, inline assignment, plugin
    # injection, interpreter optimisation flag, deselection or masking, and
    # nothing but admitted command words at the head of each line.
    for jn, pinned_list in unparsed_expected.items():
        for r in pinned_list:
            if not ("go" in r or "python" in r or "pytest" in r):
                continue
            if r not in PINNED_EXECUTABLE_RUNS:
                add("run_not_recognized", f"{jn} pinned contains go|python|pytest")
                continue
            for reason in _pinned_body_escape_failures(r):
                add("run_not_recognized", f"{jn} pinned body {reason}")

    # lexical GITHUB_ENV ban and flag scans over words
    go_test_jobs_found: set[str] = set()
    guarded_computed: dict[str, list[int]] = {}
    pytest_cmds: dict[str, list[tuple[str | None, str]]] = {}
    go_test_cmds: dict[str, list[tuple[str | None, str]]] = {}

    go_version = _go_mod_version(root)
    toolchain = _go_mod_toolchain(root)

    for jn, job in jobs.items():
        steps = _job_steps(job)
        # job env
        if jn in GO_TEST_JOBS or jn in PYTHON_OPT_JOBS:
            for k in _env_keys(job.get("env")):
                if jn in GO_TEST_JOBS and _is_forbidden_go_env_key(k):
                    add("go_env_key", f"{jn} {k}")
                if jn in PYTHON_OPT_JOBS and _is_forbidden_py_env_key(k):
                    add("python_env_key", f"{jn} {k}")

        setup_idxs: list[int] = []
        go_idxs: list[int] = []
        g_idxs: list[int] = []

        for i, step in enumerate(steps):
            uses = step.get("uses") or ""
            if isinstance(uses, str) and uses.startswith("actions/setup-go@"):
                setup_idxs.append(i)
                if jn in GO_TEST_JOBS:
                    if "if" in step:
                        add("go_version_mismatch", f"{jn} setup-go if")
                    with_ = step.get("with") or {}
                    gv = with_.get("go-version")
                    if "go-version-file" in with_ or not isinstance(gv, str):
                        add("go_version_mismatch", f"{jn} go-version form")
                    elif gv.strip('"').strip("'") != go_version:
                        add("go_version_mismatch", f"{jn} {gv}!={go_version}")
                    if toolchain and toolchain != go_version:
                        add("go_version_mismatch", "toolchain")

            # step env
            if jn in GO_TEST_JOBS or jn in PYTHON_OPT_JOBS:
                for k in _env_keys(step.get("env")):
                    if jn in GO_TEST_JOBS and _is_forbidden_go_env_key(k):
                        add("go_env_key", f"{jn}[{i}] {k}")
                    if jn in PYTHON_OPT_JOBS and _is_forbidden_py_env_key(k):
                        add("python_env_key", f"{jn}[{i}] {k}")

            run = _step_run(step)
            if run is None:
                continue

            # GITHUB_ENV lexical
            if jn in PYTHON_OPT_JOBS and "GITHUB_ENV" in run:
                add("github_env_write", f"{jn}[{i}]")

            # e2e GITHUB_PATH equality
            if jn == "e2e" and "GITHUB_PATH" in run:
                path_lines = {ln.strip() for ln in run.splitlines() if "GITHUB_PATH" in ln}
                if path_lines != EXPECTED_E2E_GITHUB_PATH_LINES and not path_lines.issubset(EXPECTED_E2E_GITHUB_PATH_LINES):
                    # collect all path writes in e2e job later
                    pass

            parsed = _parse_run(run)
            if parsed is None:
                continue

            all_cmds = _expand_commands_with_subs(parsed, run)
            if all_cmds is None:
                # Nested substitution failed closed after outer parse — treat
                # as unrecognized (belt; _parse_dollar already refuses).
                add("run_not_recognized", f"{jn}[{i}] nested sub")
                continue

            # operand checks on every nested command too (AL)(2) / C1
            for cmd in all_cmds:
                if not _check_operands(cmd):
                    add("command_operand_drift", f"{jn}[{i}] {cmd.command_word and cmd.command_word.literal_value}")

            # flags / assignments on every word of every nested command (C1)
            words = _words_from_commands(all_cmds)
            for w in words:
                fn = _flag_name(w)
                an = _inline_assign_name(w)
                if fn == "tags":
                    add("go_build_tag_flag", f"{jn}[{i}]")
                if jn in RACE_SHORT_BAN_JOBS and fn in {"race", "short"}:
                    add("go_race_or_short_flag", f"{jn}[{i}]")
                if an and _is_forbidden_go_env_key(an):
                    add("go_env_key", f"{jn}[{i}] inline {an}")
                if jn in PYTHON_OPT_JOBS:
                    if fn in {"O", "OO"}:
                        add("python_optimize_flag", f"{jn}[{i}]")
                    if an and _is_forbidden_py_env_key(an):
                        add("python_env_key", f"{jn}[{i}] inline {an}")

            has_go_test = False
            has_pytest = False
            for cmd in all_cmds:
                if _is_go_test_cmd(cmd):
                    has_go_test = True
                    # static + no assignments
                    if cmd.assignments or any(w.is_dynamic for w in [cmd.command_word, *cmd.args] if w):
                        add("go_test_command_unparsed", f"{jn}[{i}]")
                    else:
                        wd = step.get("working-directory")
                        go_test_cmds.setdefault(jn, []).append((wd, _norm_cmd(cmd)))
                if _is_pytest_cmd(cmd):
                    has_pytest = True
                    wd = step.get("working-directory")
                    pytest_cmds.setdefault(jn, []).append((wd, _norm_cmd(cmd)))

            if has_go_test:
                go_test_jobs_found.add(jn)
                go_idxs.append(i)
            if has_go_test or has_pytest:
                g_idxs.append(i)
                # (AK)(4) guarded step shape — outer parsed commands only for
                # the step envelope; $() anywhere in the run is still banned.
                outer_words = _shell_words(run) or []
                if "|" in {w.literal_value for w in outer_words}:
                    add("guarded_step_shape", f"{jn}[{i}] pipe")
                if any(w.literal_value in {">", ">>"} for w in outer_words):
                    add("guarded_step_shape", f"{jn}[{i}] redir")
                if "$(" in run:
                    add("guarded_step_shape", f"{jn}[{i}] subshell")
                for cmd in parsed:
                    if cmd.assignments:
                        add("guarded_step_shape", f"{jn}[{i}] assign")
                    if cmd.command_word and cmd.command_word.literal_value not in GUARDED_STEP_COMMAND_WORDS:
                        add("guarded_step_shape", f"{jn}[{i}] cw")

        if g_idxs:
            guarded_computed[jn] = g_idxs

        if jn in GO_TEST_JOBS:
            if len(setup_idxs) != 1:
                add("missing_setup_go", jn)
            elif go_idxs and setup_idxs[0] >= min(go_idxs):
                add("setup_go_ordering", jn)
            elif not go_idxs:
                add("missing_setup_go", f"{jn} no go test")
            # runner
            if job.get("runs-on") != "ubuntu-latest":
                add("go_runner_drift", jn)
            if "container" in job:
                add("go_runner_drift", f"{jn} container")

    if go_test_jobs_found != GO_TEST_JOBS:
        add("go_test_job_inventory")

    if guarded_computed != GUARDED_STEPS:
        add("step_envelope_drift", "guarded inventory")

    # pytest command equality
    for jn, expected in EXPECTED_PYTEST_COMMANDS.items():
        got = pytest_cmds.get(jn, [])
        if got != expected:
            add("pytest_command_drift", jn)
    for jn in pytest_cmds:
        if jn not in EXPECTED_PYTEST_COMMANDS:
            add("pytest_command_drift", f"extra {jn}")

    for jn, expected in EXPECTED_GO_TEST_COMMANDS.items():
        got = go_test_cmds.get(jn, [])
        if got != expected:
            add("go_test_command_drift", jn)
    for jn in go_test_cmds:
        if jn not in EXPECTED_GO_TEST_COMMANDS:
            add("go_test_command_drift", f"extra {jn}")

    # e2e GITHUB_PATH job-wide
    e2e = jobs.get("e2e")
    if e2e:
        path_lines: set[str] = set()
        for step in _job_steps(e2e):
            run = _step_run(step)
            if not run:
                continue
            for ln in run.splitlines():
                if "GITHUB_PATH" in ln:
                    path_lines.add(ln.strip())
        if path_lines != EXPECTED_E2E_GITHUB_PATH_LINES:
            add("github_path_write_drift")

    # extract unique tokens (first component)
    tokens = []
    for f in fails:
        tokens.append(f.split(":", 1)[0])
    return tokens


def _e2e_runner_failures(run_sh_text: str) -> list[str]:
    fails: list[str] = []
    # exactly one -m pytest
    pytest_lines = [ln for ln in run_sh_text.splitlines() if "-m pytest" in ln]
    # normalize command: drop continuations, collapse ws
    # find the invocation
    text = run_sh_text.replace("\\\n", " ")
    # locate python3 -m pytest ...
    import re as _re
    m = _re.search(r"python3\s+-m\s+pytest\b[^\n]*", text)
    count = len(_re.findall(r"-m\s+pytest\b", text))
    if count != 1:
        fails.append("e2e_command_drift")
    else:
        # extract full command line roughly
        for ln in run_sh_text.replace("\\\n", " ").splitlines():
            if "-m pytest" in ln:
                norm = " ".join(ln.split())
                # strip leading stuff in phase body
                if "python3 -m pytest" in norm:
                    idx = norm.index("python3 -m pytest")
                    cmd = norm[idx:]
                    # strip trailing quotes/backslashes
                    cmd = cmd.rstrip("\'\"")
                    if cmd != EXPECTED_E2E_PYTEST_COMMAND:
                        fails.append("e2e_command_drift")
                break

    # flag O/OO in whitespace tokens with quote strip
    for tok in run_sh_text.split():
        t = tok
        if len(t) >= 2 and t[0] == t[-1] and t[0] in "'\"":
            t = t[1:-1]
        flag = t.lstrip("-")
        if "=" in flag:
            flag = flag.split("=", 1)[0]
        name = flag if t.startswith("-") else None
        # after stripping dashes once or twice
        if t.startswith("-"):
            fn = t.lstrip("-").split("=", 1)[0]
            if fn in {"O", "OO"}:
                fails.append("e2e_command_drift")

    # PYTHON/PYTEST assign or export
    for ln in run_sh_text.splitlines():
        s = ln.strip()
        if s.startswith("export "):
            rest = s[len("export "):].strip()
            name = rest.split("=", 1)[0].split()[0] if rest else ""
            if name.startswith("PYTHON") or name.startswith("PYTEST"):
                fails.append("python_env_key")
        for tok in s.split():
            if "=" in tok and not tok.startswith("-"):
                nm = tok.split("=", 1)[0]
                if nm.startswith("PYTHON") or nm.startswith("PYTEST"):
                    fails.append("python_env_key")

    # hygiene gate
    defs = [ln for ln in run_sh_text.splitlines() if ln.startswith("env_hygiene_gate()")]
    if len([1 for ln in run_sh_text.splitlines() if "env_hygiene_gate() {" in ln or ln.strip() == "env_hygiene_gate() {"]) != 1:
        # count function defs
        pass
    if run_sh_text.count("env_hygiene_gate() {") != 1:
        fails.append("missing_e2e_hygiene_gate")
    else:
        # body one line
        import re as _re2
        m = _re2.search(r"env_hygiene_gate\(\) \{\n  (.*?)\n\}", run_sh_text)
        if not m or m.group(1).strip() != EXPECTED_E2E_HYGIENE_COMMAND:
            fails.append("missing_e2e_hygiene_gate")

    # bare call
    call_lines = [i for i, ln in enumerate(run_sh_text.splitlines()) if ln.strip() == "env_hygiene_gate"]
    if len(call_lines) != 1:
        fails.append("missing_e2e_hygiene_gate")
    else:
        lines = run_sh_text.splitlines()
        idx = call_lines[0]
        # next non-blank non-comment
        j = idx + 1
        while j < len(lines) and (not lines[j].strip() or lines[j].strip().startswith("#")):
            j += 1
        if j >= len(lines) or not lines[j].lstrip().startswith('phase "pytest_e2e"'):
            fails.append("missing_e2e_hygiene_gate")

    return fails


def _is_config_shaped(name: str) -> bool:
    if name.endswith((".ini", ".toml", ".cfg")):
        return True
    if name == "setup.py":
        return True
    base = name.lstrip(".")
    return base.startswith("pytest")


def _covered_py_links(root: Path = REPO_ROOT) -> list[str]:
    data = _load(root / "tests" / "benchmark" / "thresholds.yaml")
    links = []
    for b in data["benchmarks"]:
        if b.get("status") != "covered":
            continue
        for lnk in b.get("tests") or []:
            if lnk.split("::", 1)[0].endswith(".py"):
                links.append(lnk)
    return links


#: bench-on-demand FP-BOD-8: the nested kind burst. It is deliberately NOT one
#: of B1's threshold-bearing links -- it carries no latency comparison at all
#: since the p99 tape was deleted -- so nothing in `thresholds.yaml` would
#: otherwise carry `tests/e2e/` into the collection-suppression guard below.
#: This constant does, explicitly: its eleven correctness clauses still fail
#: the e2e job, and a suppressed collection would silence all eleven.
B1_NESTED_CORRECTNESS_LINK = (
    "tests/e2e/test_e2e_load.py::test_b1_ingest_burst_profile"
)


def _collection_guard_links(root: Path = REPO_ROOT) -> list[str]:
    """Covered threshold links PLUS the nested correctness path.

    Collection reachability and threshold-bearingness are different claims: a
    test that decides nothing numerically must still be collected and run.
    """
    return [*_covered_py_links(root), B1_NESTED_CORRECTNESS_LINK]


def _chain_dirs(root: Path, links: list[str]) -> set[Path]:
    dirs: set[Path] = set()
    for lnk in links:
        rel = lnk.split("::", 1)[0]
        p = (root / rel).resolve()
        cur = p.parent
        root_r = root.resolve()
        while True:
            dirs.add(cur)
            if cur == root_r or cur.parent == cur:
                break
            cur = cur.parent
            if root_r not in cur.parents and cur != root_r:
                break
    dirs.add(root.resolve())
    return dirs


def _collect_toml_keys(data: dict, prefix: str = "") -> set[str]:
    keys: set[str] = set()
    for k, v in data.items():
        dotted = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            keys |= _collect_toml_keys(v, dotted)
        else:
            keys.add(k)  # option keys are leaf names
    return keys


def _pytest_keys_from_file(path: Path) -> tuple[set[str] | None, str | None]:
    """Return (keys, error_token)."""
    name = path.name
    try:
        if name.endswith((".ini", ".cfg")):
            cp = configparser.RawConfigParser(strict=True)
            cp.read(path, encoding="utf-8")
            dedicated = name.lstrip(".").startswith("pytest")
            keys: set[str] = set()
            for sec in cp.sections():
                if dedicated or "pytest" in sec.lower():
                    keys |= set(cp.options(sec))
            if dedicated:
                # every key in every section
                keys = set()
                for sec in cp.sections():
                    keys |= set(cp.options(sec))
            return keys, None
        if name.endswith(".toml"):
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            dedicated = name.lstrip(".").startswith("pytest")
            keys = set()
            if dedicated:
                def all_leaf_keys(d, acc):
                    for k, v in d.items():
                        if isinstance(v, dict):
                            all_leaf_keys(v, acc)
                        else:
                            acc.add(k)
                all_leaf_keys(data, keys)
            else:
                def walk(d, path_parts):
                    for k, v in d.items():
                        parts = path_parts + [k]
                        dotted = ".".join(parts)
                        if isinstance(v, dict):
                            if "pytest" in dotted.lower():
                                for kk, vv in v.items():
                                    if not isinstance(vv, dict):
                                        keys.add(kk)
                                    else:
                                        walk({kk: vv}, parts)
                            else:
                                walk(v, parts)
                walk(data, [])
            return keys, None
        return set(), None
    except Exception:
        return None, "pytest_config_unreadable"


def _conftest_hook_failures(path: Path) -> list[str]:
    fails: list[str] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        fails.append("conftest_collection_hook")
        return fails
    if not isinstance(tree, ast.Module):
        return fails
    # (AI) any module-scope binding matching ^pytest_
    occ = _binding_occurrences(tree)
    parents = _build_parent_map(tree)
    for name, nodes in occ.items():
        for n in nodes:
            holder = _stmt_of(n, parents)
            if holder not in tree.body:
                continue
            if name.startswith("pytest_"):
                # exception: bare import pytest_asyncio
                if (
                    isinstance(holder, ast.Import)
                    and len(holder.names) == 1
                    and holder.names[0].name == "pytest_asyncio"
                    and holder.names[0].asname is None
                ):
                    continue
                fails.append("conftest_collection_hook")
            if name in {"collect_ignore", "collect_ignore_glob"}:
                fails.append("conftest_collection_hook")

    # decorators on module-scope defs
    for stmt in tree.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for dec in stmt.decorator_list:
            if not _decorator_admitted(tree, dec):
                fails.append("conftest_collection_hook")
    return fails


def _decorator_admitted(tree: ast.Module, dec: ast.AST) -> bool:
    """(AM) resolve decorator origin."""
    cur = dec
    if isinstance(cur, ast.Call):
        cur = cur.func
        if isinstance(cur, ast.Call):
            return False  # two Call layers
    root = None
    attr = None
    if isinstance(cur, ast.Name):
        root = cur.id
    elif isinstance(cur, ast.Attribute) and isinstance(cur.value, ast.Name):
        root = cur.value.id
        attr = cur.attr
    else:
        return False
    stmt = _resolve_module_binding(tree, root)
    if stmt is None:
        return False
    origin = None
    if isinstance(stmt, ast.Import):
        for a in stmt.names:
            bound = a.asname or a.name.split(".")[0]
            if bound != root:
                continue
            if a.asname is None and "." in a.name:
                return False
            if attr is None:
                return False
            origin = f"{a.name}.{attr}"
            break
    elif isinstance(stmt, ast.ImportFrom) and stmt.level == 0:
        for a in stmt.names:
            if (a.asname or a.name) != root:
                continue
            origin = f"{stmt.module}.{a.name}"
            if attr:
                origin = f"{origin}.{attr}"
            break
    else:
        return False
    return origin in ADMITTED_DECORATOR_ORIGINS


def _pytest_collection_failures(root: Path, links: list[str]) -> list[str]:
    fails: list[str] = []
    dirs = _chain_dirs(root, links)
    found: set[str] = set()
    for d in dirs:
        if not d.is_dir():
            continue
        for p in d.iterdir():
            if not p.is_file():
                continue
            if _is_config_shaped(p.name):
                rel = str(p.relative_to(root.resolve()))
                found.add(rel)
    if found != EXPECTED_CHAIN_CONFIG_FILES:
        fails.append("pytest_config_inventory")

    for rel in sorted(found & EXPECTED_CHAIN_CONFIG_FILES):
        path = root / rel
        keys, err = _pytest_keys_from_file(path)
        if err:
            fails.append(err)
            continue
        if keys is None:
            continue
        if not keys <= PYTEST_OPTION_ALLOWLIST:
            fails.append("pytest_collection_override")

    for d in dirs:
        conf = d / "conftest.py"
        if conf.is_file():
            fails.extend(_conftest_hook_failures(conf))
    return fails


# ---------------------------------------------------------------------------
# Threshold assertion fixtures (38 neg / 14 pos)
# ---------------------------------------------------------------------------

_TEST_NAME = "test_b99_ok"


def _fx(body: str, *, preamble: str = "", name: str = _TEST_NAME) -> str:
    indented = "\n".join(
        ("    " + line if line.strip() else line) for line in body.strip("\n").split("\n")
    )
    return f"{preamble}def {name}():\n{indented}\n"


THRESHOLD_ASSERTION_FIXTURES: list[tuple[str, str, Callable[[], str]]] = [
    ("docstring_only_threshold_claim", "no_candidate", lambda: _fx('"""B11 threshold p99 < 200 ms."""\nmeasured = 999999\nreturn measured\n')),
    ("comment_only_threshold_claim", "no_candidate", lambda: _fx("# B11 threshold p99 < 200 ms\nmeasured = 999999\nreturn measured\n")),
    ("assertion_message_only", "not_a_threshold_comparison", lambda: _fx('measured = 999999\nassert measured, "B11 rate must be >= 1000.0/s"\n')),
    ("threshold_only_in_a_log_line", "no_candidate", lambda: _fx('rate = 1.0\nprint(f"B11 rate={rate} threshold 1000.0")\n')),
    ("assert_in_an_uncalled_nested_def", "no_candidate", lambda: _fx("def _unused():\n    rate = 1.0\n    assert rate >= 1000.0\nrate = 1.0\nreturn rate\n")),
    ("assert_under_a_literal_false_branch", "not_a_threshold_comparison", lambda: _fx("rate = 1.0\nif False:\n    assert rate >= 1000.0\n")),
    ("equality_instead_of_a_threshold", "not_a_threshold_comparison", lambda: _fx("measured = 999999\nassert measured == 999999\n")),
    ("threshold_operand_is_a_runtime_value", "no_numeric_term", lambda: _fx('import os\nrate = 1.0\nassert rate >= float(os.environ["B11_BAR"])\n')),
    ("assert_test_is_a_short_circuit_boolop", "not_a_threshold_comparison", lambda: _fx("measured = 999999.0\nassert True or (measured < 1000.0)\n")),
    ("raise_branch_under_a_short_circuit_condition", "not_a_threshold_comparison", lambda: _fx('measured = 1.0\nif False and measured >= 1000.0:\n    raise AssertionError("over")\n')),
    ("assert_nested_under_a_short_circuit_branch", "not_a_threshold_comparison", lambda: _fx("def _cheap():\n    return False\nmeasured = 999999.0\nif False and _cheap():\n    assert measured < 1000.0\n")),
    ("both_operands_are_numeric_terms", "both_operands_numeric", lambda: _fx("assert 1.0 < 2.0\n")),
    ("assert_negates_the_comparison", "not_a_threshold_comparison", lambda: _fx("measured = 1.0\nassert not (measured >= 1000.0)\n")),
    ("module_constant_mutated_by_augassign", "unresolved_identifier", lambda: _fx('import os\nrate = 1.0\nassert rate >= BUDGET\n', preamble='BUDGET = 1000.0\nBUDGET += float(os.environ["B11_BAR"])\n\n')),
    ("module_constant_rebound_by_a_for_target", "unresolved_identifier", lambda: _fx("rate = 1.0\nassert rate >= BUDGET\n", preamble="BUDGET = 1000.0\nfor BUDGET in (1.0, 2.0):\n    pass\n\n")),
    ("module_constant_rebound_by_a_walrus", "unresolved_identifier", lambda: _fx('import os\nrate = 1.0\nassert rate >= BUDGET\n', preamble='BUDGET = 1000.0\nif (BUDGET := float(os.environ["B11_BAR"])):\n    pass\n\n')),
    ("numeric_name_also_bound_inside_the_test", "unresolved_identifier", lambda: _fx('import os\nBUDGET = float(os.environ["B11_BAR"])\nrate = 1.0\nassert rate >= BUDGET\n', preamble="BUDGET = 1000.0\n\n")),
    ("module_star_import_poisons_numeric_names", "star_import", lambda: _fx("rate = 1.0\nassert rate >= BUDGET\n", preamble="BUDGET = 1000.0\nfrom runtime_budget import *\n\n")),
    ("fail_call_on_an_unrelated_receiver", "no_fail_in_branch", lambda: _fx('class L:\n    def fail(self, m): pass\nlogger = L()\nmeasured = 1.0\nif measured >= 1000.0:\n    logger.fail("over")\n')),
    ("locally_defined_fail_function", "no_fail_in_branch", lambda: _fx('def fail(msg): pass\nmeasured = 1.0\nif measured >= 1000.0:\n    fail("over")\n')),
    ("pytest_name_rebound_before_the_fail_call", "no_fail_in_branch", lambda: _fx('import pytest\npytest = type("P", (), {"fail": staticmethod(lambda m: None)})()\nmeasured = 1.0\nif measured >= 1000.0:\n    pytest.fail("over")\n')),
    ("self_fail_branch", "no_fail_in_branch", lambda: _fx('measured = 1.0\nif measured >= 1000.0:\n    self.fail("over")\n')),
    ("hidden_nested_test_function", "nonexistent_linked_test", lambda: "def _outer():\n    def test_b99_ok():\n        measured = 1.0\n        assert measured < 1000.0\n"),
    ("test_function_inside_a_class", "nonexistent_linked_test", lambda: "class TestSuite:\n    def test_b99_ok(self):\n        measured = 1.0\n        assert measured < 1000.0\n"),
    ("top_level_function_not_named_test", "not_collected", lambda: "def check_b99():\n    measured = 1.0\n    assert measured < 1000.0\n"),
    ("assert_after_an_unconditional_return", "dead_candidate", lambda: _fx("return\nmeasured = 1.0\nassert measured < 1000.0\n")),
    ("assert_after_an_unconditional_pytest_skip", "dead_candidate", lambda: _fx('pytest.skip("later")\nmeasured = 1.0\nassert measured < 1000.0\n', preamble="import pytest\n\n")),
    ("assert_swallowed_by_except_assertionerror", "swallowed_candidate", lambda: _fx("measured = 1.0\ntry:\n    assert measured < 1000.0\nexcept AssertionError:\n    pass\n")),
    ("assert_swallowed_by_a_bare_except", "swallowed_candidate", lambda: _fx("measured = 1.0\ntry:\n    assert measured < 1000.0\nexcept:\n    pass\n")),
    ("assert_swallowed_by_except_exception", "swallowed_candidate", lambda: _fx("measured = 1.0\ntry:\n    assert measured < 1000.0\nexcept Exception:\n    pass\n")),
    ("assert_swallowed_by_a_tuple_handler", "swallowed_candidate", lambda: _fx("measured = 1.0\ntry:\n    assert measured < 1000.0\nexcept (ValueError, Exception):\n    pass\n")),
    ("assert_swallowed_by_an_unrecognized_handler_type", "swallowed_candidate", lambda: _fx("measured = 1.0\ntry:\n    assert measured < 1000.0\nexcept _ERRORS:\n    pass\n", preamble="_ERRORS = (ValueError, Exception)\n\n")),
    ("raise_branch_swallowed_by_its_own_exception_type", "swallowed_candidate", lambda: _fx('measured = 1.0\ntry:\n    if measured >= 1000.0:\n        raise RuntimeError("over")\nexcept RuntimeError:\n    pass\n')),
    ("assert_inside_a_pytest_raises_block", "swallowed_candidate", lambda: _fx("import pytest\nmeasured = 1.0\nwith pytest.raises(AssertionError):\n    assert measured < 1000.0\n")),
    ("assert_inside_a_contextlib_suppress_block", "swallowed_candidate", lambda: _fx("import contextlib\nmeasured = 1.0\nwith contextlib.suppress(AssertionError):\n    assert measured < 1000.0\n")),
    ("skip_decorated_test_function", "skipped", lambda: "import pytest\n\n@pytest.mark.skip\ndef test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n"),
    # Rebind: non-skip then skip — pytest uses the last binding; must still disqualify (review C4).
    ("module_pytestmark_skips_the_file", "skipped", lambda: "import pytest\npytestmark = pytest.mark.e2e\npytestmark = pytest.mark.skip\n\ndef test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n"),
    ("linked_file_basename_not_collected", "not_collected", lambda: _fx("measured = 1.0\nassert measured < 20.0\n")),
]


THRESHOLD_ASSERTION_POSITIVE_CONTROLS: list[tuple[str, Callable[[], str]]] = [
    ("plain_assert_against_a_literal", lambda: _fx("p99 = 1.0\nassert p99 < 20.0, f\"p99={p99}\"\n")),
    ("assert_against_a_module_constant", lambda: _fx("p99 = 1.0\nassert p99 < P99_MS\n", preamble="P99_MS = 150.0\n\n")),
    ("assert_against_a_derived_constant", lambda: _fx("offered_rate = 1000.0\nassert offered_rate >= BURST_RATE * 0.99\n", preamble="BURST_RATE = 1000\n\n")),
    ("explicit_raise_branch", lambda: _fx('measured = 1.0\nif measured >= 1000.0:\n    raise AssertionError("over budget")\n')),
    ("pytest_fail_branch", lambda: _fx('measured = 1.0\nif measured >= 1000.0:\n    pytest.fail("over budget")\n', preamble="import pytest\n\n")),
    ("chained_comparison_with_a_measured_operand", lambda: _fx("p99 = 1.0\nassert 0 < p99 < 20.0\n")),
    ("module_constant_read_in_several_places", lambda: ("BURST_RATE = 1000\nTOTAL = BURST_RATE * 30\n\ndef _helper():\n    return BURST_RATE\n\ndef test_b99_ok():\n    offered = 1000.0\n    _ = BURST_RATE\n    assert offered >= BURST_RATE * 0.99\n")),
    ("fail_imported_from_pytest", lambda: _fx('measured = 1.0\nif measured >= 1000.0:\n    fail("over")\n', preamble="from pytest import fail\n\n")),
    ("async_module_level_test", lambda: "async def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n"),
    # (R)(3) / review W1: module-level non-skip pytestmark must be accepted.
    ("custom_marker_on_the_test_function", lambda: "import pytest\npytestmark = pytest.mark.e2e\n\ndef test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n"),
    ("assert_inside_a_try_with_an_unrelated_handler", lambda: _fx("p99 = 1.0\ntry:\n    assert p99 < 20.0\nexcept ValueError:\n    pass\n")),
    ("assert_inside_a_try_whose_handler_reraises", lambda: _fx("p99 = 1.0\ntry:\n    assert p99 < 20.0\nexcept Exception:\n    raise\n")),
    ("assert_after_a_conditional_return", lambda: _fx("warm = False\nif warm:\n    return\np99 = 1.0\nassert p99 < 20.0\n")),
    ("assert_inside_an_ordinary_with_block", lambda: _fx("class F:\n    def __enter__(self): return self\n    def __exit__(self, *a): return False\nwith F() as session:\n    p99 = 1.0\n    assert p99 < 20.0\n")),
]


@pytest.mark.parametrize(
    "case_id, expected_reason, builder",
    THRESHOLD_ASSERTION_FIXTURES,
    ids=[c[0] for c in THRESHOLD_ASSERTION_FIXTURES],
)
def test_threshold_assertion_checker_rejects_known_bypasses(
    case_id: str, expected_reason: str, builder: Callable[[], str], tmp_path: Path
):
    src = builder()
    name = _TEST_NAME
    if case_id == "top_level_function_not_named_test":
        name = "check_b99"
    path = None
    if case_id == "linked_file_basename_not_collected":
        path = tmp_path / "helpers.py"
        path.write_text(src, encoding="utf-8")
    ok, reason = _python_test_asserts_threshold(src, name, path=path)
    assert ok is False, f"{case_id}: expected reject"
    assert reason == expected_reason, f"{case_id}: got {reason!r} want {expected_reason!r}"


@pytest.mark.parametrize(
    "case_id, builder",
    THRESHOLD_ASSERTION_POSITIVE_CONTROLS,
    ids=[c[0] for c in THRESHOLD_ASSERTION_POSITIVE_CONTROLS],
)
def test_threshold_assertion_checker_accepts_real_shapes(
    case_id: str, builder: Callable[[], str]
):
    src = builder()
    ok, reason = _python_test_asserts_threshold(src, _TEST_NAME)
    assert ok is True, f"{case_id}: expected accept, got reason={reason!r}"
    assert reason is None


def test_manifest_checker_is_real_caller_of_shared_seam_with_identical_fixture_verdicts(
    monkeypatch, tmp_path: Path
):
    """C3 / FP-IG-19: ``_python_test_asserts_threshold`` must call the shared
    core, and every existing fixture must produce the same verdict it did
    before the refactor (positive control).
    """
    # Patch the same module dict the checker closes over.
    mod = sys.modules[_python_test_asserts_threshold.__module__]
    calls: list[tuple] = []
    real_seam = mod._python_qualifying_comparison

    def tracking_seam(tree, test_name, *, operators, operand_rule):
        calls.append((test_name, operators, operand_rule))
        return real_seam(
            tree, test_name, operators=operators, operand_rule=operand_rule
        )

    monkeypatch.setattr(mod, "_python_qualifying_comparison", tracking_seam)

    # Reasons that exit before the shared seam is consulted.
    _EARLY_EXIT = {
        "nonexistent_linked_test",
        "not_collected",
        "skipped",
        "star_import",
        "ambiguous_test_name",
    }

    # Negative fixtures — identical reject reasons.
    for case_id, expected_reason, builder in THRESHOLD_ASSERTION_FIXTURES:
        src = builder()
        name = _TEST_NAME
        path = None
        if case_id == "top_level_function_not_named_test":
            name = "check_b99"
        if case_id == "linked_file_basename_not_collected":
            path = tmp_path / f"helpers_{case_id}.py"
            path.write_text(src, encoding="utf-8")
        before_calls = len(calls)
        ok, reason = _python_test_asserts_threshold(src, name, path=path)
        assert ok is False, f"{case_id}: expected reject"
        assert reason == expected_reason, (
            f"{case_id}: got {reason!r} want {expected_reason!r}"
        )
        if expected_reason not in _EARLY_EXIT:
            assert len(calls) > before_calls, (
                f"{case_id}: seam was not invoked — checker is not a real caller"
            )

    # Positive fixtures — identical accepts, seam always invoked.
    for case_id, builder in THRESHOLD_ASSERTION_POSITIVE_CONTROLS:
        src = builder()
        before_calls = len(calls)
        ok, reason = _python_test_asserts_threshold(src, _TEST_NAME)
        assert ok is True, f"{case_id}: expected accept, got reason={reason!r}"
        assert reason is None
        assert len(calls) > before_calls, (
            f"{case_id}: seam was not invoked — checker is not a real caller"
        )

    assert calls, "shared seam was never invoked across the fixture table"
    # Every seam call used the ordering operator set (no Eq admitted).
    for _name, operators, _rule in calls:
        assert operators == _ORDERED_OPS, operators


def test_manifest_checker_rejects_when_shared_seam_returns_empty(monkeypatch, tmp_path: Path):
    """C3 / FP-IG-19: emptying the shared seam must change every positive
    fixture's verdict to reject. Invocation alone is not authority — the
    shared result is the only route to acceptance.
    """
    mod = sys.modules[_python_test_asserts_threshold.__module__]
    calls: list[int] = []

    def empty_seam(tree, test_name, *, operators, operand_rule):
        calls.append(1)
        return []

    monkeypatch.setattr(mod, "_python_qualifying_comparison", empty_seam)

    # Every positive fixture must flip from accept → reject when the seam
    # yields nothing; the fallback must not rescue them.
    for case_id, builder in THRESHOLD_ASSERTION_POSITIVE_CONTROLS:
        src = builder()
        before = len(calls)
        ok, reason = _python_test_asserts_threshold(src, _TEST_NAME)
        assert ok is False, (
            f"{case_id}: empty seam still ACCEPTED (reason={reason!r}) — "
            "shared result is not authoritative"
        )
        assert reason is not None
        assert len(calls) > before, f"{case_id}: seam was not consulted"

    # Negative fixtures keep rejecting (verdict identical: still False).
    for case_id, expected_reason, builder in THRESHOLD_ASSERTION_FIXTURES:
        src = builder()
        name = _TEST_NAME
        path = None
        if case_id == "top_level_function_not_named_test":
            name = "check_b99"
        if case_id == "linked_file_basename_not_collected":
            path = tmp_path / f"helpers_empty_seam_{case_id}.py"
            path.write_text(src, encoding="utf-8")
        ok, reason = _python_test_asserts_threshold(src, name, path=path)
        assert ok is False, f"{case_id}: expected reject under empty seam"
        # Early-exit reasons never reach the seam and stay exact; post-seam
        # reasons may differ when evaluate-None paths no longer accept, but
        # the reject verdict is mandatory.
        _EARLY = {
            "nonexistent_linked_test",
            "not_collected",
            "skipped",
            "star_import",
            "ambiguous_test_name",
        }
        if expected_reason in _EARLY:
            assert reason == expected_reason, (
                f"{case_id}: early-exit reason changed {reason!r} vs {expected_reason!r}"
            )

    assert calls, "empty-seam control never invoked the shared seam"


# ---------------------------------------------------------------------------
# Focused (R)(3) pytestmark module-scope binding controls (review C1).
# Outside the design-pinned 38/14 tables so the fixture count stays fixed.
# ---------------------------------------------------------------------------

# (case_id, src) or (case_id, src, expected_reason). Default reason is "skipped".
# Star-import cases report the dedicated ``star_import`` token (H takes
# precedence over the pytestmark default-deny that also fires for ``import *``).
_PYTESTMARK_SKIP_CASES: list[tuple[str, ...]] = [
    # Control-flow rebind: runtime skips, top-level-only scan would miss it.
    (
        "skip_rebinding_inside_if_true",
        "import pytest\npytestmark = pytest.mark.e2e\nif True:\n"
        "    pytestmark = pytest.mark.skip\n\ndef test_b99_ok():\n"
        "    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "skip_only_inside_if_true",
        "import pytest\nif True:\n    pytestmark = pytest.mark.skip\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "skip_inside_try_body",
        "import pytest\ntry:\n    pytestmark = pytest.mark.skip\n"
        "except Exception:\n    pass\n\ndef test_b99_ok():\n"
        "    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "augassign_pytestmark_is_opaque",
        "import pytest\npytestmark = pytest.mark.e2e\n"
        "pytestmark += pytest.mark.e2e\n\ndef test_b99_ok():\n"
        "    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "destructure_binding_is_opaque",
        "import pytest\npytestmark, _other = pytest.mark.e2e, None\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "import_binding_is_opaque",
        "from somewhere import pytestmark\n\ndef test_b99_ok():\n"
        "    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "for_target_binding_is_opaque",
        "import pytest\nfor pytestmark in [pytest.mark.e2e]:\n    pass\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "walrus_skip_in_if_test",
        "import pytest\nif (pytestmark := pytest.mark.skip):\n    pass\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "list_form_with_skip_component",
        "import pytest\npytestmark = [pytest.mark.e2e, pytest.mark.skip]\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    # Module-evaluated def-attached surfaces (review C1 round 4): decorators,
    # argument defaults, and lambda defaults run at definition time in the
    # enclosing scope — a walker that only excludes whole FunctionDef/Lambda
    # nodes would miss these and falsely accept the linked test.
    (
        "walrus_skip_in_function_decorator",
        "import pytest\n"
        "@((pytestmark := pytest.mark.skip))\n"
        "def _helper():\n    pass\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "walrus_skip_in_function_default",
        "import pytest\n"
        "def _helper(m=(pytestmark := pytest.mark.skip)):\n    pass\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "walrus_skip_in_lambda_default",
        "import pytest\n"
        "_f = lambda m=(pytestmark := pytest.mark.skip): m\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    # Review C1 round 5: except* (ast.TryStar) handler is module-scope; a
    # walker that only branches on ast.Try (not generically on ExceptHandler)
    # would miss this and falsely accept the linked threshold test.
    (
        "skip_inside_except_star_handler",
        "import pytest\n"
        "try:\n"
        "    raise ExceptionGroup('eg', [ValueError('x')])\n"
        "except* ValueError:\n"
        "    pytestmark = pytest.mark.skip\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    # Deep nesting of with/for: generic child walk must reach arbitrary depth
    # without a fixed per-type container branch list.
    (
        "skip_deeply_nested_with_for",
        "import pytest\n"
        "class _CM:\n"
        "    def __enter__(self): return self\n"
        "    def __exit__(self, *a): return False\n"
        "with _CM():\n"
        "    for _ in (1,):\n"
        "        with _CM():\n"
        "            for _ in (1,):\n"
        "                pytestmark = pytest.mark.skip\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    # Review C1 round 6: AnnAssign.annotation and evaluated target expressions
    # are module-evaluated; a walker that early-returns after only stmt.value
    # would miss walrus bindings on those surfaces and falsely accept.
    (
        "walrus_skip_in_annassign_annotation",
        "import pytest\n"
        "_holder: (pytestmark := pytest.mark.skip)\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "walrus_skip_in_assign_target_subscript",
        "import pytest\n"
        "_d = {}\n"
        "_d[(pytestmark := pytest.mark.skip)] = 1\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "walrus_skip_in_augassign_target_subscript",
        "import pytest\n"
        "_d = {0: 0}\n"
        "_d[(pytestmark := pytest.mark.skip)] += 1\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "walrus_skip_in_delete_target_subscript",
        "import pytest\n"
        "_d = {0: 0}\n"
        "del _d[(pytestmark := pytest.mark.skip)]\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    # Review C1 round 7: withitem.optional_vars is an expression surface —
    # walrus in the as-target must reject; plain ``as pytestmark`` already did.
    (
        "walrus_skip_in_withitem_optional_vars",
        "import pytest\n"
        "import contextlib\n"
        "_d = {0: 0}\n"
        "with contextlib.nullcontext(1) as _d[\n"
        "    0 if (pytestmark := pytest.mark.skip) else 0\n"
        "]:\n"
        "    pass\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    # Review C1 round 7: star import may rebind pytestmark via __all__;
    # default-deny without resolving the imported module. Full-path reason is
    # ``star_import`` (H vocabulary); walker still treats it as pytestmark-opaque.
    (
        "wildcard_import_is_opaque",
        "from helper import *\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
        "star_import",
    ),
    # Review C1 round 7: class-body ``global pytestmark`` + assignment is a
    # MODULE-scope binding evaluated at class definition (import) time.
    (
        "class_body_global_pytestmark_skip",
        "import pytest\n"
        "class _C:\n"
        "    global pytestmark\n"
        "    pytestmark = pytest.mark.skip\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    # Review C1 round 8: PEP 695 ``type pytestmark = …`` binds at module scope.
    # The value is a type-alias object, not a Mark (real pytest: TypeError);
    # walker must opaque/default-deny, not treat the RHS as a marker.
    (
        "type_alias_pytestmark_is_opaque",
        "import pytest\n"
        "type pytestmark = pytest.mark.skip\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
]

_PYTESTMARK_ACCEPT_CASES: list[tuple[str, str]] = [
    (
        "non_skip_marker_at_module_scope",
        "import pytest\npytestmark = pytest.mark.e2e\n\ndef test_b99_ok():\n"
        "    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    (
        "non_skip_inside_if_true",
        "import pytest\nif True:\n    pytestmark = pytest.mark.e2e\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    # Accept control: function-body pytestmark is a nested scope and must NOT
    # reject (walker must not descend into FunctionDef bodies).
    (
        "function_local_pytestmark_ignored",
        "import pytest\ndef _helper():\n    pytestmark = pytest.mark.skip\n"
        "    return pytestmark\n\ndef test_b99_ok():\n"
        "    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    # Ordinary class attr pytestmark WITHOUT global is class-local, not module.
    (
        "class_body_pytestmark_ignored",
        "import pytest\nclass _C:\n    pytestmark = pytest.mark.skip\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    # Bounds the decorator scan: a non-pytestmark walrus must not disqualify.
    (
        "non_pytestmark_walrus_in_function_decorator",
        "import pytest\n"
        "@((other := pytest.mark.e2e))\n"
        "def _helper():\n    pass\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    # Review C1 round 6: ordinary annotated assign must not over-reject when
    # annotation recursion was added (no pytestmark on any surface).
    (
        "ordinary_annotated_assign_accepted",
        "x: int = 5\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    # Review C1 round 7: normal non-wildcard import must not default-deny
    # (only explicit pytestmark aliases and star imports are opaque).
    (
        "normal_non_wildcard_import_accepted",
        "from somewhere import other\nimport helper\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    # Review C1 round 7: uncalled nested def with global pytestmark does NOT
    # bind at import — must not reject.
    (
        "class_nested_function_global_pytestmark_ignored",
        "import pytest\n"
        "class _C:\n"
        "    def _helper(self):\n"
        "        global pytestmark\n"
        "        pytestmark = pytest.mark.skip\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    # Review C1 round 8: ordinary type alias must not over-reject when
    # TypeAlias binding dispatch was added.
    (
        "ordinary_type_alias_accepted",
        "type Alias = int\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
]


@pytest.mark.parametrize(
    "case",
    _PYTESTMARK_SKIP_CASES,
    ids=[c[0] for c in _PYTESTMARK_SKIP_CASES],
)
def test_pytestmark_skips_rejects_module_scope_binding_shapes(case: tuple[str, ...]):
    case_id, src = case[0], case[1]
    expected_reason = case[2] if len(case) > 2 else "skipped"
    tree = ast.parse(src)
    assert _pytestmark_skips(tree) is True, case_id
    ok, reason = _python_test_asserts_threshold(src, _TEST_NAME)
    assert ok is False, f"{case_id}: expected reject"
    assert reason == expected_reason, f"{case_id}: got {reason!r} want {expected_reason!r}"


@pytest.mark.parametrize(
    "case_id, src",
    _PYTESTMARK_ACCEPT_CASES,
    ids=[c[0] for c in _PYTESTMARK_ACCEPT_CASES],
)
def test_pytestmark_skips_accepts_non_skip_and_nested_scopes(
    case_id: str, src: str
):
    tree = ast.parse(src)
    assert _pytestmark_skips(tree) is False, case_id
    ok, reason = _python_test_asserts_threshold(src, _TEST_NAME)
    assert ok is True, f"{case_id}: expected accept, got reason={reason!r}"
    assert reason is None


# ---------------------------------------------------------------------------
# LINK_LOOP_FIXTURES (9)
# ---------------------------------------------------------------------------


def _write_good(path: Path, name: str = "test_b99_ok") -> None:
    path.write_text(
        f"def {name}():\n    p99 = 1.0\n    assert p99 < 20.0\n",
        encoding="utf-8",
    )


def _link_loop_valid_first_missing(tmp_path: Path) -> dict:
    _write_good(tmp_path / "test_good.py")
    return {
        "id": "B99",
        "status": "covered",
        "tests": ["test_good.py::test_b99_ok", "gone.py::test_b99_gone"],
    }


def _link_loop_unknown_test(tmp_path: Path) -> dict:
    _write_good(tmp_path / "test_good.py")
    (tmp_path / "test_other.py").write_text("def other():\n    pass\n", encoding="utf-8")
    return {
        "id": "B99",
        "status": "covered",
        "tests": ["test_good.py::test_b99_ok", "test_other.py::test_b99_gone"],
    }


def _link_loop_weak(tmp_path: Path) -> dict:
    _write_good(tmp_path / "test_good.py")
    (tmp_path / "test_weak.py").write_text(
        "def test_b99_weak():\n    measured = 1\n    assert measured == 1\n",
        encoding="utf-8",
    )
    return {
        "id": "B99",
        "status": "covered",
        "tests": ["test_good.py::test_b99_ok", "test_weak.py::test_b99_weak"],
    }


def _link_loop_all_ok(tmp_path: Path) -> dict:
    _write_good(tmp_path / "test_a.py")
    _write_good(tmp_path / "test_b.py")
    return {
        "id": "B99",
        "status": "covered",
        "tests": ["test_a.py::test_b99_ok", "test_b.py::test_b99_ok"],
    }


def _link_loop_single(tmp_path: Path) -> dict:
    _write_good(tmp_path / "test_a.py")
    return {"id": "B99", "status": "covered", "tests": ["test_a.py::test_b99_ok"]}


def _link_loop_empty(tmp_path: Path) -> dict:
    return {"id": "B99", "status": "covered", "tests": []}


def _link_loop_unknown_suffix(tmp_path: Path) -> dict:
    (tmp_path / "b99_notes.md").write_text("x", encoding="utf-8")
    return {"id": "B99", "status": "covered", "tests": ["b99_notes.md::test_b99_ok"]}


def _link_loop_go_no_guard(tmp_path: Path) -> dict:
    (tmp_path / "bench_b99_test.go").write_text(
        "package t\nfunc TestB99() {}\n", encoding="utf-8"
    )
    return {"id": "B99", "status": "covered", "tests": ["bench_b99_test.go::TestB99"]}


def _link_loop_ambiguous(tmp_path: Path) -> dict:
    (tmp_path / "test_dup.py").write_text(
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
        encoding="utf-8",
    )
    return {"id": "B99", "status": "covered", "tests": ["test_dup.py::test_b99_ok"]}


LINK_LOOP_FIXTURES: list[tuple[str, str | None, int, Callable]] = [
    ("valid_first_link_then_missing_file", "missing_file", 1, _link_loop_valid_first_missing),
    ("valid_first_link_then_unknown_test_name", "nonexistent_linked_test", 1, _link_loop_unknown_test),
    ("valid_first_link_then_link_without_a_threshold_assert", "not_a_threshold_comparison", 1, _link_loop_weak),
    ("all_links_qualify", None, 0, _link_loop_all_ok),
    ("single_link_entry_qualifies", None, 0, _link_loop_single),
    ("covered_entry_with_no_links", None, 1, _link_loop_empty),
    ("link_with_an_unknown_suffix", "unknown_suffix", 1, _link_loop_unknown_suffix),
    ("go_link_without_the_go_guard", "missing_go_guard", 1, _link_loop_go_no_guard),
    ("two_functions_with_the_linked_name", "ambiguous_test_name", 1, _link_loop_ambiguous),
]


@pytest.mark.parametrize(
    "case_id, expected_token, n_fail, builder",
    LINK_LOOP_FIXTURES,
    ids=[c[0] for c in LINK_LOOP_FIXTURES],
)
def test_every_link_of_a_covered_entry_is_checked(
    case_id: str,
    expected_token: str | None,
    n_fail: int,
    builder: Callable,
    tmp_path: Path,
):
    entry = builder(tmp_path)
    fails = _entry_link_failures(entry, root=tmp_path)
    assert len(fails) == n_fail, f"{case_id}: {fails}"
    if expected_token is not None:
        assert any(expected_token in f for f in fails), f"{case_id}: {fails}"


def test_threshold_assertion_fixture_count():
    assert len(THRESHOLD_ASSERTION_FIXTURES) == 38
    assert len(THRESHOLD_ASSERTION_POSITIVE_CONTROLS) == 14
    assert len(LINK_LOOP_FIXTURES) == 9
    # bench-on-demand FP-BOD-1 retired one row with the B1 wrapper step it
    # mutated; the count is the remaining list, not a smaller integer over the
    # same ids.
    assert len(CI_PIN_FIXTURES) == 109
    for _cid, reason, _b in THRESHOLD_ASSERTION_FIXTURES:
        assert reason in THRESHOLD_REASONS
    for _cid, tok, _n, _b in LINK_LOOP_FIXTURES:
        if tok is not None:
            assert tok in THRESHOLD_REASONS
    for row in CI_PIN_FIXTURES:
        assert row[2] in CI_PIN_REASONS
    assert THRESHOLD_REASONS & CI_PIN_REASONS == set()

# ---------------------------------------------------------------------------
# CI_PIN_FIXTURES
# ---------------------------------------------------------------------------


def _load_wf() -> dict:
    return yaml.safe_load((REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))


def _b5_step(wf: dict) -> dict:
    return wf["jobs"]["benchmark"]["steps"][10]


def _b9_step(wf: dict) -> dict:
    return wf["jobs"]["benchmark"]["steps"][12]


def _set_run(step: dict, text: str) -> None:
    step["run"] = text


def _ci_pin_workflow_cases():
    cases = []

    def add(cid, reason, mut):
        cases.append((cid, "workflow", reason, mut))

    add(
        "tags_flag_split_form",
        "go_build_tag_flag",
        lambda wf: _set_run(
            _b5_step(wf),
            "go test ./probe/internal/redact/... -tags integration -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "tags_flag_equals_form",
        "go_build_tag_flag",
        lambda wf: _set_run(
            _b5_step(wf),
            "go test ./probe/internal/redact/... -tags=integration -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "tags_flag_double_dash_form",
        "go_build_tag_flag",
        lambda wf: _set_run(
            _b5_step(wf),
            "go test ./probe/internal/redact/... --tags=integration -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "race_flag_equals_true_in_benchmark",
        "go_race_or_short_flag",
        lambda wf: _set_run(
            _b5_step(wf),
            "go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s -race=true",
        ),
    )
    add(
        "short_flag_equals_true_in_functional",
        "go_race_or_short_flag",
        lambda wf: _set_run(
            wf["jobs"]["functional"]["steps"][10],
            "go test ./tests/functional/... -v -timeout 300s -short=true",
        ),
    )
    add(
        "short_flag_split_form_in_benchmark",
        "go_race_or_short_flag",
        lambda wf: _set_run(
            _b9_step(wf),
            "go test ./probe/internal/adapter/presto/... -run TestB9 -v -timeout 60s -short",
        ),
    )
    add(
        "goflags_env_at_workflow_scope",
        "go_env_key",
        lambda wf: wf.__setitem__("env", {"GOFLAGS": "-tags=integration"}),
    )
    add(
        "cgo_enabled_env_at_job_scope",
        "go_env_key",
        lambda wf: wf["jobs"]["benchmark"].__setitem__("env", {"CGO_ENABLED": "0"}),
    )
    add(
        "goos_env_at_step_scope",
        "go_env_key",
        lambda wf: _b5_step(wf).__setitem__("env", {"GOOS": "darwin"}),
    )
    add(
        "gotoolchain_env_at_job_scope",
        "go_env_key",
        lambda wf: wf["jobs"]["benchmark"].__setitem__("env", {"GOTOOLCHAIN": "go1.27.0"}),
    )
    add(
        "inline_goflags_assignment_in_a_run",
        "go_env_key",
        lambda wf: _set_run(
            _b5_step(wf),
            "GOFLAGS=-tags=integration go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s",
        ),
    )

    def remove_setup(wf):
        steps = wf["jobs"]["benchmark"]["steps"]
        wf["jobs"]["benchmark"]["steps"] = [
            s for s in steps if not str(s.get("uses", "")).startswith("actions/setup-go@")
        ]

    add("setup_go_step_removed_from_benchmark", "missing_setup_go", remove_setup)

    def bad_ver(wf):
        for s in wf["jobs"]["benchmark"]["steps"]:
            if str(s.get("uses", "")).startswith("actions/setup-go@"):
                s.setdefault("with", {})["go-version"] = "1.25.0"

    add("setup_go_version_disagrees_with_go_mod", "go_version_mismatch", bad_ver)

    def ver_file(wf):
        for s in wf["jobs"]["benchmark"]["steps"]:
            if str(s.get("uses", "")).startswith("actions/setup-go@"):
                s["with"] = {"go-version-file": "go.mod"}

    add("setup_go_uses_go_version_file", "go_version_mismatch", ver_file)
    add(
        "go_job_not_on_ubuntu_latest",
        "go_runner_drift",
        lambda wf: wf["jobs"]["benchmark"].__setitem__("runs-on", ["self-hosted", "linux"]),
    )

    def move_b5(wf):
        steps = wf["jobs"]["benchmark"]["steps"]
        step = [s for s in steps if "TestB5" in str(s.get("run", ""))][0]
        wf["jobs"]["benchmark"]["steps"] = [s for s in steps if s is not step]
        wf["jobs"]["benchmark-go"] = {
            "runs-on": "ubuntu-latest",
            "steps": [
                {"uses": "actions/checkout@v4"},
                {"uses": "actions/setup-go@v5", "with": {"go-version": "1.26.4"}},
                step,
            ],
        }

    add("go_test_moved_to_a_new_job", "go_test_job_inventory", move_b5)

    def rename_bench(wf):
        wf["jobs"]["bench"] = wf["jobs"].pop("benchmark")

    add("benchmark_job_renamed", "job_inventory", rename_bench)

    def curl_O(wf):
        run = wf["jobs"]["e2e"]["steps"][5]["run"]
        wf["jobs"]["e2e"]["steps"][5]["run"] = run.replace("-o /tmp/kind", "-O")

    add("curl_dash_O_in_the_e2e_job", "python_optimize_flag", curl_O)
    add(
        "pythonoptimize_env_in_the_e2e_job",
        "python_env_key",
        lambda wf: wf["jobs"]["e2e"].__setitem__("env", {"PYTHONOPTIMIZE": "1"}),
    )

    def github_env(wf):
        wf["jobs"]["e2e"]["steps"].append({"run": 'echo "PYTHONOPTIMIZE=1" >> "$GITHUB_ENV"'})

    add("e2e_step_writes_github_env", "github_env_write", github_env)
    add(
        "quoted_tags_equals_form",
        "go_build_tag_flag",
        lambda wf: _set_run(
            _b5_step(wf),
            'go test ./probe/internal/redact/... "-tags=integration" -run TestB5 -v -timeout 60s',
        ),
    )

    def setup_after(wf):
        steps = wf["jobs"]["benchmark"]["steps"]
        setup = [s for s in steps if str(s.get("uses", "")).startswith("actions/setup-go@")][0]
        rest = [s for s in steps if s is not setup]
        wf["jobs"]["benchmark"]["steps"] = rest + [setup]

    add("setup_go_after_go_test", "setup_go_ordering", setup_after)
    add(
        "unbalanced_quote_in_a_run_block",
        "run_not_recognized",
        lambda wf: _set_run(_b5_step(wf), "go test ./probe/internal/redact/... -run 'TestB5"),
    )
    add(
        "heredoc_in_a_go_test_job_run_block",
        "run_not_recognized",
        lambda wf: _set_run(
            _b9_step(wf),
            "cat <<EOF > /tmp/x\nhello\nEOF\ngo test ./probe/internal/adapter/presto/... -run TestB9 -v -timeout 60s",
        ),
    )
    add(
        "go_test_flags_from_a_shell_variable",
        "go_test_command_unparsed",
        lambda wf: _set_run(
            _b5_step(wf),
            "EXTRA=-tags=integration\ngo test ./probe/internal/redact/... $EXTRA -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "go_test_launched_through_eval",
        "run_not_recognized",
        lambda wf: _set_run(
            _b5_step(wf),
            "eval go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s",
        ),
    )

    def path_prepend(wf):
        wf["jobs"]["e2e"]["steps"].append({"run": 'echo "/tmp/shim" >> "$GITHUB_PATH"'})

    add("e2e_step_prepends_a_path_entry", "github_path_write_drift", path_prepend)
    add(
        "ansi_c_quoted_tags_flag",
        "run_not_recognized",
        lambda wf: _set_run(
            _b5_step(wf),
            "go test ./probe/internal/redact/... $'-tags=integration' -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "go_test_under_a_reserved_word",
        "run_not_recognized",
        lambda wf: _set_run(
            _b5_step(wf),
            'if true; then go test ./probe/internal/redact/... "$EXTRA"; fi',
        ),
    )
    add(
        "go_test_through_an_unlisted_wrapper",
        "run_not_recognized",
        lambda wf: _set_run(
            _b5_step(wf),
            "nohup go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "go_test_wrapped_in_sudo",
        "run_not_recognized",
        lambda wf: _set_run(
            _b5_step(wf),
            "sudo go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "inline_shell_program_passed_to_bash",
        "run_not_recognized",
        lambda wf: _set_run(
            _b5_step(wf),
            'bash -c "go test ./probe/internal/redact/... -tags=integration -run TestB5"',
        ),
    )
    add(
        "unpinned_compound_command_in_a_go_test_job",
        "run_not_recognized",
        lambda wf: wf["jobs"]["benchmark"]["steps"].append(
            {"run": 'for p in ./probe/...; do go test "$p"; done'}
        ),
    )

    def edit_push(wf):
        r = wf["jobs"]["images"]["steps"][7]["run"]
        wf["jobs"]["images"]["steps"][7]["run"] = r + "\necho extra\n"

    add("pinned_push_step_edited", "run_not_recognized", edit_push)
    add(
        "step_declares_an_alternate_shell",
        "run_not_recognized",
        lambda wf: _b9_step(wf).__setitem__("shell", "python"),
    )

    # bench-on-demand FP-BOD-1: the functional job's measured step is pinned
    # as a reviewable literal (the closed grammar refuses its quoted marker
    # expression), so an edit to it is `run_not_recognized` rather than
    # `pytest_command_drift` -- and it is BYTE equality, so an added `-o`
    # override, a widened `--ignore` and a prepended `source` are all caught.
    def override_ini(wf):
        r = wf["jobs"]["functional"]["steps"][9]["run"]
        wf["jobs"]["functional"]["steps"][9]["run"] = (
            r.rstrip() + ' -o "python_functions=test_ci_*"\n'
        )

    add("functional_pytest_gains_an_override_ini", "run_not_recognized", override_ini)

    # Step 17 is the surviving benchmark pytest step (B2/B10 node ids) since
    # the two B1 wrapper steps were deleted.
    def config_flag(wf):
        r = wf["jobs"]["benchmark"]["steps"][17]["run"]
        wf["jobs"]["benchmark"]["steps"][17]["run"] = r.rstrip() + " -c /tmp/alt.ini\n"

    add("benchmark_pytest_gains_a_config_flag", "pytest_command_drift", config_flag)

    def deselect(wf):
        r = wf["jobs"]["benchmark"]["steps"][17]["run"]
        wf["jobs"]["benchmark"]["steps"][17]["run"] = r.rstrip() + (
            " --deselect tests/benchmark/test_pg_scale.py::test_b2_fingerprint_correlation_p99_under_20ms\n"
        )

    add("benchmark_pytest_gains_a_deselection", "pytest_command_drift", deselect)

    # bench-on-demand FP-BOD-1: the `benchmark_b1_wrapper_gains_an_option_word`
    # case is RETIRED with the wrapper step it mutated -- no CI job delegates a
    # B1 run to the launcher any more. Its replacement has the opposite
    # polarity and a different owner: `_B1_ROUTE_MUTATIONS`'s
    # `b1_wrapper_returned_to_ci` puts a wrapper step back and requires
    # `wrapper_inventory_drift`, and `test_ci_does_not_run_b1_or_b11` names the
    # target. There is nothing for a wrapper-shape fixture to mutate here.

    def ignore_wide(wf):
        r = wf["jobs"]["functional"]["steps"][9]["run"]
        wf["jobs"]["functional"]["steps"][9]["run"] = r.rstrip() + " --ignore=tests/functional\n"

    add("functional_pytest_ignore_widened", "run_not_recognized", ignore_wide)
    add(
        "unit_gateway_pytest_working_directory_changed",
        "pytest_command_drift",
        lambda wf: wf["jobs"]["unit-gateway"]["steps"][3].__setitem__("working-directory", "."),
    )
    add(
        "guarded_step_gains_a_false_condition",
        "step_envelope_drift",
        lambda wf: _b5_step(wf).__setitem__("if", "${{ false }}"),
    )
    add(
        "guarded_step_gains_continue_on_error",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["functional"]["steps"][9].__setitem__("continue-on-error", True),
    )
    add(
        "go_test_job_gains_continue_on_error",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["benchmark"].__setitem__("continue-on-error", True),
    )
    add(
        "job_holding_a_guarded_step_gains_a_condition",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["functional"].__setitem__("if", "github.event_name != 'schedule'"),
    )
    add(
        "upstream_job_gains_a_condition",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["lint"].__setitem__("if", "github.event_name != 'push'"),
    )
    add(
        "guarded_job_declares_a_matrix",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["benchmark"].__setitem__("strategy", {"matrix": {"n": []}}),
    )

    def del_b9(wf):
        steps = wf["jobs"]["benchmark"]["steps"]
        wf["jobs"]["benchmark"]["steps"] = [
            s for s in steps if "TestB9" not in str(s.get("run", ""))
        ]

    add("guarded_step_inventory_shifts", "step_envelope_drift", del_b9)
    add(
        "go_test_short_circuited_by_an_or",
        "run_not_recognized",
        lambda wf: _set_run(
            _b5_step(wf),
            "echo ok || go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "pytest_failure_masked_by_an_or",
        "run_not_recognized",
        lambda wf: _set_run(
            wf["jobs"]["benchmark"]["steps"][17],
            "services/worker/.venv/bin/python -m pytest tests/benchmark/test_pg_scale.py -v -s || echo ok",
        ),
    )
    add(
        "go_test_piped_into_another_command",
        "guarded_step_shape",
        lambda wf: _set_run(
            _b9_step(wf),
            "go test ./probe/internal/adapter/presto/... -run TestB9 -v -timeout 60s | echo done",
        ),
    )

    def wrap_b6(wf):
        # C1 (round 2): Bash prompt expansion ${PAYLOAD@P} executes command
        # substitutions embedded in the parameter value. Default-deny braced
        # grammar refuses @P (and all other @-transforms) as run_not_recognized
        # rather than accepting the step as readable. Count stays 104.
        wf["jobs"]["benchmark"]["steps"][11]["run"] = (
            "services/worker/.venv/bin/python -m pytest "
            "libs/py/rca_common/tests/test_rawcmd.py::test_b6_static_validator_under_5ms -v\n"
            "PAYLOAD='$(go env -w GOFLAGS=-exec=/bin/true)'\n"
            'echo "${PAYLOAD@P}"\n'
        )

    add("pytest_wrapped_in_a_command_substitution", "run_not_recognized", wrap_b6)

    def source_guarded(wf):
        r = wf["jobs"]["functional"]["steps"][9]["run"]
        wf["jobs"]["functional"]["steps"][9]["run"] = "source deploy/versions.env\n" + r

    add("source_command_inside_a_guarded_step", "run_not_recognized", source_guarded)

    def redir(wf):
        r = wf["jobs"]["benchmark"]["steps"][14]["run"]
        wf["jobs"]["benchmark"]["steps"][14]["run"] = r.rstrip() + " > /tmp/b13.log\n"

    add("guarded_step_redirects_its_output", "guarded_step_shape", redir)

    def assign_prefix(wf):
        r = wf["jobs"]["benchmark"]["steps"][13]["run"]
        # Prefix the first non-empty line with an assignment word (AK)(4).
        lines = r.splitlines(keepends=True)
        for i, ln in enumerate(lines):
            if ln.strip():
                lines[i] = "TMPDIR=/tmp " + ln.lstrip()
                break
        wf["jobs"]["benchmark"]["steps"][13]["run"] = "".join(lines)

    add("guarded_step_gains_an_assignment_prefix", "guarded_step_shape", assign_prefix)

    def ifs_smuggle(wf):
        r = "go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s"
        wf["jobs"]["benchmark"]["steps"][10]["run"] = "bash -c 'go${IFS}test${IFS}./x'\n" + r

    add("inline_shell_program_smuggled_through_ifs", "command_operand_drift", ifs_smuggle)
    add(
        "inline_python_program_launches_pytest",
        "command_operand_drift",
        lambda wf: _set_run(wf["jobs"]["lint"]["steps"][6], "python -c 'print(1)'"),
    )
    add(
        "python_module_outside_the_pin",
        "command_operand_drift",
        lambda wf: _set_run(
            wf["jobs"]["lint"]["steps"][6],
            "python -m pip install pytest-randomly\npython -m compileall -q .",
        ),
    )
    add(
        "go_run_replaces_go_vet",
        "command_operand_drift",
        lambda wf: _set_run(wf["jobs"]["lint"]["steps"][7], "go run ./probe/cmd/probe"),
    )

    def sudo_bash(wf):
        r = wf["jobs"]["e2e"]["steps"][5]["run"]
        wf["jobs"]["e2e"]["steps"][5]["run"] = r.replace(
            "sudo mv /tmp/kind /usr/local/bin/kind", "sudo bash tests/e2e/run.sh"
        )

    add("sudo_wraps_an_unlisted_program", "command_operand_drift", sudo_bash)

    def sudo_go(wf):
        r = wf["jobs"]["e2e"]["steps"][5]["run"]
        wf["jobs"]["e2e"]["steps"][5]["run"] = r.replace(
            "sudo mv /tmp/kind /usr/local/bin/kind", "sudo mv /tmp/kind /usr/local/bin/go"
        )

    add("sudo_shadows_the_go_binary", "command_operand_drift", sudo_go)
    add(
        "bash_runs_a_script_outside_the_pin",
        "command_operand_drift",
        lambda wf: _set_run(wf["jobs"]["functional"]["steps"][5], "bash /tmp/gen.sh"),
    )

    def bash_pipe(wf):
        r = wf["jobs"]["e2e"]["steps"][5]["run"]
        wf["jobs"]["e2e"]["steps"][5]["run"] = r.replace("| tar -xz -C /tmp", "| bash")

    add("bash_reads_its_program_from_a_pipe", "command_operand_drift", bash_pipe)

    def pip_url(wf):
        r = wf["jobs"]["benchmark"]["steps"][6]["run"]
        wf["jobs"]["benchmark"]["steps"][6]["run"] = (
            r + "\nservices/worker/.venv/bin/pip install https://example.invalid/x.whl\n"
        )

    add("pip_installs_from_a_url", "command_operand_drift", pip_url)

    def tar_prog(wf):
        r = wf["jobs"]["functional"]["steps"][7]["run"]
        wf["jobs"]["functional"]["steps"][7]["run"] = r.replace(
            "tar -xzf /tmp/helm.tgz -C /tmp",
            "tar --use-compress-program=/tmp/x -xf /tmp/helm.tgz -C /tmp",
        )

    add("tar_uses_a_compress_program", "command_operand_drift", tar_prog)

    def set_plus(wf):
        r = wf["jobs"]["images"]["steps"][6]["run"]
        wf["jobs"]["images"]["steps"][6]["run"] = r.replace("set -euo pipefail", "set +e")

    add("set_disables_errexit_in_an_unguarded_step", "command_operand_drift", set_plus)
    add(
        "go_test_lists_its_tests_instead_of_running_them",
        "go_test_command_drift",
        lambda wf: _set_run(
            _b5_step(wf),
            "go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s -list .",
        ),
    )
    add(
        "go_test_compiles_without_running",
        "go_test_command_drift",
        lambda wf: _set_run(_b9_step(wf), "go test -c ./probe/internal/adapter/presto"),
    )
    add(
        "go_test_runs_under_a_no_op_exec",
        "go_test_command_drift",
        lambda wf: _set_run(
            wf["jobs"]["functional"]["steps"][10],
            "go test ./tests/functional/... -v -timeout 300s -exec /bin/true",
        ),
    )
    add(
        "go_test_step_gains_a_working_directory",
        "go_test_command_drift",
        lambda wf: wf["jobs"]["unit-go"]["steps"][7].__setitem__("working-directory", "probe"),
    )

    def install_shadow(wf):
        r = wf["jobs"]["lint"]["steps"][4]["run"]
        wf["jobs"]["lint"]["steps"][4]["run"] = (
            r + "\ngo install github.com/example/toolchain/cmd/go@v1.0.0\n"
        )

    add("go_install_shadows_the_go_toolchain", "command_operand_drift", install_shadow)
    add(
        "upstream_job_declares_an_empty_matrix",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["lint"].__setitem__("strategy", {"matrix": {"n": []}}),
    )

    def go_env_w(wf):
        r = wf["jobs"]["benchmark"]["steps"][4]["run"]
        wf["jobs"]["benchmark"]["steps"][4]["run"] = (
            r + "\nX=\ngo env -w GO${X}FLAGS=-exec=/bin/true\n"
        )

    add("go_env_persistently_records_goflags", "command_operand_drift", go_env_w)

    def go_env_diff(wf):
        r = wf["jobs"]["lint"]["steps"][4]["run"]
        wf["jobs"]["lint"]["steps"][4]["run"] = r.replace("go env GOPATH", "go env GOMODCACHE")

    add("go_env_reads_a_different_variable", "command_operand_drift", go_env_diff)
    add(
        "go_vet_runs_a_vettool",
        "command_operand_drift",
        lambda wf: _set_run(wf["jobs"]["lint"]["steps"][7], "go vet -vettool=/tmp/x ./..."),
    )

    def install_unpin(wf):
        r = wf["jobs"]["lint"]["steps"][4]["run"]
        wf["jobs"]["lint"]["steps"][4]["run"] = r.replace(
            "google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1",
            "example.com/cmd/tool@latest",
        )

    add("go_install_targets_an_unpinned_module", "command_operand_drift", install_unpin)
    add(
        "cgo_enabled_inline_assignment_in_an_unguarded_run",
        "go_env_key",
        lambda wf: _set_run(wf["jobs"]["lint"]["steps"][7], "CGO_ENABLED=0 go vet ./..."),
    )
    add(
        "cgo_cflags_env_at_step_scope",
        "go_env_key",
        lambda wf: _b5_step(wf).__setitem__("env", {"CGO_CFLAGS": "-I/tmp/x"}),
    )
    add(
        "cc_env_at_workflow_scope",
        "go_env_key",
        lambda wf: wf.__setitem__("env", {"CC": "/tmp/shim/cc"}),
    )
    add(
        "guard_job_gains_a_needs_edge",
        "needs_graph_drift",
        lambda wf: wf["jobs"]["manifest-guard"].__setitem__("needs", "lint"),
    )
    add(
        "benchmark_needs_rewired_past_the_unit_tier",
        "needs_graph_drift",
        lambda wf: wf["jobs"]["benchmark"].__setitem__("needs", "lint"),
    )
    add(
        "e2e_needs_rewired_back_to_benchmark",
        "needs_graph_drift",
        lambda wf: wf["jobs"]["e2e"].__setitem__("needs", "benchmark"),
    )
    # FP-E2EB1D-9 negative fixtures for the new conditional-step data.
    # bench-on-demand FP-BOD-8: the success-only B1 diagnostics upload is
    # deleted, so the failure upload is index 7 again. Re-adding a
    # success-conditioned upload, and widening the failure upload's condition,
    # are both drift.
    add(
        "e2e_b1_diagnostics_success_upload_returns",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["e2e"]["steps"].insert(
            7,
            {
                "name": "Upload B1 diagnostics on success",
                "if": "success()",
                "uses": "actions/upload-artifact@v4",
                "with": {"name": "e2e-b1-diagnostics", "path": "/tmp/rca-e2e/x.txt"},
            },
        ),
    )
    add(
        "e2e_failure_upload_removed",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["e2e"]["steps"].pop(7),
    )
    add(
        "e2e_failure_upload_condition_replaced_after_the_shift",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["e2e"]["steps"][7].__setitem__("if", "always()"),
    )
    add(
        "e2e_if_drops_main_push_clause",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["e2e"].__setitem__(
            "if",
            "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || "
            "startsWith(github.ref, 'refs/tags/') || github.event_name == 'pull_request'",
        ),
    )
    add(
        "guard_job_gains_a_job_level_condition",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["manifest-guard"].__setitem__(
            "if", "github.event_name == 'push'"
        ),
    )
    add(
        "guard_job_removed_from_the_workflow",
        "job_inventory",
        lambda wf: wf["jobs"].pop("manifest-guard", None),
    )
    add(
        "guard_job_renamed_out_of_its_required_context",
        "guard_context_drift",
        lambda wf: wf["jobs"]["manifest-guard"].__setitem__(
            "name", "manifest honesty + CI pin"
        ),
    )
    add(
        "another_job_takes_the_guards_context",
        "guard_context_drift",
        lambda wf: wf["jobs"]["images"].__setitem__("name", "manifest-guard"),
    )
    return cases


def _ci_pin_runner_cases():
    def mut_O(t: str) -> str:
        return t.replace(
            "python3 -m pytest tests/e2e -v --tb=short",
            "python3 -O -m pytest tests/e2e -v --tb=short",
        )

    def mut_export(t: str) -> str:
        return t.replace("env_hygiene_gate\n", "export PYTHONOPTIMIZE=1\nenv_hygiene_gate\n")

    def mut_del_gate(t: str) -> str:
        return t.replace("env_hygiene_gate\n", "")

    def mut_between(t: str) -> str:
        return t.replace("env_hygiene_gate\n", "env_hygiene_gate\necho between\n")

    return [
        ("run_sh_pytest_gains_dash_O", "runner", "e2e_command_drift", mut_O),
        ("run_sh_exports_pythonoptimize", "runner", "python_env_key", mut_export),
        ("run_sh_hygiene_gate_deleted", "runner", "missing_e2e_hygiene_gate", mut_del_gate),
        (
            "run_sh_statement_between_gate_and_phase",
            "runner",
            "missing_e2e_hygiene_gate",
            mut_between,
        ),
    ]


def _ci_pin_tree_cases():
    cases = []

    def add(cid, reason, mut):
        cases.append((cid, "tree", reason, mut))

    add(
        "root_pytest_ini_sets_addopts",
        "pytest_collection_override",
        lambda root: (root / "pytest.ini").write_text(
            "[pytest]\nasyncio_mode = auto\naddopts = -p no:cacheprovider\n",
            encoding="utf-8",
        ),
    )
    add(
        "nested_pytest_toml_in_tests_e2e",
        "pytest_config_inventory",
        lambda root: (root / "tests/e2e/pytest.toml").write_text(
            '[pytest]\npython_functions = ["check_*"]\n', encoding="utf-8"
        ),
    )
    add(
        "dot_pytest_ini_beside_a_linked_test",
        "pytest_config_inventory",
        lambda root: (root / "tests/benchmark/.pytest.ini").write_text(
            "[pytest]\n", encoding="utf-8"
        ),
    )
    add(
        "dot_pytest_toml_at_the_repo_root",
        "pytest_config_inventory",
        lambda root: (root / ".pytest.toml").write_text("[pytest]\n", encoding="utf-8"),
    )

    def worker_funcs(root):
        p = root / "services/worker/pyproject.toml"
        text = p.read_text(encoding="utf-8")
        text = text.replace(
            "[tool.pytest.ini_options]",
            '[tool.pytest.ini_options]\npython_functions = ["check_*"]',
        )
        p.write_text(text, encoding="utf-8")

    add("worker_pyproject_declares_python_functions", "pytest_collection_override", worker_funcs)

    def collect_ignore(root):
        p = root / "tests/e2e/conftest.py"
        t = p.read_text(encoding="utf-8") if p.is_file() else ""
        p.write_text(t + '\ncollect_ignore = ["test_e2e_load.py"]\n', encoding="utf-8")

    add("conftest_declares_collect_ignore", "conftest_collection_hook", collect_ignore)

    def native_table(root):
        p = root / "services/worker/pyproject.toml"
        t = p.read_text(encoding="utf-8")
        t = t.replace(
            "[tool.pytest.ini_options]",
            '[tool.pytest]\npython_functions = ["check_*"]',
        )
        p.write_text(t, encoding="utf-8")

    add("worker_pyproject_uses_the_native_pytest_table", "pytest_collection_override", native_table)

    def unread_section(root):
        p = root / "pytest.ini"
        p.write_text(
            p.read_text(encoding="utf-8") + "\n[tool:pytest]\npython_files = check_*.py\n",
            encoding="utf-8",
        )

    add("root_pytest_ini_key_under_an_unread_section", "pytest_collection_override", unread_section)

    def unreadable(root):
        p = root / "libs/py/rca_common/pyproject.toml"
        p.write_text(p.read_text(encoding="utf-8") + "\n[\n", encoding="utf-8")

    add("inventoried_pyproject_does_not_parse", "pytest_config_unreadable", unreadable)

    def unlisted_hook(root):
        p = root / "tests/benchmark/conftest.py"
        t = p.read_text(encoding="utf-8") if p.is_file() else "import pytest\n"
        p.write_text(t + "\ndef pytest_collection(session):\n    pass\n", encoding="utf-8")

    add("conftest_declares_an_unlisted_collection_hook", "conftest_collection_hook", unlisted_hook)

    def specname(root):
        p = root / "tests/e2e/conftest.py"
        t = p.read_text(encoding="utf-8") if p.is_file() else "import pytest\n"
        p.write_text(
            t
            + '\n@pytest.hookimpl(specname="pytest_collection_modifyitems")\n'
            "def _reorder(session, config, items):\n    items.clear()\n",
            encoding="utf-8",
        )

    add("conftest_binds_a_hook_through_specname", "conftest_collection_hook", specname)

    def alias_hook(root):
        p = root / "tests/functional/conftest.py"
        t = p.read_text(encoding="utf-8") if p.is_file() else "import pytest\n"
        p.write_text(
            t
            + '\nfrom pytest import hookimpl as _h\n@_h(specname="pytest_ignore_collect")\n'
            "def _skip(collection_path, config):\n    return True\n",
            encoding="utf-8",
        )

    add("conftest_imports_hookimpl_under_an_alias", "conftest_collection_hook", alias_hook)

    def alias_fixture(root):
        p = root / "tests/functional/conftest.py"
        t = p.read_text(encoding="utf-8") if p.is_file() else "import pytest\n"
        p.write_text(
            t
            + '\nfrom pytest import hookimpl as fixture\n'
            '@fixture(specname="pytest_collection_modifyitems")\n'
            "def _drop(session, config, items):\n    items.clear()\n",
            encoding="utf-8",
        )

    add("conftest_aliases_hookimpl_as_fixture", "conftest_collection_hook", alias_fixture)

    def assign_fixture(root):
        p = root / "tests/benchmark/conftest.py"
        t = p.read_text(encoding="utf-8") if p.is_file() else "import pytest\n"
        p.write_text(
            t
            + "\nfixture = pytest.hookimpl\n@fixture(specname=\"pytest_ignore_collect\")\n"
            "def _skip(collection_path, config):\n    return True\n",
            encoding="utf-8",
        )

    add("conftest_binds_fixture_by_assignment", "conftest_collection_hook", assign_fixture)

    def star(root):
        p = root / "tests/e2e/conftest.py"
        t = p.read_text(encoding="utf-8") if p.is_file() else ""
        t = (
            t.replace("import pytest", "from pytest import *")
            if "import pytest" in t
            else "from pytest import *\n" + t
        )
        p.write_text(t, encoding="utf-8")

    add("conftest_star_imports_pytest", "conftest_collection_hook", star)
    return cases


def _build_ci_pin_fixtures():
    rows = []
    rows.extend(_ci_pin_workflow_cases())
    rows.extend(_ci_pin_runner_cases())
    rows.extend(_ci_pin_tree_cases())

    def toolchain_mut(root: Path) -> None:
        p = root / "go.mod"
        p.write_text(p.read_text(encoding="utf-8") + "\ntoolchain go1.27.0\n", encoding="utf-8")

    rows.append(("go_mod_declares_a_newer_toolchain", "tree", "go_version_mismatch", toolchain_mut))
    return rows


CI_PIN_FIXTURES = _build_ci_pin_fixtures()


def _materialize_tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for rel in EXPECTED_CHAIN_CONFIG_FILES:
        src = REPO_ROOT / rel
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    (root / "go.mod").write_text((REPO_ROOT / "go.mod").read_text(encoding="utf-8"), encoding="utf-8")
    for rel in [
        "conftest.py",
        "tests/functional/conftest.py",
        "tests/e2e/conftest.py",
        "tests/benchmark/conftest.py",
        "services/worker/tests/conftest.py",
        "services/dashboard-api/tests/conftest.py",
    ]:
        src = REPO_ROOT / rel
        if src.is_file():
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    for rel in [
        "tests/e2e/test_e2e_load.py",
        "tests/benchmark/test_pg_scale.py",
        "tests/functional/test_manifests.py",
        "services/worker/tests/test_x.py",
        "services/gateway/tests/test_x.py",
        "services/dashboard-api/tests/test_x.py",
        "libs/py/rca_common/tests/test_x.py",
    ]:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_text("# dummy\n", encoding="utf-8")
    return root


def test_ci_pins_the_checker_assumptions():
    wf = _load_wf()
    fails = _ci_pin_failures(wf, REPO_ROOT)
    assert fails == [], fails
    run_sh = (REPO_ROOT / "tests/e2e/run.sh").read_text(encoding="utf-8")
    assert _e2e_runner_failures(run_sh) == []
    links = _collection_guard_links(REPO_ROOT)
    assert B1_NESTED_CORRECTNESS_LINK in links
    assert _pytest_collection_failures(REPO_ROOT, links) == []
    env_min = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LC_ALL": "C"}
    r0 = subprocess.run(["/bin/bash", "-e", "-c", EXPECTED_E2E_HYGIENE_COMMAND], env=env_min)
    assert r0.returncode == 0
    r1 = subprocess.run(
        ["/bin/bash", "-e", "-c", EXPECTED_E2E_HYGIENE_COMMAND],
        env={**env_min, "PYTHONOPTIMIZE": "1"},
    )
    assert r1.returncode != 0
    r2 = subprocess.run(
        ["/bin/bash", "-e", "-c", EXPECTED_E2E_HYGIENE_COMMAND],
        env={**env_min, "PYTEST_PLUGINS": "x"},
    )
    assert r2.returncode != 0
    assert pytest.version_tuple[0] in (8, 9)


@pytest.mark.parametrize(
    "case_id, kind, expected, mutator",
    CI_PIN_FIXTURES,
    ids=[c[0] for c in CI_PIN_FIXTURES],
)
def test_ci_pin_rejects_known_drift(case_id, kind, expected, mutator, tmp_path: Path):
    if kind == "workflow":
        wf = _load_wf()
        mutator(wf)
        fails = _ci_pin_failures(wf, REPO_ROOT)
        assert expected in fails, f"{case_id}: {fails}"
    elif kind == "runner":
        text = (REPO_ROOT / "tests/e2e/run.sh").read_text(encoding="utf-8")
        fails = _e2e_runner_failures(mutator(text))
        assert expected in fails, f"{case_id}: {fails}"
    elif kind == "tree":
        root = _materialize_tree(tmp_path)
        mutator(root)
        if case_id == "go_mod_declares_a_newer_toolchain":
            wf = _load_wf()
            fails = _ci_pin_failures(wf, root)
            assert expected in fails, f"{case_id}: {fails}"
        else:
            links = [
                "tests/e2e/test_e2e_load.py::test_b1_ingest_burst_profile",
                "tests/benchmark/test_pg_scale.py::test_b2_fingerprint_correlation_p99_under_20ms",
                "services/worker/tests/test_x.py::test_x",
                "services/gateway/tests/test_x.py::test_x",
                "services/dashboard-api/tests/test_x.py::test_x",
                "libs/py/rca_common/tests/test_x.py::test_x",
                "tests/functional/test_manifests.py::test_x",
            ]
            fails = _pytest_collection_failures(root, links)
            assert expected in fails, f"{case_id}: {fails}"
    else:
        raise AssertionError(kind)


# ---------------------------------------------------------------------------
# GC-1 — the B1 manifest contract and the one tracked B1 route (FP-GC1-2/5)
# ---------------------------------------------------------------------------

B1_LAUNCHER = REPO_ROOT / "scripts" / "integration-test.sh"
B1_PRODUCT_LINK = (
    "services/gateway/tests/test_b1_ingest_burst.py::test_b1_product_exclusive_reference_profile"
)
B1_GATEWAY_PYPROJECT = REPO_ROOT / "services" / "gateway" / "pyproject.toml"

# Every clause the shell route must carry, as independent literals. These are
# not derived from the script: a pin that reads its subject cannot detect
# drift in it.
B1_ROUTE_CLAUSES: tuple[str, ...] = (
    # image build, from the pinned Dockerfile, with the repo root as context
    "docker build -t dbagent-review-runner:b1 -f deploy/review-runner/Dockerfile .",
    # driver container: identity, namespaces, mounts, declared CPU
    'B1_DRIVER_NAME_PREFIX="dbagent-b1-driver-"',
    '--name "${B1_DRIVER_NAME_PREFIX}${B1_RUN_ID}"',
    '--label "${B1_RUN_LABEL_KEY}=${B1_RUN_ID}"',
    '--label "${B1_ROLE_LABEL_KEY}=driver"',
    "    --network host \\",
    "    --pid host \\",
    '-v "$REPO_ROOT":/workspace:ro',
    '-v "$B1_RUN_DIR":"$B1_RUN_MOUNT"',
    '-v "$B1_SOCKET":/var/run/docker.sock',
    'taskset -c "$cpuset" bash "$B1_RUN_MOUNT/$script"',
    # 32-hex run id, generated once by the shell
    'B1_RUN_ID="$(od -An -tx1 -N16 /dev/urandom | tr -d \' \\n\')"',
    'if [ "${#B1_RUN_ID}" -ne 32 ]; then',
    # the launcher's own available CPUs, read before any role is narrowed
    'affinity="$(taskset -pc $$ 2>/dev/null | sed \'s/.*: *//\')"',
    "b1_expand_cpu_list \"$affinity\" | sort -n -u",
    'if [ "${#cpus[@]}" -lt 8 ]; then',
    # the closed schema-2 product-local launch contract, affinity mechanism.
    # bench-on-demand (FP-BOD-2): it is the ONLY contract this shell writes.
    # The schema-3 topology document, the carrier read, the route record and
    # the `contract-selected` render are deleted with the CI-scale route, and
    # their literals are pinned ABSENT in B1_RETIRED_ROUTE_CLAUSES below.
    '"schema": 2,',
    '"mechanism": "sched-affinity",',
    '"profile": "product-exclusive",',
    '"minimumHostLogicalCpus": 8,',
    '"gateway": {"allowedCpus": "${gateway_cpus}"},',
    '"postgres": {"allowedCpus": "${postgres_cpus}"},',
    '"driver": {"allowedCpus": "${driver_cpus}"}',
    # writable coverage / pytest-cache / bytecode directories on the run mount
    'mkdir -p "$B1_RUN_DIR/coverage" "$B1_RUN_DIR/pytest-cache" "$B1_RUN_DIR/pycache"',
    # label-scoped, verified cleanup
    'docker ps -aq --filter "label=${B1_RUN_LABEL_KEY}=${B1_RUN_ID}"',
    "trap 'b1_cleanup' EXIT TERM INT",
    'B1_CLEANUP_FAILED=1',
    # the run directory is emptied where the privilege is (the driver writes it
    # as the image's root user, which on CI's ROOTFUL daemon is host uid 0) and
    # its own survival is a failure of its own, never a container verdict
    'B1_RUN_DIR_FAILED=1',
    'find "$B1_RUN_MOUNT" -mindepth 1 -delete',
    '--label "${B1_ROLE_LABEL_KEY}=cleanup"',
    'if [ "$B1_CLEANUP_FAILED" -ne 0 ] || [ "$B1_RUN_DIR_FAILED" -ne 0 ]; then return 1; fi',
    # the purge container is censused too: force-remove, then verify
    '    docker rm -f $ids >/dev/null 2>&1\n    ids="$(docker ps -aq --filter '
    '"label=${B1_RUN_LABEL_KEY}=${B1_RUN_ID}" 2>/dev/null)"',
)

#: bench-on-demand FP-BOD-2: every route the slice deleted, pinned ABSENT.
#: A half-revert that puts one of these back is a named failure rather than a
#: silently reinstated CI-scale gate.
B1_RETIRED_ROUTE_CLAUSES: tuple[str, ...] = (
    "b1_topology_probe",
    "b1_latency_basis",
    "B1_PROBE_PLANNER",
    "B1_ROUTE_RECORD",
    "contract-selected",
    "route-fields",
    "b1_topology_decision.json",
    "b1_write_coverage_driver",
    "driver-coverage.sh",
    "driver-live.sh",
    "basis-oracle-preflight",
    "basis-oracle-route",
)

# The runner image declares VOLUME mountpoints under /workspace, and the
# driver binds the repository there read-only. Docker materialises an image
# VOLUME as an anonymous volume at `docker run` and creates its mountpoint if
# the path is missing -- which it cannot do inside a read-only bind (EROFS).
# The set is READ FROM THE IMAGE, not restated here, so the launcher's mkdir
# and the Dockerfile cannot drift apart: adding a VOLUME without preparing its
# mountpoint is exactly the defect this pin exists to catch.
B1_RUNNER_DOCKERFILE = REPO_ROOT / "deploy" / "review-runner" / "Dockerfile"
_B1_VOLUME_LINE_RE = re.compile(r"^\s*VOLUME\s+\[(?P<body>[^\]]*)\]\s*$", re.MULTILINE)
B1_SOURCE_MOUNT = "/workspace/"


def _b1_image_volume_paths() -> tuple[str, ...]:
    """The runner image's VOLUME mountpoints, as declared in the Dockerfile."""
    bodies = _B1_VOLUME_LINE_RE.findall(
        B1_RUNNER_DOCKERFILE.read_text(encoding="utf-8")
    )
    if len(bodies) != 1:
        return ()
    return tuple(re.findall(r'"([^"]+)"', bodies[0]))


def _b1_mountpoint_failures(launcher: str) -> list[str]:
    """The image's /workspace VOLUMEs are created on the host before the run."""
    fails: list[str] = []

    def add(reason: str, detail: str = "") -> None:
        fails.append(f"{reason}{(' ' + detail) if detail else ''}")

    volumes = _b1_image_volume_paths()
    if not volumes:
        add("image_volume_declaration_unreadable")
        return fails
    expected = {
        path[len(B1_SOURCE_MOUNT):] for path in volumes if path.startswith(B1_SOURCE_MOUNT)
    }
    if not expected:
        add("image_volume_declaration_unreadable", str(sorted(volumes)))
        return fails
    lines = [ln.strip() for ln in launcher.splitlines()]
    mkdirs = [ln for ln in lines if ln.startswith("mkdir -p") and '"$REPO_ROOT/' in ln]
    if len(mkdirs) != 1:
        add("volume_mountpoint_mkdir_inventory_drift", str(len(mkdirs)))
        return fails
    operands = set(re.findall(r'"\$REPO_ROOT/([^"]+)"', mkdirs[0]))
    if operands != expected:
        add(
            "volume_mountpoint_set_drift",
            f"{sorted(operands)} != {sorted(expected)}",
        )
    # It must run in b1_prepare, which both targets call before any driver.
    prepare = [ln.strip() for ln in _b1_target_region(launcher, "b1_prepare").splitlines()]
    if mkdirs[0] not in prepare:
        add("volume_mountpoint_mkdir_outside_prepare", mkdirs[0])
    for target in ("b1_product",):
        region = [ln.strip() for ln in _b1_target_region(launcher, target).splitlines()]
        prepared = next((i for i, ln in enumerate(region) if ln.startswith("b1_prepare")), None)
        started = next((i for i, ln in enumerate(region) if ln.startswith("b1_run_driver")), None)
        if prepared is None or started is None or prepared > started:
            add("volume_mountpoint_created_too_late", f"{target} {prepared} {started}")
    return fails


# Docker bandwidth/cpuset controls, which GC-1 rev 0.5 removed as the
# allocation primitive. Their ABSENCE is pinned statically here and nowhere
# else: there is deliberately no runtime check that a role's cgroup carries no
# quota, because `cpu.max` describes whatever ambient policy the host imposes
# and is not an oracle for what this launcher applied.
B1_BANDWIDTH_CONTROLS = (
    "--cpus",
    "--cpu-period",
    "--cpu-quota",
    "--cpuset-cpus",
    "cpu_period=",
    "cpu_quota=",
    "cpuset_cpus=",
)

# Which `${cpus[N]}` index each role's generated set must take, per profile.
#
# GC-3 (FP-GC3-4) removed the ordinary CI-scale entry, and its absence is
# enforced rather than assumed: the ordinary b1 target no longer allocates
# roles at all. It routes the exact host CPU model to its ratified topology and
# asks `contract-selected` to render that class over the two OBSERVED sibling
# pairs, so a literal `${cpus[0..3]}` role assignment reappearing in that
# region would be a second topology author and is a named failure below. The
# product-local 4/3/1 pin is unchanged.
B1_AFFINITY_SELECTION = {
    "b1_product": {"gateway": (0, 1, 2, 3), "postgres": (4, 5, 6), "driver": (7,)},
}
_B1_CPU_INDEX_RE = re.compile(r"\$\{cpus\[(\d+)\]\}")
_B1_ROLE_SELECTION_RE = re.compile(
    r'^\s*(gateway|postgres|driver)_cpus="\$\(b1_canonical_cpu_list (.+)\)"\s*$'
)


# ---------------------------------------------------------------------------
# The cleanup contract (GC-1 design/slices/gc-1-reference-topology §3.3): remove
# this run's containers, fail if any survive, then drop the run directory --
# and report those two as the separate facts they are.
#
# The run directory is written by the driver container as the runner image's
# default user, root. On CI's ROOTFUL daemon that is host uid 0, so the host's
# own `rm -rf` cannot unlink it and the removal must happen through a
# root-capable path. What is pinned here is that the removal is attempted after
# the container census, that its outcome is judged by whether the directory
# survived, and that a surviving directory never prints the container verdict.
# ---------------------------------------------------------------------------
B1_CLEANUP_CENSUS = 'docker ps -aq --filter "label=${B1_RUN_LABEL_KEY}=${B1_RUN_ID}"'
B1_CONTAINER_VERDICT = "left containers behind"
B1_RUN_DIR_VERDICT = "could not remove its run directory"
B1_CLEANUP_RUN_DIR_GUARD = 'if [ -n "$B1_RUN_DIR" ] && [ -d "$B1_RUN_DIR" ]; then'
B1_CLEANUP_REMOVAL = 'rm -rf "$B1_RUN_DIR"'
B1_CLEANUP_SURVIVOR_TEST = 'if [ -d "$B1_RUN_DIR" ]; then'
B1_PURGE_TARGET = "b1_purge_run_dir"
# The measured container's identity, asserted where it is applied. Two B1
# containers now carry this run's label -- the driver and the short-lived
# cleanup purge -- so "the literal appears somewhere in the launcher" would no
# longer prove the driver still has it.
B1_DRIVER_TARGET = "b1_run_driver"
B1_DRIVER_CLAUSES = (
    '--name "${B1_DRIVER_NAME_PREFIX}${B1_RUN_ID}"',
    '--label "${B1_RUN_LABEL_KEY}=${B1_RUN_ID}"',
    '--label "${B1_ROLE_LABEL_KEY}=driver"',
    "--network host",
    "--pid host",
    '-v "$REPO_ROOT":/workspace:ro',
    '-v "$B1_RUN_DIR":"$B1_RUN_MOUNT"',
    '-v "$B1_SOCKET":/var/run/docker.sock',
    'taskset -c "$cpuset" bash "$B1_RUN_MOUNT/$script"',
)
B1_PURGE_CLAUSES = (
    # only when the image this run built actually exists
    '[ "$B1_IMAGE_BUILT" -eq 1 ] || return 0',
    # one short-lived, run-scoped, self-removing container ...
    "docker run --rm",
    '--label "${B1_RUN_LABEL_KEY}=${B1_RUN_ID}"',
    '--label "${B1_ROLE_LABEL_KEY}=cleanup"',
    # ... over this run's mount and nothing else ...
    '-v "$B1_RUN_DIR":"$B1_RUN_MOUNT"',
    '"$B1_IMAGE_TAG"',
    # ... which empties it without unlinking the busy mount point itself.
    'find "$B1_RUN_MOUNT" -mindepth 1 -delete',
)
B1_CLEANUP_GATE = (
    'if [ "$B1_CLEANUP_FAILED" -ne 0 ] || [ "$B1_RUN_DIR_FAILED" -ne 0 ]; then return 1; fi'
)


def _uncommented(region: str) -> str:
    return "\n".join(
        line for line in region.splitlines() if not line.strip().startswith("#")
    )


def _b1_cleanup_failures(launcher: str) -> list[str]:
    """The lifecycle guard's two failures stay two failures."""
    fails: list[str] = []

    def add(reason: str, detail: str = "") -> None:
        fails.append(f"{reason}{(' ' + detail) if detail else ''}")

    region = _uncommented(_b1_target_region(launcher, "b1_cleanup"))
    if not region:
        add("cleanup_target_missing")
        return fails
    if B1_CLEANUP_RUN_DIR_GUARD not in region:
        add("cleanup_run_dir_guard_missing")
        return fails
    # Three parts, in this order: the container census, the run-directory
    # branch it brackets, and the second census that covers the purge
    # container the branch itself created. The branch is delimited by its own
    # closing `fi` at the function's indentation; every `fi` inside it is
    # deeper.
    census_part, after_guard = region.split(B1_CLEANUP_RUN_DIR_GUARD, 1)
    if "\n  fi" not in after_guard:
        add("cleanup_run_dir_branch_unterminated")
        return fails
    run_dir_part, post_purge_part = after_guard.split("\n  fi", 1)

    # (1) the container census: two filtered reads, one verdict, one flag, and
    # no opinion at all about the run directory.
    if census_part.count(B1_CLEANUP_CENSUS) != 2:
        add("cleanup_census_inventory_drift", str(census_part.count(B1_CLEANUP_CENSUS)))
    if B1_CONTAINER_VERDICT not in census_part:
        add("cleanup_container_verdict_missing")
    if "B1_CLEANUP_FAILED=1" not in census_part:
        add("cleanup_container_flag_missing")
    if "B1_RUN_DIR_FAILED" in census_part:
        add("cleanup_container_branch_sets_the_run_dir_flag")

    # (2) the run directory: removed after the census, through the root-capable
    # path when the plain removal could not do it, and judged by survival.
    if "B1_CLEANUP_FAILED" in run_dir_part:
        add("cleanup_run_dir_sets_the_container_flag")
    if B1_CONTAINER_VERDICT in run_dir_part:
        add("cleanup_run_dir_blames_containers")
    if B1_RUN_DIR_VERDICT not in run_dir_part:
        add("cleanup_run_dir_verdict_missing")
    if "B1_RUN_DIR_FAILED=1" not in run_dir_part:
        add("cleanup_run_dir_flag_missing")
    if B1_PURGE_TARGET not in run_dir_part:
        add("cleanup_purge_missing")
    if B1_CLEANUP_REMOVAL not in run_dir_part:
        add("cleanup_removal_missing")
    else:
        removal_tail = run_dir_part.rsplit(B1_CLEANUP_REMOVAL, 1)[-1]
        if (B1_CLEANUP_SURVIVOR_TEST not in removal_tail
                or "B1_RUN_DIR_FAILED=1" not in removal_tail):
            add("cleanup_removal_unchecked", " ".join(removal_tail.split())[:80])

    # (2b) the purge container is a container of this run, created after the
    # first census -- so the run is censused again, with the same
    # force-remove-then-verify shape, and a survivor is still fatal.
    if post_purge_part.count(B1_CLEANUP_CENSUS) != 2:
        add("cleanup_post_purge_census_missing", str(post_purge_part.count(B1_CLEANUP_CENSUS)))
    if B1_CONTAINER_VERDICT not in post_purge_part:
        add("cleanup_post_purge_verdict_missing")
    if "B1_CLEANUP_FAILED=1" not in post_purge_part:
        add("cleanup_post_purge_flag_missing")
    if "B1_RUN_DIR_FAILED" in post_purge_part:
        add("cleanup_post_purge_sets_the_run_dir_flag")
    if B1_CLEANUP_REMOVAL in post_purge_part:
        add("cleanup_removes_the_run_dir_after_the_last_census")
    if region.count(B1_CONTAINER_VERDICT) != 2:
        add("cleanup_container_verdict_inventory_drift", str(region.count(B1_CONTAINER_VERDICT)))

    # (3) the driver container still carries its own identity and mounts.
    driver = _uncommented(_b1_target_region(launcher, B1_DRIVER_TARGET))
    if not driver:
        add("driver_target_missing")
    else:
        for clause in B1_DRIVER_CLAUSES:
            if clause not in driver:
                add("driver_clause_missing", repr(clause))

    # (4) the purge container itself, and the tree it is allowed to touch.
    purge = _uncommented(_b1_target_region(launcher, B1_PURGE_TARGET))
    if not purge:
        add("purge_target_missing")
    else:
        for clause in B1_PURGE_CLAUSES:
            if clause not in purge:
                add("purge_clause_missing", repr(clause))
        for mount in ("$REPO_ROOT", "/workspace", "docker.sock"):
            if mount in purge:
                add("purge_mounts_more_than_the_run_dir", mount)

    # (5) every consumer gates on BOTH flags, on every path that can return
    # success. bench-on-demand (FP-BOD-2) left ONE such consumer and ONE such
    # path: the product target's live exit. The recorded, no-live route that
    # needed a second gate is deleted with the CI-scale target.
    for target, expected in (("b1_product", 1),):
        observed = _uncommented(_b1_target_region(launcher, target)).count(B1_CLEANUP_GATE)
        if observed != expected:
            add("consumer_ignores_the_run_dir_failure", f"{target} {observed}/{expected}")
    return fails


def _b1_retired_arm_failures(launcher: str) -> list[str]:
    """FP-BOD-2: the sweep's per-arm lifecycle is deleted, not weakened.

    The 28-arm discovery sweep had its own cleanup contract -- reset the run
    directory flag, one container verdict, one run-directory verdict, a
    `return 1` on each -- because an arm that leaked a container contended
    with the next measurement. There is no sweep any more, so there is nothing
    to hold to that contract; what stays is that the target cannot come back
    quietly, since a re-added arm would be running an unpinned lifecycle.
    """
    if _uncommented(_b1_target_region(launcher, "b1_topology_probe_arm")):
        return ["retired_arm_target_survives"]
    return []


def _b1_target_region(launcher: str, target: str) -> str:
    """The shell text of one target, delimited by top-level function headers."""
    lines = launcher.splitlines()
    starts = [
        (index, match.group(1))
        for index, match in (
            (i, re.match(r"\A([A-Za-z0-9_]+)\(\)\s*\{\s*\Z", line))
            for i, line in enumerate(lines)
        )
        if match
    ]
    for position, (index, name) in enumerate(starts):
        if name != target:
            continue
        stop = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        return "\n".join(lines[index + 1:stop])
    return ""


def _b1_affinity_failures(launcher: str) -> list[str]:
    """Each profile's generated sets: cardinality, disjointness, index range."""
    fails: list[str] = []
    for target, expected in B1_AFFINITY_SELECTION.items():
        region = _b1_target_region(launcher, target)
        if not region:
            fails.append(f"affinity_target_missing {target}")
            continue
        selected: dict[str, tuple[int, ...]] = {}
        for line in region.splitlines():
            match = _B1_ROLE_SELECTION_RE.match(line)
            if match:
                selected[match.group(1)] = tuple(
                    int(n) for n in _B1_CPU_INDEX_RE.findall(match.group(2))
                )
        if set(selected) != set(expected):
            fails.append(f"affinity_selection_missing {target} {sorted(selected)}")
            continue
        for role, indices in expected.items():
            if len(selected[role]) != len(indices):
                fails.append(
                    f"affinity_cardinality_drift {target}/{role} {list(selected[role])}"
                )
        taken: dict[int, str] = {}
        for role in ("gateway", "postgres", "driver"):
            for index in selected[role]:
                if index in taken:
                    fails.append(
                        f"affinity_overlap {target} {taken[index]}/{role} share cpus[{index}]"
                    )
                taken[index] = role
        bound = 8
        outside = sorted(i for i in taken if not 0 <= i < bound)
        if outside:
            fails.append(f"affinity_index_drift {target} {outside} outside the first {bound}")
        if f'if [ "${{#cpus[@]}}" -lt {bound} ]; then' not in region:
            fails.append(f"affinity_host_floor_drift {target} lacks its -lt {bound} guard")
    fails.extend(_b1_ordinary_route_order_failures(launcher))
    return fails


def _b1_ordinary_route_order_failures(launcher: str) -> list[str]:
    """FP-BOD-2: the ordinary CI-scale route is deleted, and stays deleted.

    What this used to pin -- read the allowed CPU set once, run the traced
    coverage phase, evaluate the four-CPU floor inside the `gating` branch,
    render the role mapping through `contract-selected` -- described a target
    that no longer exists. The positive half moved to the product route's own
    checks in `_b1_affinity_failures`; what remains here is the absence.
    """
    fails: list[str] = []
    if _b1_target_region(launcher, "b1"):
        fails.append("retired_ci_scale_target_survives")
    for retired in ("b1_latency_basis", "b1_topology_probe", "b1_write_coverage_driver"):
        if _b1_target_region(launcher, retired):
            fails.append(f"retired_target_survives {retired}")
    return fails


B1_ENV_UNSET_PREFIX = (
    "env -u PYTHON_VERSION -u PYTHON_PIP_VERSION -u PYTHON_GET_PIP_URL "
    "-u PYTHON_GET_PIP_SHA256"
)
B1_PYCACHE_FLAG = "-X pycache_prefix=/run/dbagent-b1/pycache"
# The three files this slice changes. Coverage is reported over exactly these,
# once as an aggregate and once per file, all at --fail-under=81.
# bench-on-demand FP-BOD-1 (design.md §3.2): the coverage phase moved out of
# the deleted driver container into the functional job, so the paths are
# REPOSITORY-RELATIVE now rather than rooted at the container's /workspace
# mount, and the deleted probe module left the list. The bar is unchanged.
B1_COVERED_FILES = (
    "services/gateway/tests/b1_reference_profile.py",
    "services/gateway/tests/test_b1_ingest_burst.py",
    "scripts/b1-affinity-helper.py",
)
B1_COVERAGE_FAIL_UNDER = "--fail-under=81"
B1_COVERAGE_DATA_FILE = '--data-file="$RUNNER_TEMP/b1-harness.coverage"'
#: FP-BOD-1: the container-free harness selection, on the functional job's
#: step. Both exclusions are required: a marker that selects nothing is
#: exactly how a live node would end up inside the traced phase.
B1_COVERAGE_SELECTION = '-m "not b1_live and not b1_product"'
B1_PRODUCT_SELECTION = "-m b1_product"
B1_ROUTING_MARKERS = ("b1_live", "b1_product")
B1_REJECTED_ESCAPES = (
    "runs-on: ubuntu-24.04-8core",
    "self-hosted",
    "runner-group",
    "continue-on-error",
    "|| true",
    "--deselect",
    "pytest.mark.skip",
    "pytest.mark.xfail",
)


def _b1_launcher_source() -> str:
    return B1_LAUNCHER.read_text(encoding="utf-8")


def _b1_route_failures(workflow: dict, launcher: str, *, markers_toml: str) -> list[str]:
    """Every clause of the one-tracked-route contract, as named failures."""
    fails: list[str] = []

    def add(reason: str, detail: str = "") -> None:
        fails.append(f"{reason}{(' ' + detail) if detail else ''}")

    jobs = workflow.get("jobs") or {}
    # bench-on-demand FP-BOD-1: NO job delegates a B1 run to the launcher any
    # more, in any job, at any index. The inventory is the emptiness.
    for job_name, job in jobs.items():
        for index, step in enumerate(job.get("steps") or []):
            if "scripts/integration-test.sh" in (step.get("run") or ""):
                add("wrapper_inventory_drift", f"{job_name}[{index}]")
    if "scripts/integration-test.sh" not in BASH_SCRIPTS:
        add("wrapper_not_admitted")
    # The three routing markers are static pytest metadata, so the chain-config
    # allowlist must admit exactly `markers` (ratified GC-1 deviation).
    if "markers" not in PYTEST_OPTION_ALLOWLIST:
        add("markers_not_admitted")
    if not PYTEST_OPTION_ALLOWLIST <= {"asyncio_mode", "markers"}:
        add("markers_allowlist_widened", str(sorted(PYTEST_OPTION_ALLOWLIST)))

    # FP-BOD-2: the `b1_product` TARGET is local only -- no workflow step may
    # invoke it. The MARKER is a different string in a different position: the
    # functional job's harness selection excludes it by name, which is how the
    # live node stays out of the traced phase.
    for job_name, job in jobs.items():
        for i, step in enumerate(job.get("steps") or []):
            body = step.get("run") or ""
            if "integration-test.sh b1_product" in body:
                add("product_target_in_ci", f"{job_name}[{i}]")

    for clause in B1_ROUTE_CLAUSES:
        if clause not in launcher:
            add("route_clause_missing", repr(clause))
    for retired in B1_RETIRED_ROUTE_CLAUSES:
        if retired in launcher:
            add("retired_route_clause_survives", retired)

    # FP-BOD-1: the harness coverage phase is a functional-job step now. Its
    # selection, its three includes and its bar are pinned on that step.
    functional_steps = (jobs.get("functional") or {}).get("steps") or []
    harness_bodies = [
        (step.get("run") or "") for step in functional_steps
        if "-m coverage run" in (step.get("run") or "")
    ]
    if len(harness_bodies) != 1:
        add("coverage_phase_drift", str(len(harness_bodies)))
    else:
        body = harness_bodies[0]
        if B1_COVERAGE_SELECTION not in body:
            add("coverage_selection_drift", B1_COVERAGE_SELECTION)
        if B1_COVERAGE_DATA_FILE not in body:
            add("coverage_data_path_drift", B1_COVERAGE_DATA_FILE)
        report_lines = [
            ln.strip() for ln in body.splitlines() if "-m coverage report" in ln
        ]
        if len(report_lines) != 1 + len(B1_COVERED_FILES):
            add("coverage_report_inventory_drift", str(len(report_lines)))
        else:
            aggregate, per_file = report_lines[0], report_lines[1:]
            if f"--include={','.join(B1_COVERED_FILES)}" not in aggregate:
                add("coverage_aggregate_scope_drift", aggregate)
            for path, line in zip(B1_COVERED_FILES, per_file):
                if f"--include={path}" not in line:
                    add("coverage_per_file_scope_drift", line)
        for line in report_lines:
            if B1_COVERAGE_FAIL_UNDER not in line:
                add("coverage_bar_drift", line)
        for escape in B1_REJECTED_ESCAPES:
            if escape in body:
                add("rejected_escape_in_coverage_step", escape)

    product_lines = [
        ln for ln in launcher.splitlines()
        if "-m pytest" in ln and ln.strip().startswith(B1_ENV_UNSET_PREFIX)
        and ln.rstrip().split(" -o ")[0].endswith(B1_PRODUCT_SELECTION)
    ]
    if len(product_lines) != 1:
        add("product_selection_drift", str(len(product_lines)))
    elif "coverage run" in product_lines[0]:
        add("product_phase_traced", product_lines[0])

    # Every driver-side Python command carries the complete four-key prefix,
    # and keeps its bytecode cache off the read-only source mount: a host
    # __pycache__ entry arriving through that mount is loaded in preference to
    # the source and carries the host's own absolute paths into the container.
    for line in launcher.splitlines():
        stripped = line.strip()
        if "python3 -B" not in stripped:
            continue
        if not stripped.startswith(B1_ENV_UNSET_PREFIX + " python3 -B"):
            add("env_unset_prefix_drift", stripped)
        if B1_PYCACHE_FLAG not in stripped:
            add("pycache_prefix_drift", stripped)
    if launcher.count(B1_ENV_UNSET_PREFIX) < 1:
        add("env_unset_prefix_missing", str(launcher.count(B1_ENV_UNSET_PREFIX)))

    # Writable cache paths, never the read-only source mount. Only driver-side
    # commands are in scope: they are exactly the ones carrying the four-key
    # prefix, and they are the ones that run against /workspace:ro.
    for line in launcher.splitlines():
        stripped = line.strip()
        if not stripped.startswith(B1_ENV_UNSET_PREFIX):
            continue
        if "-m pytest" in stripped and "-o cache_dir=/run/dbagent-b1/pytest-cache" not in stripped:
            add("pytest_cache_path_drift", stripped)

    # No pass-through, no caller-supplied profile value.
    if '"$@"' in launcher.split("b1_product() {", 1)[-1].split("\nb1_topology", 1)[0]:
        add("b1_accepts_pass_through")

    for escape in B1_REJECTED_ESCAPES:
        if escape in launcher:
            add("rejected_escape_in_launcher", escape)

    # All three routing markers registered in the gateway pyproject.
    for marker in B1_ROUTING_MARKERS:
        if f'"{marker}:' not in markers_toml:
            add("marker_not_registered", marker)

    # Fixture-side literals: the quota pairs are applied from Python constants,
    # never read from the environment.
    fixture_src = (
        REPO_ROOT / "services" / "gateway" / "tests" / "test_b1_ingest_burst.py"
    ).read_text(encoding="utf-8")
    for clause in (
        # The allocation is affinity cardinality, declared in Python. GC-3
        # (FP-GC3-4) made the CI-scale half a CLOSED MAP KEYED BY EXACT
        # cpuModel -- checked entry by entry against the tracked carrier below
        # -- while the product-local scalar is unchanged.
        'PRODUCT_AFFINITY_CARDINALITY = {"gateway": 4, "postgres": 3, "driver": 1}',
        "PRODUCT_PLACEMENT_SCHEMA = 2",
        'B1_PLACEMENT_MECHANISM = "sched-affinity"',
        # The gateway command runs under its declared set.
        'f"taskset -c {b1.format_cpu_list(gateway_cpus)} "',
        # PostgreSQL is pinned by the closed helper, for both profiles.
        "_pin_postgres_tree(",
        # Opening and closing effective-affinity gates.
        'witness.failures(roles_open, gateway_worker_pids=workers_pre, when="open")',
        'witness.failures(roles_close, gateway_worker_pids=workers_post, when="close")',
        "testcontainers_config.ryuk_disabled = True",
        "stack.callback(_restore_ryuk, testcontainers_config, previous_ryuk)",
        "previous_ryuk = testcontainers_config.ryuk_disabled",
        # The host-loopback route overrides, saved and restored in the stack.
        '("connection_mode_override", ConnectionMode.docker_host)',
        '("tc_host_override", B1_SIBLING_HOST)',
        "stack.callback(\n                _restore_attr, testcontainers_config, name,",
        'B1_SIBLING_HOST = "127.0.0.1"',
        'B1_DRIVER_NAME_PREFIX = "dbagent-b1-driver-"',
        'B1_RUN_LABEL_KEY = "dbagent.b1.run"',
        'B1_ROLE_LABEL_KEY = "dbagent.b1.role"',
        "if len(matches) != 1:",
        "network_mode=\"host\"",
    ):
        if clause not in fixture_src:
            add("fixture_clause_missing", repr(clause))
    if "getenv" in fixture_src or "os.environ.get" in fixture_src:
        add("fixture_reads_the_environment")
    for escape in ("pytest.mark.skip", "pytest.mark.xfail", "continue-on-error", "|| true"):
        if escape in fixture_src:
            add("rejected_escape_in_fixture", escape)

    # The PostgreSQL pin is unconditional: exactly one call site, and not
    # inside a profile branch. A helper that runs for only one profile would
    # leave the other's PostgreSQL wherever Docker put it.
    fixture_tree = ast.parse(fixture_src)
    live = next(
        (n for n in fixture_tree.body
         if isinstance(n, ast.FunctionDef) and n.name == "_run_b1_reference"), None
    )
    if live is None:
        add("fixture_clause_missing", "'_run_b1_reference'")
    else:
        pins = [
            n for n in ast.walk(live)
            if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "_pin_postgres_tree"
        ]
        if len(pins) != 1:
            add("postgres_pin_conditional", f"{len(pins)} call sites")
        for node in ast.walk(live):
            if isinstance(node, ast.If) and any(
                isinstance(c, ast.Call) and getattr(c.func, "id", None) == "_pin_postgres_tree"
                for c in ast.walk(node)
            ):
                add("postgres_pin_conditional", ast.unparse(node.test))

    # No Docker bandwidth or cpuset control anywhere in either carrier. This is
    # a static check by design: cgroup state is a reported diagnostic, never an
    # oracle for what the launcher applied.
    for label, source in (("launcher", launcher), ("fixture", fixture_src)):
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            for control in B1_BANDWIDTH_CONTROLS:
                if control in stripped:
                    add(f"bandwidth_control_in_{label}", f"{control} :: {stripped[:80]}")

    fails.extend(_b1_affinity_failures(launcher))
    fails.extend(_b1_mountpoint_failures(launcher))
    fails.extend(_b1_cleanup_failures(launcher))
    fails.extend(_b1_retired_arm_failures(launcher))
    return fails


def _source_assigns(src: str) -> "dict[str, ast.AST]":
    """Module-level ``NAME = <expr>`` assignments, by name."""
    out: "dict[str, ast.AST]" = {}
    for node in ast.parse(src).body:
        targets = (
            node.targets if isinstance(node, ast.Assign)
            else [node.target] if isinstance(node, ast.AnnAssign) and node.value is not None
            else []
        )
        for target in targets:
            if isinstance(target, ast.Name):
                out[target.id] = node.value
    return out


# ---------------------------------------------------------------------------
# GC-3 — the manual topology-discovery route (FP-GC3-2 / 4 / 6).
#
# Every literal below is declared here, independently of the files it pins.
# The clauses are deliberately split between "the probe exists and is
# dispatch-only" and "the ordinary merge gate is untouched": this slice adds a
# measurement instrument, and the one thing it must never do is become one.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# GC-3 FP-GC3-4, review round 1 C1: the launcher's OWN pair string must be a
# legal input to `contract-selected`.
#
# The unit tests around the selected contract feed hand-written canonical CPU
# lists ("0-1", "2-3"), so every one of them stays green whatever
# `b1_complete_sibling_pairs` actually prints. This test closes that gap the
# only way it can be closed: it runs the launcher's own helper functions, under
# bash, against a fabricated sysfs tree, and pipes what they emit -- unmodified,
# through the same `--pairs` array the gating branch builds -- into the real
# CLI. It is named for the composition, and it fails when the composition is
# broken, which is exactly what a space-separated "lo hi" pair did.
# ---------------------------------------------------------------------------

_B1_ROUTE_MUTATIONS: list[tuple[str, str, str]] = [
    # (id, kind, expected reason) -- the mutator is resolved below by id.
    # bench-on-demand FP-BOD-1: the wrapper cases become ONE case with the
    # opposite polarity -- a re-added `integration-test.sh` step in any job is
    # the drift now, because no CI job may delegate a B1 run at all.
    ("b1_wrapper_returned_to_ci", "workflow", "wrapper_inventory_drift"),
    ("product_target_sent_to_ci", "workflow", "product_target_in_ci"),
    ("launcher_drops_the_image_build", "launcher", "route_clause_missing"),
    ("driver_loses_the_host_pid_namespace", "launcher", "route_clause_missing"),
    ("driver_loses_the_host_network", "launcher", "route_clause_missing"),
    ("source_mount_becomes_writable", "launcher", "route_clause_missing"),
    ("docker_socket_unmounted", "launcher", "route_clause_missing"),
    ("profile_renamed_in_the_contract", "launcher", "route_clause_missing"),
    ("run_id_shortened", "launcher", "route_clause_missing"),
    ("driver_name_prefix_changed", "launcher", "route_clause_missing"),
    ("run_label_dropped", "launcher", "driver_clause_missing"),
    ("role_label_dropped", "launcher", "route_clause_missing"),
    ("cleanup_filter_widened", "launcher", "route_clause_missing"),
    ("cleanup_trap_removed", "launcher", "route_clause_missing"),
    ("product_cpu_floor_lowered", "launcher", "affinity_host_floor_drift"),
    # --- GC-1 rev 0.5: the affinity allocation itself ---
    ("driver_loses_its_taskset", "launcher", "route_clause_missing"),
    ("gateway_loses_its_taskset", "fixture", "fixture_clause_missing"),
    ("launcher_stops_reading_its_own_affinity", "launcher", "route_clause_missing"),
    ("schema_reverted_to_1", "launcher", "route_clause_missing"),
    ("mechanism_reverted_to_quota", "launcher", "route_clause_missing"),
    ("ci_scale_target_returned", "launcher", "retired_ci_scale_target_survives"),
    ("product_affinity_cardinality_changed", "launcher", "affinity_cardinality_drift"),
    ("gateway_postgres_affinity_overlap", "launcher", "affinity_overlap"),
    ("gateway_driver_affinity_overlap", "launcher", "affinity_overlap"),
    ("postgres_driver_affinity_overlap", "launcher", "affinity_overlap"),
    ("affinity_outside_host_set", "launcher", "affinity_index_drift"),
    # --- the image's VOLUME mountpoints, under the read-only source bind ---
    ("volume_mountpoint_mkdir_removed", "launcher", "volume_mountpoint_mkdir_inventory_drift"),
    ("volume_mountpoint_set_drifts_from_the_image", "launcher", "volume_mountpoint_set_drift"),
    ("volume_mountpoint_mkdir_moved_out_of_prepare", "launcher",
     "volume_mountpoint_mkdir_outside_prepare"),
    ("launcher_stops_preparing_before_the_driver", "launcher",
     "volume_mountpoint_created_too_late"),
    ("cfs_quota_reintroduced_in_launcher", "launcher", "bandwidth_control_in_launcher"),
    ("cfs_quota_reintroduced_in_fixture", "fixture", "bandwidth_control_in_fixture"),
    ("cpuset_reintroduced_in_fixture", "fixture", "bandwidth_control_in_fixture"),
    ("postgres_helper_skipped_for_ci_scale", "fixture", "postgres_pin_conditional"),
    ("postgres_helper_skipped_for_product", "fixture", "postgres_pin_conditional"),
    ("postgres_helper_removed", "fixture", "fixture_clause_missing"),
    ("opening_affinity_gate_removed", "fixture", "fixture_clause_missing"),
    ("closing_affinity_gate_removed", "fixture", "fixture_clause_missing"),
    # --- selections, environment, coverage, cleanup ---
    ("coverage_selection_widened", "workflow", "coverage_selection_drift"),
    ("product_selection_widened", "launcher", "product_selection_drift"),
    ("env_unset_key_dropped", "launcher", "env_unset_prefix_drift"),
    ("bytecode_cache_left_on_the_source_mount", "launcher", "pycache_prefix_drift"),
    ("coverage_bar_lowered", "workflow", "coverage_bar_drift"),
    ("coverage_aggregate_include_widened", "workflow", "coverage_aggregate_scope_drift"),
    ("coverage_per_file_report_dropped", "workflow", "coverage_report_inventory_drift"),
    ("coverage_data_file_moved_to_the_source_mount", "workflow", "coverage_data_path_drift"),
    ("pytest_cache_moved_to_the_source_mount", "launcher", "pytest_cache_path_drift"),
    # GC-3 (FP-GC3-4): the single driver script became two, so masking is two
    # independent mutations -- one per phase -- and each must go red on its own.
    ("coverage_phase_masks_a_failure", "workflow", "rejected_escape_in_coverage_step"),
    ("product_phase_masks_a_failure", "launcher", "rejected_escape_in_launcher"),
    ("launcher_continues_on_error", "launcher", "rejected_escape_in_launcher"),
    ("marker_registration_removed", "markers", "marker_not_registered"),
    ("pytest_markers_allowlist_removed", "admission", "markers_not_admitted"),
    ("ryuk_scope_removed", "fixture", "fixture_clause_missing"),
    ("ryuk_restore_removed", "fixture", "fixture_clause_missing"),
    ("connection_mode_override_removed", "fixture", "fixture_clause_missing"),
    ("tc_host_override_changed", "fixture", "fixture_clause_missing"),
    ("testcontainers_overrides_not_restored", "fixture", "fixture_clause_missing"),
    ("driver_identity_accepts_many_matches", "fixture", "fixture_clause_missing"),
    ("gateway_loses_host_networking", "fixture", "fixture_clause_missing"),
    ("wrapper_admission_revoked", "admission", "wrapper_not_admitted"),
    # --- the run directory the rootful daemon writes as uid 0 (fix.md D1) ---
    ("cleanup_blames_containers_for_the_run_dir", "launcher",
     "cleanup_run_dir_sets_the_container_flag"),
    ("cleanup_drops_the_root_capable_purge", "launcher", "cleanup_purge_missing"),
    ("cleanup_stops_checking_that_the_run_dir_is_gone", "launcher",
     "cleanup_removal_unchecked"),
    ("purge_stops_deleting", "launcher", "purge_clause_missing"),
    ("purge_loses_its_run_label", "launcher", "purge_clause_missing"),
    ("purge_gains_the_source_mount", "launcher", "purge_mounts_more_than_the_run_dir"),
    ("b1_ignores_the_run_dir_failure", "launcher", "consumer_ignores_the_run_dir_failure"),
    ("probe_arm_target_returned", "launcher", "retired_arm_target_survives"),
    ("cleanup_drops_the_post_purge_census", "launcher", "cleanup_post_purge_census_missing"),
    ("post_purge_census_is_not_fatal", "launcher", "cleanup_post_purge_flag_missing"),
    # --- bench-on-demand FP-BOD-2: each retired route, put back by name ---
    ("latency_basis_target_returned", "launcher", "retired_target_survives"),
    ("topology_carrier_read_returned", "launcher", "retired_route_clause_survives"),
    ("coverage_driver_function_returned", "launcher", "retired_target_survives"),
]


# The second census stanza, as one literal, so the two mutations below remove
# exactly it and nothing that looks like it.
_B1_POST_PURGE_CENSUS = """  ids="$(docker ps -aq --filter "label=${B1_RUN_LABEL_KEY}=${B1_RUN_ID}" 2>/dev/null)"
  if [ -n "$ids" ]; then
    # shellcheck disable=SC2086
    docker rm -f $ids >/dev/null 2>&1
    ids="$(docker ps -aq --filter "label=${B1_RUN_LABEL_KEY}=${B1_RUN_ID}" 2>/dev/null)"
  fi
  if [ -n "$ids" ]; then
    echo "integration-test.sh: run ${B1_RUN_ID} left containers behind: $(echo "$ids" | tr '\\n' ' ')" >&2
    B1_CLEANUP_FAILED=1
  fi
  return 0
}"""


def _apply_b1_route_mutation(case_id: str, wf: dict, launcher: str, markers: str,
                             fixture: str) -> tuple[dict, str, str, str]:
    steps = wf["jobs"]["benchmark"]["steps"]
    functional_steps = wf["jobs"]["functional"]["steps"]
    harness_index = next(
        i for i, step in enumerate(functional_steps)
        if "-m coverage run" in (step.get("run") or "")
    )
    if case_id == "b1_wrapper_returned_to_ci":
        steps.append({"run": "bash scripts/integration-test.sh b1"})
    elif case_id == "product_target_sent_to_ci":
        steps.append({"run": "bash scripts/integration-test.sh b1_product"})
    elif case_id == "launcher_drops_the_image_build":
        launcher = launcher.replace(
            "docker build -t dbagent-review-runner:b1 -f deploy/review-runner/Dockerfile .",
            "true", 1)
    elif case_id == "driver_loses_the_host_pid_namespace":
        launcher = launcher.replace("    --pid host \\\n", "", 1)
    elif case_id == "driver_loses_the_host_network":
        launcher = launcher.replace("    --network host \\\n", "", 1)
    elif case_id == "source_mount_becomes_writable":
        launcher = launcher.replace('-v "$REPO_ROOT":/workspace:ro', '-v "$REPO_ROOT":/workspace:rw', 1)
    elif case_id == "docker_socket_unmounted":
        launcher = launcher.replace('    -v "$B1_SOCKET":/var/run/docker.sock \\\n', "", 1)
    elif case_id == "profile_renamed_in_the_contract":
        launcher = launcher.replace('"profile": "product-exclusive",',
                                    '"profile": "product-exclusive-v2",', 1)
    elif case_id == "run_id_shortened":
        launcher = launcher.replace('if [ "${#B1_RUN_ID}" -ne 32 ]; then',
                                    'if [ "${#B1_RUN_ID}" -ne 8 ]; then', 1)
    elif case_id == "driver_name_prefix_changed":
        launcher = launcher.replace('B1_DRIVER_NAME_PREFIX="dbagent-b1-driver-"',
                                    'B1_DRIVER_NAME_PREFIX="b1-"', 1)
    elif case_id == "run_label_dropped":
        launcher = launcher.replace(
            '    --name "${B1_DRIVER_NAME_PREFIX}${B1_RUN_ID}" \\\n'
            '    --label "${B1_RUN_LABEL_KEY}=${B1_RUN_ID}" \\\n',
            '    --name "${B1_DRIVER_NAME_PREFIX}${B1_RUN_ID}" \\\n', 1)
    elif case_id == "role_label_dropped":
        launcher = launcher.replace('    --label "${B1_ROLE_LABEL_KEY}=driver" \\\n', "", 1)
    elif case_id == "cleanup_filter_widened":
        launcher = launcher.replace('docker ps -aq --filter "label=${B1_RUN_LABEL_KEY}=${B1_RUN_ID}"',
                                    'docker ps -aq --filter "label=${B1_RUN_LABEL_KEY}"')
    elif case_id == "cleanup_trap_removed":
        launcher = launcher.replace("trap 'b1_cleanup' EXIT TERM INT", "true", 1)
    elif case_id == "product_cpu_floor_lowered":
        launcher = launcher.replace('if [ "${#cpus[@]}" -lt 8 ]; then',
                                    'if [ "${#cpus[@]}" -lt 4 ]; then', 1)
    elif case_id == "driver_loses_its_taskset":
        launcher = launcher.replace('taskset -c "$cpuset" bash "$B1_RUN_MOUNT/$script"',
                                    'bash "$B1_RUN_MOUNT/$script"', 1)
    elif case_id == "gateway_loses_its_taskset":
        fixture = fixture.replace('f"taskset -c {b1.format_cpu_list(gateway_cpus)} "\n            ',
                                  "", 1)
    elif case_id == "launcher_stops_reading_its_own_affinity":
        launcher = launcher.replace(
            "affinity=\"$(taskset -pc $$ 2>/dev/null | sed 's/.*: *//')\"",
            'affinity="0-3"', 1)
    elif case_id == "schema_reverted_to_1":
        launcher = launcher.replace('"schema": 2,', '"schema": 1,')
    elif case_id == "mechanism_reverted_to_quota":
        launcher = launcher.replace('"mechanism": "sched-affinity",', '"mechanism": "cfs-quota",')
    elif case_id == "ci_scale_target_returned":
        launcher = launcher + "\nb1() {\n  return 0\n}\n"
    elif case_id == "product_affinity_cardinality_changed":
        launcher = launcher.replace(
            'postgres_cpus="$(b1_canonical_cpu_list "${cpus[4]}" "${cpus[5]}" "${cpus[6]}")"',
            'postgres_cpus="$(b1_canonical_cpu_list "${cpus[4]}" "${cpus[5]}")"', 1)
    elif case_id == "gateway_postgres_affinity_overlap":
        launcher = launcher.replace(
            'postgres_cpus="$(b1_canonical_cpu_list "${cpus[4]}" "${cpus[5]}" "${cpus[6]}")"',
            'postgres_cpus="$(b1_canonical_cpu_list "${cpus[3]}" "${cpus[5]}" "${cpus[6]}")"', 1)
    elif case_id == "gateway_driver_affinity_overlap":
        launcher = launcher.replace('driver_cpus="$(b1_canonical_cpu_list "${cpus[7]}")"',
                                    'driver_cpus="$(b1_canonical_cpu_list "${cpus[0]}")"', 1)
    elif case_id == "postgres_driver_affinity_overlap":
        launcher = launcher.replace('driver_cpus="$(b1_canonical_cpu_list "${cpus[7]}")"',
                                    'driver_cpus="$(b1_canonical_cpu_list "${cpus[6]}")"', 1)
    elif case_id == "affinity_outside_host_set":
        launcher = launcher.replace('driver_cpus="$(b1_canonical_cpu_list "${cpus[7]}")"',
                                    'driver_cpus="$(b1_canonical_cpu_list "${cpus[9]}")"', 1)
    elif case_id in (
        "volume_mountpoint_mkdir_removed",
        "volume_mountpoint_mkdir_moved_out_of_prepare",
    ):
        line = next(
            ln for ln in launcher.splitlines()
            if ln.strip().startswith('mkdir -p "$REPO_ROOT/')
        )
        launcher = launcher.replace(line + "\n", "", 1)
        if case_id == "volume_mountpoint_mkdir_moved_out_of_prepare":
            # Present, correct, and too late: it now runs in the cleanup path.
            launcher = launcher.replace("b1_cleanup() {\n", f"b1_cleanup() {{\n{line}\n", 1)
    elif case_id == "volume_mountpoint_set_drifts_from_the_image":
        # Drop the last VOLUME the image declares, so the launcher prepares a
        # proper subset of the mountpoints Docker will try to create.
        dropped = _b1_image_volume_paths()[-1][len(B1_SOURCE_MOUNT):]
        launcher = launcher.replace(f' "$REPO_ROOT/{dropped}"', "", 1)
    elif case_id == "launcher_stops_preparing_before_the_driver":
        launcher = launcher.replace("  b1_prepare || return 1\n", "", 1)
    elif case_id == "cfs_quota_reintroduced_in_launcher":
        launcher = launcher.replace('    --network host \\\n',
                                    '    --network host \\\n    --cpu-quota 200000 \\\n', 1)
    elif case_id == "cfs_quota_reintroduced_in_fixture":
        fixture = fixture.replace("        gateway.with_kwargs(\n",
                                  "        gateway.with_kwargs(\n            cpu_quota=200000,\n", 1)
    elif case_id == "cpuset_reintroduced_in_fixture":
        fixture = fixture.replace("        gateway.with_kwargs(\n",
                                  '        gateway.with_kwargs(\n            cpuset_cpus="0-1",\n', 1)
    elif case_id == "postgres_helper_skipped_for_ci_scale":
        fixture = fixture.replace(
            "        _pin_postgres_tree(\n",
            "        if declaration.profile == PRODUCT_PROFILE_NAME:\n         _pin_postgres_tree(\n",
            1)
    elif case_id == "postgres_helper_skipped_for_product":
        fixture = fixture.replace(
            "        _pin_postgres_tree(\n",
            "        if declaration.profile == CI_SCALE_PROFILE_NAME:\n         _pin_postgres_tree(\n",
            1)
    elif case_id == "postgres_helper_removed":
        fixture = fixture.replace("_pin_postgres_tree(", "_no_pin(")
    elif case_id == "opening_affinity_gate_removed":
        fixture = fixture.replace(
            'witness.failures(roles_open, gateway_worker_pids=workers_pre, when="open")',
            "[]", 1)
    elif case_id == "closing_affinity_gate_removed":
        fixture = fixture.replace(
            'witness.failures(roles_close, gateway_worker_pids=workers_post, when="close")',
            "[]", 1)
    elif case_id == "coverage_selection_widened":
        functional_steps[harness_index]["run"] = functional_steps[harness_index][
            "run"
        ].replace(B1_COVERAGE_SELECTION, '-m "not b1_product"', 1)
    elif case_id == "product_selection_widened":
        launcher = launcher.replace("-m b1_product -o cache_dir", "-m b1_live -o cache_dir", 1)
    elif case_id == "env_unset_key_dropped":
        launcher = launcher.replace(
            "env -u PYTHON_VERSION -u PYTHON_PIP_VERSION "
            "-u PYTHON_GET_PIP_URL -u PYTHON_GET_PIP_SHA256 python3 -B",
            "env -u PYTHON_VERSION -u PYTHON_PIP_VERSION "
            "-u PYTHON_GET_PIP_URL python3 -B", 1)
    elif case_id == "bytecode_cache_left_on_the_source_mount":
        launcher = launcher.replace(" -X pycache_prefix=/run/dbagent-b1/pycache", "", 1)
    elif case_id == "coverage_bar_lowered":
        functional_steps[harness_index]["run"] = functional_steps[harness_index][
            "run"
        ].replace("--fail-under=81", "--fail-under=1")
    elif case_id == "coverage_aggregate_include_widened":
        functional_steps[harness_index]["run"] = functional_steps[harness_index][
            "run"
        ].replace(f"--include={','.join(B1_COVERED_FILES)}", "", 1)
    elif case_id == "coverage_per_file_report_dropped":
        functional_steps[harness_index]["run"] = "\n".join(
            ln for ln in functional_steps[harness_index]["run"].splitlines()
            if f"--include={B1_COVERED_FILES[2]}" not in ln
        )
    elif case_id == "coverage_data_file_moved_to_the_source_mount":
        functional_steps[harness_index]["run"] = functional_steps[harness_index][
            "run"
        ].replace(B1_COVERAGE_DATA_FILE, '--data-file=.coverage')
    elif case_id == "pytest_cache_moved_to_the_source_mount":
        launcher = launcher.replace("-o cache_dir=/run/dbagent-b1/pytest-cache",
                                    "-o cache_dir=/workspace/.pytest_cache")
    elif case_id == "coverage_phase_masks_a_failure":
        functional_steps[harness_index]["run"] = (
            functional_steps[harness_index]["run"] + " || true"
        )
    elif case_id == "product_phase_masks_a_failure":
        launcher = launcher.replace('  b1_run_driver driver-product.sh "$driver_cpus"',
                                    '  b1_run_driver driver-product.sh "$driver_cpus" || true', 1)
    elif case_id == "launcher_continues_on_error":
        launcher = launcher + "\ncontinue-on-error\n"
    elif case_id == "marker_registration_removed":
        markers = "\n".join(ln for ln in markers.splitlines() if '"b1_product:' not in ln)
    elif case_id in ("pytest_markers_allowlist_removed", "wrapper_admission_revoked"):
        pass  # handled by the caller, which edits the module-level allowlist
    elif case_id == "ryuk_scope_removed":
        fixture = fixture.replace("testcontainers_config.ryuk_disabled = True", "pass")
    elif case_id == "ryuk_restore_removed":
        fixture = fixture.replace(
            "stack.callback(_restore_ryuk, testcontainers_config, previous_ryuk)", "pass")
    elif case_id == "connection_mode_override_removed":
        fixture = fixture.replace(
            '            ("connection_mode_override", ConnectionMode.docker_host),\n', "", 1)
    elif case_id == "tc_host_override_changed":
        fixture = fixture.replace('("tc_host_override", B1_SIBLING_HOST)',
                                  '("tc_host_override", "172.17.0.1")', 1)
    elif case_id == "testcontainers_overrides_not_restored":
        fixture = fixture.replace(
            "            stack.callback(\n                _restore_attr, testcontainers_config, name,",
            "            (\n                _restore_attr, testcontainers_config, name,", 1)
    elif case_id == "driver_identity_accepts_many_matches":
        fixture = fixture.replace("if len(matches) != 1:", "if len(matches) < 1:", 1)
    elif case_id == "cleanup_drops_the_post_purge_census":
        launcher = launcher.replace(_B1_POST_PURGE_CENSUS, "  return 0\n}", 1)
    elif case_id == "latency_basis_target_returned":
        launcher = launcher + "\nb1_latency_basis() {\n  return 0\n}\n"
    elif case_id == "topology_carrier_read_returned":
        launcher = launcher.replace(
            "b1_product() {",
            'b1_product() {\n'
            '  python3 "$B1_PROBE_PLANNER" route --decision '
            '"$REPO_ROOT/tests/benchmark/b1_topology_decision.json"', 1)
    elif case_id == "coverage_driver_function_returned":
        launcher = launcher + "\nb1_write_coverage_driver() {\n  return 0\n}\n"
    elif case_id == "post_purge_census_is_not_fatal":
        launcher = launcher.replace(
            _B1_POST_PURGE_CENSUS,
            _B1_POST_PURGE_CENSUS.replace("    B1_CLEANUP_FAILED=1\n", "", 1), 1)
    elif case_id == "cleanup_blames_containers_for_the_run_dir":
        # The defect fix.md D1 describes: one flag for two unrelated facts.
        launcher = launcher.replace("      B1_RUN_DIR_FAILED=1", "      B1_CLEANUP_FAILED=1", 1)
    elif case_id == "probe_arm_target_returned":
        launcher = launcher + "\nb1_topology_probe_arm() {\n  return 0\n}\n"
    elif case_id == "cleanup_drops_the_root_capable_purge":
        launcher = launcher.replace("      b1_purge_run_dir\n", "", 1)
    elif case_id == "cleanup_stops_checking_that_the_run_dir_is_gone":
        launcher = launcher.replace(
            '    if [ -d "$B1_RUN_DIR" ]; then\n'
            '      echo "integration-test.sh: run ${B1_RUN_ID} could not remove its run '
            'directory ${B1_RUN_DIR}" >&2\n'
            "      B1_RUN_DIR_FAILED=1\n"
            "    fi\n",
            "", 1)
    elif case_id == "purge_stops_deleting":
        launcher = launcher.replace('find "$B1_RUN_MOUNT" -mindepth 1 -delete',
                                    'find "$B1_RUN_MOUNT" -mindepth 1', 1)
    elif case_id == "purge_loses_its_run_label":
        launcher = launcher.replace(
            '    --label "${B1_RUN_LABEL_KEY}=${B1_RUN_ID}" \\\n'
            '    --label "${B1_ROLE_LABEL_KEY}=cleanup" \\\n',
            '    --label "${B1_ROLE_LABEL_KEY}=cleanup" \\\n', 1)
    elif case_id == "purge_gains_the_source_mount":
        launcher = launcher.replace(
            '    --label "${B1_ROLE_LABEL_KEY}=cleanup" \\\n',
            '    --label "${B1_ROLE_LABEL_KEY}=cleanup" \\\n'
            '    -v "$REPO_ROOT":/workspace \\\n', 1)
    elif case_id == "b1_ignores_the_run_dir_failure":
        launcher = launcher.replace(
            'if [ "$B1_CLEANUP_FAILED" -ne 0 ] || [ "$B1_RUN_DIR_FAILED" -ne 0 ]; '
            "then return 1; fi",
            'if [ "$B1_CLEANUP_FAILED" -ne 0 ]; then return 1; fi', 1)
    elif case_id == "arm_does_not_reset_the_run_dir_flag":
        launcher = launcher.replace("  B1_RUN_DIR_FAILED=0\n", "", 1)
    elif case_id == "gateway_loses_host_networking":
        fixture = fixture.replace('network_mode="host"', 'network_mode="bridge"')
    else:
        raise AssertionError(case_id)
    return wf, launcher, markers, fixture


@pytest.mark.parametrize(
    "case_id, kind, expected",
    _B1_ROUTE_MUTATIONS,
    ids=[c[0] for c in _B1_ROUTE_MUTATIONS],
)
def test_b1_resource_route_pin_rejects_known_drift(case_id, kind, expected, monkeypatch):
    """FP-GC1-2/5: each independently mutated clause produces its named failure."""
    wf = _load_wf()
    launcher = _b1_launcher_source()
    markers = B1_GATEWAY_PYPROJECT.read_text(encoding="utf-8")
    fixture_path = REPO_ROOT / "services" / "gateway" / "tests" / "test_b1_ingest_burst.py"
    fixture = fixture_path.read_text(encoding="utf-8")
    assert _b1_route_failures(wf, launcher, markers_toml=markers) == [], "positive control"

    if kind == "admission":
        if case_id == "wrapper_admission_revoked":
            monkeypatch.setitem(
                globals(), "BASH_SCRIPTS", BASH_SCRIPTS - {"scripts/integration-test.sh"}
            )
        else:
            monkeypatch.setitem(
                globals(), "PYTEST_OPTION_ALLOWLIST", PYTEST_OPTION_ALLOWLIST - {"markers"}
            )
        fails = _b1_route_failures(wf, launcher, markers_toml=markers)
        assert any(f.split(" ", 1)[0] == expected for f in fails), f"{case_id}: {fails}"
        return

    wf, launcher, markers, mutated_fixture = _apply_b1_route_mutation(
        case_id, wf, launcher, markers, fixture
    )
    if kind == "fixture":
        assert mutated_fixture != fixture, f"{case_id}: fixture mutation was a no-op"
        tmp = fixture_path.parent / "_b1_route_mutant.py"
        try:
            tmp.write_text(mutated_fixture, encoding="utf-8")
            monkeypatch.setattr(Path, "read_text", _redirecting_read_text(fixture_path, tmp))
            fails = _b1_route_failures(wf, launcher, markers_toml=markers)
        finally:
            monkeypatch.undo()
            tmp.unlink(missing_ok=True)
    else:
        if kind == "launcher":
            assert launcher != _b1_launcher_source(), f"{case_id}: launcher mutation was a no-op"
        if kind == "markers":
            assert markers != B1_GATEWAY_PYPROJECT.read_text(encoding="utf-8")
        fails = _b1_route_failures(wf, launcher, markers_toml=markers)
    assert any(f.split(" ", 1)[0] == expected for f in fails), f"{case_id}: {fails}"


def _redirecting_read_text(target: Path, replacement: Path):
    original = Path.read_text

    def patched(self, *args, **kwargs):
        if self == target:
            return original(replacement, *args, **kwargs)
        return original(self, *args, **kwargs)

    return patched


def test_b1_entry_matches_its_declared_contract():
    """FP-GC1-5 (was FP-IG-10) / FP-BOD-7: whole-object equality for B1.

    The expected object is the PRODUCT contract now: one measured profile, one
    `tier: on-demand` key, two links and a `notes` body that describes a
    benchmark measured on a developer host. Every clause the CI-scale route,
    the topology carrier, the CPU-basis oracle and the kind p99 tape used to
    publish is pinned ABSENT below, so a half-revert that leaves one of them
    in the manifest is red here rather than merely stale.
    """
    data = yaml.safe_load((REPO_ROOT / "tests/benchmark/thresholds.yaml").read_text())
    b1 = next(e for e in data["benchmarks"] if e["id"] == "B1")
    assert b1["id"] == "B1"
    assert b1["description"] == (
        "Ingest webhook under declared CPU affinities: the "
        "four-measured-role-exclusive-core product run, measured on demand"
    )
    assert b1["threshold"] == (
        "product on-demand: served == offered and 0 errors at 1000 req/s offered "
        "for 30s on the product-exclusive placement (gateway 4, PostgreSQL 3, "
        "driver 1), each role's CPU set exclusive of the others; p99 < 150 ms is "
        "printed as met or missed and is not the bar"
    )
    assert b1["owning_milestone"] == "M3"
    # `covered` is earned by the product run's own threshold comparison; the
    # on-demand tier is a key beside it, not a status and not a skip.
    assert b1["status"] == "covered"
    assert b1["tier"] == "on-demand"
    # FP-BOD-7: two links. The hmac micro-benchmark stays in the unit-gateway
    # job -- `tier: on-demand` does not pull it out of CI -- and the product
    # run is the on-demand benchmark itself.
    assert b1["tests"] == [
        "services/gateway/tests/test_hmac_auth.py::test_b1_hmac_normalize_fingerprint_hot_path",
        B1_PRODUCT_LINK,
    ]
    assert B1_NESTED_CORRECTNESS_LINK not in b1["tests"]
    assert "concurrency_model" not in b1
    notes = b1["notes"]
    for clause in (
        # the on-demand disposition and its two triggers
        "tier: on-demand",
        "design/slices/bench-on-demand/design.md",
        "before every `v*` tag",
        "No CI job runs the live node",
        "not deferred, not skipped and not xfailed",
        # the allocation mechanism, unchanged
        "scheduler affinity (sched_setaffinity/taskset), not a CFS bandwidth",
        "exact, pairwise-disjoint set of logical",
        "reported diagnostics only and decide nothing",
        "`unavailable`",
        # the product bar, with the two failure-producing equalities named
        "the first eight CPUs available to the launcher, split 4/3/1",
        "holds four logical CPUs exclusive of the PostgreSQL and driver sets",
        "1000 req/s offered for 30 s = 30000",
        "MAX_IN_FLIGHT=1000",
        "`scripts/integration-test.sh b1_product`",
        "at least eight available logical CPUs",
        "FAILS THE RUN on errors != 0 and on served != offered",
        "served_rate>=SUSTAINED_FLOOR=200",
        "met/missed",
        "RECORDED ONLY",
        "does not refuse a release",
        "four total vCPUs",
        "no larger, self-hosted or paid runner class is available on this account",
        # the e2e disposition, without a latency claim
        "kind",
        "nested",
        "refutes neither",
        "Eleven kind comparisons fail the e2e job",
        "no longer measured, recorded or uploaded at all",
        "changes no kind deployment resource",
        # the sizing ledger, kept as history (FP-BOD-9 / DW9)
        "B1-LATENCY-BASIS-1",
        "ingestGateway.sizingBasis.observations",
        "collection.attempts",
        "design/slices/b1-latency-basis-1/design.md",
        "design/slices/gc-1-reference-topology/design.md",
        "design/frozen-deviations.md",
        # retained vocabulary
        "reference",
        "open-loop",
        "workers=4",
    ):
        assert clause in notes, f"B1 notes missing {clause!r}"
    # The notes must not call the recorded p99 gating, promise to move a link
    # to a later milestone, or republish anything the slice deleted.
    for forbidden in (
        "product tier gates",
        "product comparisons gate",
        "will be gating",
        "will move to",
        # rev 0.4's falsified allocation primitive
        "CPU=2.00/1.00/0.50",
        "cpu.max pair",
        "cgroup v2 CPU quota",
        # the retired first-four/2-1-1 CI-scale claim
        "the first four CPUs available to the launcher, split 2/1/1",
        # bench-on-demand FP-BOD-1/2/8/9: every deleted route, by name
        "CI-scale gates in both CI and local",
        "`scripts/integration-test.sh b1`",
        "`scripts/integration-test.sh b1_latency_basis`",
        "tests/benchmark/b1_topology_decision.json",
        "topology_unratified_sku",
        "topology_cpu_model_unavailable",
        "gc3_decision_missing",
        "gc3_decision_invalid",
        "500 req/s offered for 30 s = 15000",
        "MAX_IN_FLIGHT=500",
        "CI_SCALE_SUSTAINED_FLOOR=450",
        "recorded, non-gating; reason: host-dependent, not in CI",
        "recorded as pytest observation",
        "does not fail the kind job",
        "keeps p99 < 150 ms at full strength",
        "ratified GC-3 placement",
        "visible only in the uploaded e2e diagnostics artifact",
        "e2e-b1-diagnostics",
    ):
        assert forbidden not in notes, f"B1 notes must not say {forbidden!r}"


#: e2e-b1-kind-policy: every committed carrier of the observational-latency
#: policy. `design/` is gitignored and absent in CI, so no clause below reads
#: it: the deviation is pinned as a PATH STRING inside the manifest, never as a
#: file this test opens.
B1_KIND_POLICY_NOTES_CLAUSES: tuple[str, ...] = (
    # the nested path is named, and named as a non-threshold link
    "tests/e2e/test_e2e_load.py::test_b1_ingest_burst_profile",
    "one of the three threshold-bearing links above",
    # the observational latency policy itself
    "the kind\ndue-time p99 is still compared with 150 ms",
    "recorded as pytest observation",
    "does not fail the kind job",
    # every retained failure class
    "Eleven kind comparisons still fail it",
    "platform\nONLINE",
    "baseline served+errors==6000, errors==0, served==6000 and committed==served",
    "sat_served+sat_errors==issued, sat_errors==0, gateway restart delta ==0",
    "Unhealthy event count",
    "sat_committed==sat_served, and the exact admissible audit-action tuple",
    # the accepted cost, stated rather than hidden
    "Accepted cost",
    "no longer fails e2e",
    "keeps p99 < 150 ms at full strength",
    "ratified GC-3 placement",
    "no CI job fails on ingest latency",
    "visible only in the uploaded e2e diagnostics artifact",
    # resources unchanged and undecided
    "kind deployment resource",
    # the routing strings
    "design/slices/e2e-b1-kind-policy/design.md",
    "design/frozen-deviations.md",
)



# ---------------------------------------------------------------------------
# bench-on-demand -- B1 and B11 leave per-push CI (FP-BOD-1, FP-BOD-5,
# FP-BOD-7).
#
# Every literal below is declared here, independently of the files it pins.
# ---------------------------------------------------------------------------

#: The two on-demand benchmarks, and the one file the B1 live node lives in.
BOD_ON_DEMAND_IDS = frozenset({"B1", "B11"})
BOD_BURST_FILE = "services/gateway/tests/test_b1_ingest_burst.py"
BOD_PG_SCALE_FILE = "tests/benchmark/test_pg_scale.py"
BOD_LIVE_NODE_IDS = (
    "test_b1_product_exclusive_reference_profile",
    "test_b1_ci_scale_reference_profile",
    "test_b11_audit_llm_insert_throughput",
)
#: Whole-token launcher targets no `run:` body may carry. `b1_product` is NOT
#: among them: it is a strict extension of `b1` and would make a substring
#: search pass or fail for the wrong reason, so the check is on tokens.
BOD_RETIRED_TARGETS = ("b1", "b1_latency_basis", "b1_topology_probe")
BOD_LAUNCHER_TOKEN = "integration-test.sh"
#: The two node ids CI must still run from the B2/B10 benchmark step.
BOD_REQUIRED_BENCHMARK_NODES = (
    "test_b2_fingerprint_correlation_p99_under_20ms",
    "test_b10_partitioned_list_and_filter_p99",
)
#: FP-BOD-7: both marker exclusions, required together on any command whose
#: positional root IS the burst file.
BOD_MARKER_EXCLUSIONS = ("not b1_live", "not b1_product")
#: FP-BOD-5: the tag gate's wiring, restated here rather than read from the
#: workflow it protects.
BOD_RECORD_JOB = "release-bench-record"
BOD_RECORD_STEP_RUN = "python3 scripts/check_release_bench_record.py"
BOD_IMAGES_NEEDS = ["lint", "release-bench-record"]
BOD_IMAGES_IF = (
    "always() && needs.lint.result == 'success' && "
    "(needs.release-bench-record.result == 'success' || "
    "needs.release-bench-record.result == 'skipped')"
)

#: pytest options that consume the FOLLOWING token, so its value is never
#: mistaken for a positional collection root.
_BOD_VALUE_OPTIONS = frozenset({"-m", "-k", "-o", "-c", "-p", "-W", "--deselect", "--ignore"})


def _bod_pytest_commands(run: str) -> "list[list[str]]":
    """Every pytest invocation in one `run:` body, as token lists.

    `shlex` rather than the module's closed grammar on purpose: this reads a
    body the grammar deliberately refuses (a quoted marker expression carries
    whitespace), and the question here is which files a command COLLECTS, not
    whether the body is admissible -- `_ci_pin_failures` owns that.
    """
    out: "list[list[str]]" = []
    collapsed = _delete_continuations(run or "")
    for chunk in re.split(r"[\n;]|&&", collapsed):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            tokens = shlex.split(chunk)
        except ValueError:
            continue
        if "pytest" not in tokens:
            continue
        out.append(tokens)
    return out


def _bod_pytest_operands(tokens: "list[str]") -> "tuple[list[str], list[str], str]":
    """(positional roots, `--ignore` operands, the joined `-m` expression)."""
    roots: "list[str]" = []
    ignores: "list[str]" = []
    marker = ""
    index = tokens.index("pytest") + 1
    while index < len(tokens):
        token = tokens[index]
        if token in _BOD_VALUE_OPTIONS:
            if index + 1 < len(tokens):
                if token == "-m":
                    marker += " " + tokens[index + 1]
                elif token == "--ignore":
                    ignores.append(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--ignore="):
            ignores.append(token.split("=", 1)[1])
            index += 1
            continue
        if token.startswith("-m") and len(token) > 2 and not token.startswith("--"):
            marker += " " + token[2:]
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        roots.append(token)
        index += 1
    return roots, ignores, marker


def _bod_resolved(base: str, operand: str) -> Path:
    """One collection operand, resolved against its step's working directory."""
    return (REPO_ROOT / base / operand.split("::", 1)[0]).resolve()


def _bod_step_base(job: dict, step: dict) -> str:
    return str(
        step.get("working-directory")
        or (job.get("defaults") or {}).get("run", {}).get("working-directory")
        or job.get("working-directory")
        or ""
    )


def test_ci_does_not_run_b1_or_b11():
    """FP-BOD-1 [function test]: no CI job executes either on-demand benchmark.

    Named for a workflow that still runs the ingest burst or the audit
    throughput test -- INCLUDING by collecting the whole of
    `tests/benchmark/test_pg_scale.py`, which is how B11 would come back
    without any step naming it.

    The launcher targets are matched as WHOLE TOKENS after
    `integration-test.sh`. A substring search for `b1` would fail on the live
    `b1_product` target, which is exactly the one this repository still has and
    still must never run in CI; a substring search for `b1_product` would pass
    a re-added `b1`.
    """
    workflow = _load_wf()
    jobs = workflow.get("jobs") or {}
    offences: "list[str]" = []
    benchmark_nodes: "set[str]" = set()

    for job_name, job in jobs.items():
        for index, step in enumerate(_job_steps(job)):
            run = _step_run(step) or ""
            where = f"{job_name}[{index}]"
            for retired in BOD_RETIRED_TARGETS:
                if re.search(
                    rf"{re.escape(BOD_LAUNCHER_TOKEN)}\s+{re.escape(retired)}(?![\w-])", run
                ):
                    offences.append(f"{where} runs the retired target {retired!r}")
            for node_id in BOD_LIVE_NODE_IDS:
                if node_id in run:
                    offences.append(f"{where} names the live node {node_id!r}")
            for tokens in _bod_pytest_commands(run):
                roots, _ignores, _marker = _bod_pytest_operands(tokens)
                base = _bod_step_base(job, step)
                for root in roots:
                    resolved = _bod_resolved(base, root)
                    if resolved == (REPO_ROOT / BOD_PG_SCALE_FILE).resolve() and (
                        "::" not in root
                    ):
                        offences.append(
                            f"{where} collects the whole of {BOD_PG_SCALE_FILE}"
                        )
                    if "::" in root and root.split("::", 1)[0].endswith(
                        "test_pg_scale.py"
                    ):
                        benchmark_nodes.add(root.split("::", 1)[1])

    assert offences == [], offences
    # ...and the two code-level PG benchmarks CI still owns are still named.
    for node in BOD_REQUIRED_BENCHMARK_NODES:
        assert node in benchmark_nodes, f"the benchmark job no longer runs {node}"


def test_on_demand_tier_is_covered_asserted_and_absent_from_ci():
    """FP-BOD-7 [function test]: covered, asserted, and out of CI -- all three.

    Named for three separate regressions, and it takes all three checks to
    catch them.

    `tier: on-demand` while the linked test has no threshold comparison would
    make the manifest's honesty rule vacuous for the two benchmarks that left
    CI -- so the linked functions go through the same parser
    `test_covered_benchmarks_link_to_threshold_asserting_tests` uses, and
    neither may carry a skip decorator.

    A workflow that merely omits the live node id, and then collects the burst
    file WITHOUT the marker exclusions or without the working-directory
    relative `--ignore`, runs the live node anyway. Node-id absence alone is
    not this test: the resolution below is working-directory aware, because
    the unit-gateway job ignores `tests/test_b1_ingest_burst.py` from inside
    `services/gateway` and the repository-relative string does not name the
    file from there.
    """
    data = _load(REPO_ROOT / "tests/benchmark/thresholds.yaml")
    tiered = {
        entry["id"]: entry for entry in data["benchmarks"] if "tier" in entry
    }
    assert set(tiered) == BOD_ON_DEMAND_IDS, sorted(tiered)
    for entry in tiered.values():
        assert entry["tier"] == "on-demand", entry["id"]
        assert entry["status"] == "covered", entry["id"]
        # The benchmark-named links carry a real threshold comparison, and the
        # linked function is not skipped.
        named = [
            link for link in entry["tests"]
            if _link_names_benchmark(link, entry["id"]) and link.endswith(
                tuple(f"::{n}" for n in (_link_test_name(link),))
            )
        ]
        assert named, entry["id"]
        for link in named:
            assert _link_asserts_threshold(link, REPO_ROOT), link
            path = _resolve_test_file(link, REPO_ROOT)
            assert path is not None and path.is_file(), link
            tree = ast.parse(path.read_text(encoding="utf-8"))
            func = next(
                (
                    node for node in ast.walk(tree)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == _link_test_name(link)
                ),
                None,
            )
            assert func is not None, link
            assert not any(_is_skip_decorator(d) for d in func.decorator_list), link

    workflow = _load_wf()
    burst = (REPO_ROOT / BOD_BURST_FILE).resolve()
    offences: "list[str]" = []
    for job_name, job in (workflow.get("jobs") or {}).items():
        for index, step in enumerate(_job_steps(job)):
            run = _step_run(step) or ""
            where = f"{job_name}[{index}]"
            for node_id in BOD_LIVE_NODE_IDS:
                if node_id in run:
                    offences.append(f"{where} names {node_id!r}")
            base = _bod_step_base(job, step)
            for tokens in _bod_pytest_commands(run):
                roots, ignores, marker = _bod_pytest_operands(tokens)
                resolved_ignores = {_bod_resolved(base, i) for i in ignores}
                for root in roots:
                    target = _bod_resolved(base, root)
                    if target == burst:
                        # The harness command: held to the marker pair, never
                        # to an `--ignore` of its own operand.
                        for exclusion in BOD_MARKER_EXCLUSIONS:
                            if exclusion not in marker:
                                offences.append(
                                    f"{where} collects the burst file without "
                                    f"{exclusion!r} (marker={marker.strip()!r})"
                                )
                        continue
                    if not target.is_dir():
                        continue
                    if burst.is_relative_to(target) and burst not in resolved_ignores:
                        offences.append(
                            f"{where} collects {root!r} without an --ignore that "
                            f"resolves to {BOD_BURST_FILE} (base={base!r}, "
                            f"ignores={sorted(str(i) for i in resolved_ignores)})"
                        )
    assert offences == [], offences


#: Review S1: the shapes a pinned body must refuse. Each is a real way to run
#: something the operand grammar would never have admitted in a parsed step.
BOD_PINNED_BODY_ESCAPES = (
    "bash -c 'echo pwned'",
    "sh -c 'echo pwned'",
    "curl https://example.invalid/x",
    "python3 -c 'import os'",
    "services/worker/.venv/bin/python -c 'import os'",
    "sudo chmod 777 /",
    "source deploy/versions.env",
    "export PYTHONPATH=/tmp/hook",
    "python3 -m http.server",
    "services/worker/.venv/bin/python -m pip install x",
    "git push origin main",
    "env -u X curl http://x",
    "python3 evil.sh",
    "bash scripts/integration-test.sh b1",
    "services/worker/.venv/bin/python -m pytest a -p rca_bench",
    "services/worker/.venv/bin/python -m pytest a --deselect b",
    "npm install evil",
    "tar -xzf /tmp/x.tgz",
)


def test_pinned_run_bodies_are_held_to_the_operand_grammar():
    """The (AG)(5) exception is compensated, not a hole (review S1).

    Two `run:` bodies skip `_shell_words` because the closed grammar refuses a
    quoted word containing whitespace and every pytest marker expression is
    one. Byte equality alone would only catch a workflow-side edit: someone
    who edited `EXPECTED_FUNCTIONAL_PYTEST_RUN` to match would face no operand
    check at all. `_pinned_body_escape_failures` is that check, and this test
    is what says it still is one.

    Named for the failure it has to catch: a pinned body that runs something
    the parser would never have admitted -- a general interpreter (`-c`), an
    un-admitted command word, a second module, a plugin injection, or a
    delegation to the tracked launcher.
    """
    # The two shipped bodies are admissible, and are the only exceptions.
    assert PINNED_EXECUTABLE_RUNS == {
        EXPECTED_FUNCTIONAL_PYTEST_RUN,
        EXPECTED_RELEASE_RECORD_CHECK_RUN,
    }
    for body in PINNED_EXECUTABLE_RUNS:
        assert _pinned_body_escape_failures(body) == [], body[:80]
    assert _pinned_body_escape_failures(EXPECTED_RELEASE_RECORD_FETCH_RUN) == []

    # ...and every escape is refused, appended to a real pinned body so the
    # check is on the shape rather than on a synthetic one-liner.
    for escape in BOD_PINNED_BODY_ESCAPES:
        mutated = EXPECTED_FUNCTIONAL_PYTEST_RUN + "\n" + escape
        assert _pinned_body_escape_failures(mutated) != [], escape

    # The head allowlist is narrower than the parsed grammar's on purpose: a
    # measured step never needs a setup command word.
    assert PINNED_BODY_COMMAND_WORDS < COMMAND_OPERANDS | {"python3", "git"}
    for setup_word in ("curl", "tar", "sudo", "source", "export", "npm", "helm", "chmod"):
        assert setup_word not in PINNED_BODY_COMMAND_WORDS, setup_word


def test_release_record_gates_image_push():
    """FP-BOD-5 [CI pin]: a red record job cannot publish images.

    Named for a tag that publishes images while the record job failed. An
    `if: always()` with no result check would let exactly that happen, so the
    success-or-skipped clause is required by equality -- `always()` alone is
    what keeps `images` running on a pull request, where the record job is
    skipped, and it is also what would let a FAILED record job through if the
    two result clauses were dropped.
    """
    workflow = _load_wf()
    jobs = workflow.get("jobs") or {}
    record = jobs.get(BOD_RECORD_JOB)
    assert record is not None, f"the {BOD_RECORD_JOB} job is missing"
    assert record.get("if") == "startsWith(github.ref, 'refs/tags/v')", record.get("if")
    assert record.get("runs-on") == "ubuntu-latest", record.get("runs-on")
    steps = _job_steps(record)
    checkout = steps[0]
    assert checkout.get("uses", "").startswith("actions/checkout"), checkout
    assert (checkout.get("with") or {}).get("fetch-depth") == 0, checkout
    test_steps = [
        (_step_run(step) or "").strip() for step in steps
        if "check_release_bench_record" in (_step_run(step) or "")
    ]
    assert test_steps == [BOD_RECORD_STEP_RUN], test_steps
    for step in steps:
        assert "continue-on-error" not in step, step
    # It runs neither benchmark, and delegates to no launcher target.
    for step in steps:
        run = _step_run(step) or ""
        for node_id in BOD_LIVE_NODE_IDS:
            assert node_id not in run, run
        assert BOD_LAUNCHER_TOKEN not in run, run

    images = jobs["images"]
    assert images.get("needs") == BOD_IMAGES_NEEDS, images.get("needs")
    assert _normalize_ws(images.get("if", "")) == _normalize_ws(BOD_IMAGES_IF)
