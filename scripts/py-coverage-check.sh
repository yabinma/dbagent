#!/usr/bin/env bash
# Per-module Python coverage gate (design.md Section 14.1: "> 80% line
# coverage at every level: whole repo, per service/binary, and per
# package/module. A single package below 80% fails the gate").
#
# Usage: scripts/py-coverage-check.sh <threshold> <module> [<module> ...]
# Expects a .coverage data file already written by pytest-cov in CWD.
# Fails if overall coverage is not *strictly above* threshold, or if any
# measured source file under a covered module is at or below threshold.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <threshold> <module> [<module> ...]" >&2
  exit 2
fi

THRESHOLD="$1"
shift
MODULES=("$@")

# Prefer the active venv interpreter (CI runs this after `python -m pytest --cov`
# in the same job's venv); fall back to python3 only when none is active.
if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python" ]]; then
  PY="${VIRTUAL_ENV}/bin/python"
elif command -v python >/dev/null 2>&1 && python -c "import coverage" 2>/dev/null; then
  PY=python
elif command -v python3 >/dev/null 2>&1 && python3 -c "import coverage" 2>/dev/null; then
  PY=python3
else
  # Last resort: same directory's .venv (common when working-directory is a package).
  if [[ -x .venv/bin/python ]]; then
    PY=.venv/bin/python
  else
    echo "FAILED: no Python with the coverage package on PATH" >&2
    exit 2
  fi
fi

"$PY" - "$THRESHOLD" "${MODULES[@]}" << 'PYEOF'
import sys
from collections import defaultdict
from pathlib import Path

try:
    from coverage import Coverage
    from coverage.exceptions import CoverageException
except ImportError as exc:  # pragma: no cover
    print(f"FAILED: coverage package required: {exc}", file=sys.stderr)
    sys.exit(2)

threshold = float(sys.argv[1])
modules = sys.argv[2:]

cov = Coverage()
try:
    cov.load()
except CoverageException as exc:
    print(f"FAILED: no coverage data in cwd ({Path.cwd()}): {exc}", file=sys.stderr)
    sys.exit(1)

# file -> (n_statements, n_missing)
file_stats: dict[str, tuple[int, int]] = {}
total_stmts = 0
total_missing = 0

measured = cov.get_data().measured_files()
for filename in sorted(measured):
    try:
        analysis = cov._analyze(filename)
    except Exception:
        continue
    statements = set(analysis.statements)
    missing = set(analysis.missing)
    n_stmt = len(statements)
    n_miss = len(missing & statements)
    if n_stmt == 0:
        continue
    # Restrict to requested package roots (path segment or module prefix).
    path = filename.replace("\\", "/")
    if not any(
        f"/{mod.replace('.', '/')}/" in f"/{path}/"
        or path.endswith(f"/{mod.replace('.', '/')}.py")
        or f"/{mod}/" in f"/{path}/"
        or path.rstrip("/").endswith(f"/{mod}")
        for mod in modules
    ):
        # Also accept files whose path contains the module as a directory
        # component when modules are simple names like "rca_common".
        if not any(f"/{m}/" in f"/{path}/" or f"/{m}.py" in f"/{path}" for m in modules):
            continue
    file_stats[path] = (n_stmt, n_miss)
    total_stmts += n_stmt
    total_missing += n_miss

if not file_stats:
    print(
        f"FAILED: no covered files matched modules {modules} under {Path.cwd()}",
        file=sys.stderr,
    )
    sys.exit(1)

failed: list[str] = []
print(f"==> per-file coverage (must be strictly > {threshold}%)")
for path in sorted(file_stats):
    n_stmt, n_miss = file_stats[path]
    covered = n_stmt - n_miss
    pct = (covered / n_stmt * 100.0) if n_stmt else 100.0
    # Strict inequality: design requires *above* 80%, not equal.
    status = "OK" if pct > threshold else "FAIL"
    if pct <= threshold:
        failed.append(path)
    print(f"{status:4s} {pct:6.1f}%  {covered:4d}/{n_stmt:<4d}  {path}")

overall_covered = total_stmts - total_missing
overall_pct = (overall_covered / total_stmts * 100.0) if total_stmts else 100.0
print()
print(f"TOTAL: {overall_covered}/{total_stmts} = {overall_pct:.2f}%")

if failed:
    print()
    print(f"FAILED: {len(failed)} file(s) at or below {threshold}%:")
    for p in failed:
        print(f"  - {p}")
    sys.exit(1)

if overall_pct <= threshold:
    print(
        f"FAILED: aggregate coverage {overall_pct:.2f}% is not strictly above {threshold}%"
    )
    sys.exit(1)

print(f"PASS: every file and the aggregate are strictly above {threshold}%")
PYEOF
