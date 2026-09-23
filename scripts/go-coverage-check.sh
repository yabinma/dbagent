#!/usr/bin/env bash
# Per-package Go coverage gate (design.md Section 14.1: "> 80% line
# coverage at every level: whole repo, per service/binary, and per
# package/module. A single package below 80% fails the gate ...
# Enforced via ... go test -coverprofile + per-package threshold check").
#
# Two narrow, documented exclusions (see impl-progress.md's M2 session
# section for the rationale -- both mirror how M1 already excluded
# Python's `if __name__ == "__main__":` guards from its coverage bar):
#   1. Generated code (gen/go/...) -- never hand-written, not meaningfully
#      "tested" in the traditional sense.
#   2. The `main` function specifically (not the whole package) inside
#      every `cmd/*/main.go` -- pure env-var/signal/os.Exit orchestration
#      that calls into already independently-and-thoroughly-tested
#      helpers (every one of those helpers IS covered and IS included).
#
# Usage: scripts/go-coverage-check.sh [threshold] [existing-profile]
#
#   With an existing profile (ci-runtime-1 FP-CIR1-5, the CI route): the
#   profile is the one written by the job's single preceding
#   `go test ./... -race -coverprofile=... -covermode=atomic -timeout 300s -p 1`,
#   and this script runs NO test at all. It fails closed on a missing,
#   unreadable, empty, malformed, non-atomic or statement-free profile --
#   none of those is ever read as 100% covered.
#
#   Without one (the local route): it creates a temporary profile, runs the
#   whole suite once to fill it, and removes it on exit.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ "$#" -gt 2 ]; then
  echo "usage: scripts/go-coverage-check.sh [threshold] [existing-profile]" >&2
  exit 2
fi

# Design §14.1 requires *strictly above* 80%. Accept a threshold argument for
# the floor that must be exceeded (default 80 → fail at 80.0%, pass at 80.01%).
THRESHOLD="${1:-80}"

if [ "$#" -eq 2 ]; then
  PROFILE="$2"
  echo "==> reading existing profile ${PROFILE} (no go test run)"
  if [ ! -f "$PROFILE" ]; then
    echo "FAILED: coverage profile ${PROFILE:-<empty path>} does not exist" >&2
    exit 1
  fi
  if [ ! -r "$PROFILE" ]; then
    echo "FAILED: coverage profile $PROFILE is not readable" >&2
    exit 1
  fi
  if [ ! -s "$PROFILE" ]; then
    echo "FAILED: coverage profile $PROFILE is empty" >&2
    exit 1
  fi
else
  PROFILE="$(mktemp)"
  trap 'rm -f "$PROFILE"' EXIT

  echo "==> go test ./... -coverprofile=$PROFILE"
  # -p 1: without serializing package execution this recreates the
  # real-Postgres-testcontainer contention between registry and
  # tests/functional/m2_probe_link that -p 1 was added to fix -- see the
  # unit-go step's comment in .github/workflows/ci.yml. (CI does not take this
  # path: it passes the profile its own single -race pass wrote.)
  go test ./... -coverprofile="$PROFILE" -covermode=atomic -timeout 300s -p 1
fi

echo
echo "==> per-package coverage (excluding gen/go/... and cmd/*/main.go's main() function; must be strictly > ${THRESHOLD}%)"

python3 - "$PROFILE" "$THRESHOLD" "$ROOT" << 'PYEOF'
import re
import sys
import subprocess
from collections import defaultdict

profile_path, threshold, repo_root = sys.argv[1], float(sys.argv[2]), sys.argv[3]
MODULE_PREFIX = "github.com/yabinma/dbagent/"
RECORD_RE = re.compile(r'^(\S+):(\d+)\.\d+,(\d+)\.\d+ (\d+) (\d+)$')

def to_fs_path(module_path: str) -> str:
    if module_path.startswith(MODULE_PREFIX):
        return repo_root + "/" + module_path[len(MODULE_PREFIX):]
    return module_path

def refuse(msg: str) -> None:
    # Fail closed: a profile this script cannot read in full is never a pass.
    print(f"FAILED: coverage profile {profile_path}: {msg}")
    sys.exit(1)

with open(profile_path) as f:
    raw = f.read().splitlines()

if not raw:
    refuse("empty")
if raw[0].strip() != "mode: atomic":
    refuse(f"first line is {raw[0][:60]!r}, not 'mode: atomic'")
lines = raw[1:]  # records after the "mode: ..." header
for n, line in enumerate(lines, start=2):
    if not line.strip():
        continue
    if not RECORD_RE.match(line):
        refuse(f"malformed record at line {n}: {line[:80]!r}")

# package -> [total_statements, covered_statements]
pkg_stats = defaultdict(lambda: [0, 0])
overall = [0, 0]

# Find the line range of func main() in every cmd/*/main.go, to exclude
# just that function (not the whole file/package).
main_func_ranges = {}  # file -> (start_line, end_line) exclusive-ish
for line in lines:
    m = RECORD_RE.match(line)
    if not m:
        continue
    filename = m.group(1)
    if re.search(r'/cmd/[^/]+/main\.go$', filename) and filename not in main_func_ranges:
        # Locate "func main()" in the source to bound the exclusion.
        with open(to_fs_path(filename)) as sf:
            src_lines = sf.readlines()
        start = None
        depth = 0
        end = None
        for i, sl in enumerate(src_lines, start=1):
            if start is None and re.match(r'^func main\(\)', sl):
                start = i
            if start is not None:
                depth += sl.count('{') - sl.count('}')
                if depth == 0 and '{' in ''.join(src_lines[start-1:i]):
                    end = i
                    break
        if start and end:
            main_func_ranges[filename] = (start, end)

def in_excluded_range(filename, start_line):
    if filename in main_func_ranges:
        lo, hi = main_func_ranges[filename]
        if lo <= start_line <= hi:
            return True
    return False

for line in lines:
    m = RECORD_RE.match(line)
    if not m:
        continue
    filename, start_line, _end_line, numstmt, count = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))

    if '/gen/go/' in filename:
        continue  # generated code, excluded entirely
    if in_excluded_range(filename, start_line):
        continue  # main() body, excluded

    # package = directory portion of the file's module-relative path
    pkg = filename.rsplit('/', 1)[0]
    pkg_stats[pkg][0] += numstmt
    overall[0] += numstmt
    if count > 0:
        pkg_stats[pkg][1] += numstmt
        overall[1] += numstmt

failed = []
for pkg in sorted(pkg_stats):
    total, covered = pkg_stats[pkg]
    pct = (covered / total * 100) if total else 100.0
    # Strict inequality: design requires *above* 80%, not equal.
    status = "OK" if pct > threshold else "FAIL"
    if pct <= threshold:
        failed.append(pkg)
    print(f"{status:4s} {pct:6.1f}%  {covered:4d}/{total:<4d}  {pkg}")

if overall[0] == 0:
    # No statement survived the exclusions: nothing was measured, so there is
    # nothing to call covered. Never the 100% an empty denominator would read.
    refuse("no statements left after excluding generated code and main()")

overall_pct = overall[1] / overall[0] * 100
print()
print(f"TOTAL (excluding generated code + main()): {overall[1]}/{overall[0]} = {overall_pct:.1f}%")

if failed:
    print()
    print(f"FAILED: {len(failed)} package(s) at or below {threshold}%:")
    for p in failed:
        print(f"  - {p}")
    sys.exit(1)

if overall_pct <= threshold:
    print(f"FAILED: repo-wide coverage {overall_pct:.1f}% is not strictly above {threshold}%")
    sys.exit(1)

print(f"PASS: every package and the repo total are strictly above {threshold}%")
PYEOF
