#!/usr/bin/env bash
# Copies schemas/tools/presto/*.json (source of truth, Appendix B) into
# probe/internal/toolpack/schemas/ so they can be go:embed-ed -- `embed`
# directives cannot reach outside their own package directory tree, so
# this mirrors the M1 pattern (schemas/ is the single source of truth;
# per-language artifacts are generated from it) for Go, which needs no
# real code generation here (Go parses JSON Schema into map[string]any at
# runtime), just a copy into an embeddable location.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/schemas/tools/presto"
DST="$ROOT/probe/internal/toolpack/schemas"

mkdir -p "$DST"
rm -f "$DST"/*.json
cp "$SRC"/*.json "$DST"/

echo "==> copied $(ls "$SRC"/*.json | wc -l) toolpack schema file(s) to $DST"
