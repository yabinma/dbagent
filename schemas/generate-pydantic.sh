#!/usr/bin/env bash
# Generates pydantic models from the JSON Schema source of truth into
# libs/py/rca_common/rca_common/schemas/generated (design.md Section 11).
#
# Output is gitignored, never committed -- run this before your first
# local build/test if you need these models; no CI job depends on it yet
# (nothing currently imports rca_common.schemas.generated -- see the
# "Generated-code policy" note at the top of .github/workflows/ci.yml).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT/libs/py/rca_common/rca_common/schemas/generated"
TOOL_VENV="${TOOL_VENV:-/opt/gospace/venv-tools}"

mkdir -p "$OUT_DIR"
touch "$OUT_DIR/__init__.py"

declare -A MODELS=(
  [alert_event.schema.json]=alert_event.py
  [rca_report.schema.json]=rca_report.py
  [plan.schema.json]=plan.py
  [tool_result_envelope.schema.json]=tool_result_envelope.py
)

for src in "${!MODELS[@]}"; do
  out="${MODELS[$src]}"
  echo "==> $src -> schemas/generated/$out"
  "$TOOL_VENV/bin/datamodel-codegen" \
    --input "$ROOT/schemas/$src" \
    --input-file-type jsonschema \
    --output "$OUT_DIR/$out" \
    --target-python-version 3.11 \
    --use-schema-description \
    --enum-field-as-literal all \
    --disable-timestamp
done

echo "==> done"
