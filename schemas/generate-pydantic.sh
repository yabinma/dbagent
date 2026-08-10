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
DATAMODEL_CODEGEN_VERSION="0.68.1"

mkdir -p "$OUT_DIR"
touch "$OUT_DIR/__init__.py"

# TOOL_VENV is a dev-sandbox convenience default, not a requirement: a fresh
# checkout (including any CI runner, which has no /opt/gospace) will not have
# it. Bootstrap a private, ephemeral venv on demand instead of requiring every
# caller to pre-install this tool -- deploy/docker/build.sh's images job has
# no other reason to carry a Python toolchain step for this one script.
CODEGEN_BIN="$TOOL_VENV/bin/datamodel-codegen"
if [[ ! -x "$CODEGEN_BIN" ]]; then
  BOOTSTRAP_VENV="${TMPDIR:-/tmp}/dbagent-datamodel-codegen-venv"
  if [[ ! -x "$BOOTSTRAP_VENV/bin/datamodel-codegen" ]]; then
    echo "==> bootstrapping datamodel-code-generator==$DATAMODEL_CODEGEN_VERSION (TOOL_VENV not found at $TOOL_VENV)"
    python3 -m venv "$BOOTSTRAP_VENV"
    "$BOOTSTRAP_VENV/bin/pip" install --quiet --upgrade pip
    "$BOOTSTRAP_VENV/bin/pip" install --quiet "datamodel-code-generator==$DATAMODEL_CODEGEN_VERSION"
  fi
  CODEGEN_BIN="$BOOTSTRAP_VENV/bin/datamodel-codegen"
fi

declare -A MODELS=(
  [alert_event.schema.json]=alert_event.py
  [rca_report.schema.json]=rca_report.py
  [plan.schema.json]=plan.py
  [tool_result_envelope.schema.json]=tool_result_envelope.py
)

for src in "${!MODELS[@]}"; do
  out="${MODELS[$src]}"
  echo "==> $src -> schemas/generated/$out"
  "$CODEGEN_BIN" \
    --input "$ROOT/schemas/$src" \
    --input-file-type jsonschema \
    --output "$OUT_DIR/$out" \
    --target-python-version 3.11 \
    --use-schema-description \
    --enum-field-as-literal all \
    --disable-timestamp
done

echo "==> done"
