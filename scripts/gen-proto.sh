#!/usr/bin/env bash
# Regenerates Go + Python stubs from proto/rcaprobe/v1/probe.proto.
# proto/ is the single source of truth (Section 11 of design.md); this
# script is the codegen entry point referenced by M1's acceptance bar.
#
# Output (gen/go, gen/python) is gitignored, never committed -- run this
# before your first local build/test, and CI reruns it fresh in every job
# that needs it (see .github/workflows/ci.yml).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BUF_BIN="${BUF_BIN:-buf}"
PY_VENV="${PY_VENV:-$HOME/.cache/dbagent-protoc-venv}"

echo "==> buf lint"
"$BUF_BIN" lint proto

echo "==> buf generate (Go stubs -> gen/go)"
mkdir -p gen/go
"$BUF_BIN" generate proto

echo "==> python stubs -> gen/python (grpc_tools.protoc)"
if [ ! -d "$PY_VENV" ]; then
  python3 -m venv "$PY_VENV"
  "$PY_VENV/bin/pip" install --quiet --upgrade pip grpcio-tools mypy-protobuf
fi
mkdir -p gen/python/rcaprobe/v1
export PATH="$PY_VENV/bin:$PATH"
"$PY_VENV/bin/python" -m grpc_tools.protoc \
  -I proto \
  --python_out=gen/python \
  --grpc_python_out=gen/python \
  --mypy_out=gen/python \
  proto/rcaprobe/v1/probe.proto

# grpc_tools generates absolute imports (e.g. "from rcaprobe.v1 import probe_pb2")
# which requires gen/python on PYTHONPATH; add package markers.
find gen/python -type d -exec touch {}/__init__.py \;

echo "==> done"
