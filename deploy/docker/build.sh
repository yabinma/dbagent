#!/usr/bin/env bash
# Single supported image build path (design.md FP-M6-2):
#   1. regenerate generated trees
#   2. buildx all six product images
# Tags: <registry>/<component>:<appVersion> and :sha-<short>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck disable=SC1091
source "${ROOT}/deploy/versions.env"

REGISTRY="${REGISTRY:-ghcr.io/yabinma/rca-agent}"
APP_VERSION="${APP_VERSION:-0.1.0}"
SHORT_SHA="${SHORT_SHA:-$(git rev-parse --short HEAD 2>/dev/null || echo dev)}"
PUSH="${PUSH:-0}"
PLATFORM="${PLATFORM:-linux/amd64}"

die() { echo "build.sh: ERROR: $*" >&2; exit 1; }

echo "==> codegen"
bash scripts/gen-proto.sh
bash schemas/generate-pydantic.sh
node schemas/generate-ts.js

# Fail fast if generated trees are still missing (they are gitignored).
[[ -d gen/go/rcaprobe/v1 ]] || die "gen/go missing after codegen"
[[ -d libs/py/rca_common/rca_common/schemas/generated ]] || die "pydantic generated schemas missing after codegen"
[[ -d web/src/types/generated ]] || die "TS generated types missing after codegen"

build_one() {
  local component="$1"
  local dockerfile="$2"
  local tag_ver="${REGISTRY}/${component}:${APP_VERSION}"
  local tag_sha="${REGISTRY}/${component}:sha-${SHORT_SHA}"
  echo "==> build ${component}"
  docker buildx build \
    --platform "${PLATFORM}" \
    --file "${dockerfile}" \
    --build-arg "PYTHON_IMAGE=${PYTHON_IMAGE}" \
    --build-arg "GO_IMAGE=${GO_IMAGE}" \
    --build-arg "GO_RUNTIME_IMAGE=${GO_RUNTIME_IMAGE}" \
    --build-arg "NODE_IMAGE=${NODE_IMAGE}" \
    --build-arg "NGINX_IMAGE=${NGINX_IMAGE}" \
    --tag "${tag_ver}" \
    --tag "${tag_sha}" \
    --load \
    .
  if [[ "${PUSH}" == "1" ]]; then
    docker push "${tag_ver}"
    docker push "${tag_sha}"
  fi
}

build_one ingest-gateway   deploy/docker/ingest-gateway.Dockerfile
build_one temporal-worker  deploy/docker/temporal-worker.Dockerfile
build_one probe-gateway    deploy/docker/probe-gateway.Dockerfile
build_one dashboard-api    deploy/docker/dashboard-api.Dockerfile
build_one dashboard-web    deploy/docker/dashboard-web.Dockerfile
build_one probe            deploy/docker/probe.Dockerfile

echo "==> done: six product images tagged ${APP_VERSION} and sha-${SHORT_SHA}"
