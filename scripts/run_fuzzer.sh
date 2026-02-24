#!/usr/bin/env bash
set -euo pipefail

DURATION_SECONDS="${1:-300}"
OUT_DIR="${2:-$(pwd)/out}"
WORKERS="${3:-${AFL_WORKERS:-}}"
IMAGE_TAG="${IMAGE_TAG:-flecs-script-afl}"

mkdir -p "${OUT_DIR}"

docker build -f Dockerfile.afl -t "${IMAGE_TAG}" .
docker run --rm \
  -v "${OUT_DIR}:/work/out" \
  "${IMAGE_TAG}" \
  /work/scripts/run_afl_in_container.sh "${DURATION_SECONDS}" /work/out "${WORKERS}"
