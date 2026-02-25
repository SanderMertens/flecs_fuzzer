#!/usr/bin/env bash
set -euo pipefail

DURATION_SECONDS="${1:-300}"
OUT_DIR="${2:-/work/out}"
WORKERS="${3:-${AFL_WORKERS:-$(nproc)}}"
CORPUS_DIR="/work/fuzz/seeds"
HARNESS="/opt/fuzz/flecs_script_harness"

mkdir -p "${OUT_DIR}"
rm -rf "${OUT_DIR}/default" "${OUT_DIR}"/fuzzer*

if ! [[ "${WORKERS}" =~ ^[0-9]+$ ]] || [ "${WORKERS}" -lt 1 ]; then
  WORKERS=1
fi

echo "Starting AFL++ fuzzing for ${DURATION_SECONDS}s"
echo "Harness: ${HARNESS}"
echo "Corpus:  ${CORPUS_DIR}"
echo "Output:  ${OUT_DIR}"
echo "Workers: ${WORKERS}"

set +e
AFL_EXIT=0

if [ "${WORKERS}" -eq 1 ]; then
  afl-fuzz \
    -i "${CORPUS_DIR}" \
    -o "${OUT_DIR}" \
    -m none \
    -t 2000+ \
    -V "${DURATION_SECONDS}" \
    -- "${HARNESS}" @@
  AFL_EXIT=$?
else
  pids=()
  names=()

  master="fuzzer01"
  afl-fuzz \
    -i "${CORPUS_DIR}" \
    -o "${OUT_DIR}" \
    -M "${master}" \
    -m none \
    -t 2000+ \
    -V "${DURATION_SECONDS}" \
    -- "${HARNESS}" @@ &
  pids+=("$!")
  names+=("${master}")

  i=2
  while [ "${i}" -le "${WORKERS}" ]; do
    name="$(printf 'fuzzer%02d' "${i}")"
    afl-fuzz \
      -i "${CORPUS_DIR}" \
      -o "${OUT_DIR}" \
      -S "${name}" \
      -m none \
      -t 2000+ \
      -V "${DURATION_SECONDS}" \
      -- "${HARNESS}" @@ &
    pids+=("$!")
    names+=("${name}")
    i=$((i + 1))
  done

  for idx in "${!pids[@]}"; do
    wait "${pids[$idx]}"
    rc=$?
    if [ "${rc}" -ne 0 ]; then
      echo "Worker ${names[$idx]} exited with status ${rc}" >&2
      AFL_EXIT=1
    fi
  done
fi
set -e

exit 0
