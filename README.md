# Flecs Script AFL Fuzzing

This repository contains an AFL++ harness for fuzzing Flecs script parsing and
evaluation.

## What is included

- `Dockerfile.afl`: Linux image with AFL++, Bake, Flecs build, and harness build.
- `fuzz/flecs_script_harness.c`: file-based AFL target for Flecs script.
- `fuzz/seeds/*.flecs`: seed corpus with valid and invalid script examples.
- `scripts/run_fuzzer.sh`: host command to build image, run fuzzing, and print report.
- `scripts/afl_report.py`: triage tool that reports only:
  - `ECS_INTERNAL_ERROR` asserts
  - hard crashes (signals / abnormal exits)

## One-command run

```bash
./scripts/run_fuzzer.sh 300
```

Arguments:

- first argument: fuzz duration in seconds (default `300`)
- second argument: host output directory (default `./out`)
- third argument: AFL worker count (default: all detected cores in container)

Example:

```bash
./scripts/run_fuzzer.sh 600 ./out 8
```

You can also set worker count with `AFL_WORKERS`:

```bash
AFL_WORKERS=8 ./scripts/run_fuzzer.sh 600 ./out
```

## Report behavior

The harness suppresses regular parser/evaluation errors from malformed input.
The final report ignores those expected errors and includes only
`ECS_INTERNAL_ERROR` assertions and true crashes.

When multiple workers are used, fuzzing runs in AFL++ parallel mode (`-M`/`-S`)
and the report aggregates all worker outputs.

## HTML crash dashboard

Generate an aggregated HTML report across all fuzzers in `out/`:

```bash
python3 scripts/afl_html_report.py --out ./out
```

This writes:

```text
./out/crash_report.html
```

Optional: include harness-based crash classification and stderr snippets:

```bash
python3 scripts/afl_html_report.py \
  --out ./out \
  --harness /tmp/flecs_script_harness_math_check
```

If `./out/asan_report/logs` exists (from `scripts/asan_crash_report.py`), the
HTML report also shows generated stack traces per crash. Override this location
with `--asan-log-dir <path>`.
