#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import os
import signal
import subprocess
import sys
from typing import Dict, List, Optional, Tuple


def parse_stats(path: str) -> Dict[str, str]:
    stats: Dict[str, str] = {}
    if not os.path.exists(path):
        return stats
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            stats[key.strip()] = value.strip()
    return stats


def parse_int(value: str) -> Optional[int]:
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return None


def parse_float(value: str) -> Optional[float]:
    try:
        return float(value.strip())
    except (ValueError, AttributeError):
        return None


def discover_fuzzers(out_dir: str, selected: Optional[str]) -> List[str]:
    if selected:
        stats_path = os.path.join(out_dir, selected, "fuzzer_stats")
        return [selected] if os.path.exists(stats_path) else []

    fuzzers = []
    if not os.path.isdir(out_dir):
        return fuzzers

    for name in sorted(os.listdir(out_dir)):
        stats_path = os.path.join(out_dir, name, "fuzzer_stats")
        if os.path.isdir(os.path.join(out_dir, name)) and os.path.exists(stats_path):
            fuzzers.append(name)
    return fuzzers


def list_crash_files(crash_dir: str) -> List[str]:
    if not os.path.isdir(crash_dir):
        return []
    files = []
    for name in sorted(os.listdir(crash_dir)):
        if name.startswith("README"):
            continue
        path = os.path.join(crash_dir, name)
        if os.path.isfile(path):
            files.append(path)
    return files


def run_harness(harness: str, testcase: str) -> Dict[str, str]:
    proc = subprocess.run(
        [harness, testcase],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        timeout=10,
        check=False,
    )

    stderr = proc.stderr.strip()
    internal = "ECS_INTERNAL_ERROR" in stderr
    crashed = proc.returncode < 0 or proc.returncode > 128

    signal_name = ""
    if proc.returncode < 0:
        sig = -proc.returncode
        try:
            signal_name = signal.Signals(sig).name
        except ValueError:
            signal_name = f"SIG{sig}"
    elif proc.returncode > 128:
        sig = proc.returncode - 128
        try:
            signal_name = signal.Signals(sig).name
        except ValueError:
            signal_name = f"SIG{sig}"

    status = "ignored"
    if internal:
        status = "ecs_internal_error"
    elif crashed:
        status = "crash"

    with open(testcase, "rb") as f:
        data = f.read()

    return {
        "path": testcase,
        "name": os.path.basename(testcase),
        "size": str(len(data)),
        "sha1": hashlib.sha1(data).hexdigest(),
        "returncode": str(proc.returncode),
        "signal": signal_name,
        "stderr": stderr,
        "status": status,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AFL fuzzing report")
    parser.add_argument("--out", required=True, help="AFL output directory")
    parser.add_argument("--fuzzer", default=None, help="Optional fuzzer id")
    parser.add_argument("--harness", required=True, help="Harness binary")
    args = parser.parse_args()

    fuzzers = discover_fuzzers(args.out, args.fuzzer)
    if not fuzzers:
        print("# Flecs Script AFL Report")
        print("")
        print("No AFL fuzzer outputs found.")
        return 0

    stats_by_fuzzer: Dict[str, Dict[str, str]] = {}
    crash_files: List[Tuple[str, str]] = []
    total_execs = 0
    total_execs_per_sec = 0.0
    max_paths_total: Optional[int] = None

    for fuzzer in fuzzers:
        fuzzer_dir = os.path.join(args.out, fuzzer)
        stats = parse_stats(os.path.join(fuzzer_dir, "fuzzer_stats"))
        stats_by_fuzzer[fuzzer] = stats
        crash_files.extend((fuzzer, p) for p in list_crash_files(os.path.join(fuzzer_dir, "crashes")))

        execs_done = parse_int(stats.get("execs_done", ""))
        if execs_done is not None:
            total_execs += execs_done

        execs_per_sec = parse_float(stats.get("execs_per_sec", ""))
        if execs_per_sec is not None:
            total_execs_per_sec += execs_per_sec

        paths_total = parse_int(stats.get("paths_total", ""))
        if paths_total is not None:
            max_paths_total = paths_total if max_paths_total is None else max(max_paths_total, paths_total)

    findings = []
    dedup = set()
    for fuzzer, testcase in crash_files:
        try:
            finding = run_harness(args.harness, testcase)
        except subprocess.TimeoutExpired:
            finding = {
                "path": testcase,
                "name": os.path.basename(testcase),
                "size": str(os.path.getsize(testcase)),
                "sha1": "timeout",
                "returncode": "timeout",
                "signal": "",
                "stderr": "",
                "status": "crash",
            }
        finding["worker"] = fuzzer
        if finding["status"] != "ignored":
            dedup_key = finding["sha1"]
            if dedup_key not in dedup:
                dedup.add(dedup_key)
                findings.append(finding)

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    print("# Flecs Script AFL Report")
    print("")
    print(f"- Generated (UTC): {now}")
    print(f"- AFL output: `{args.out}`")
    print(f"- Fuzzers: `{', '.join(fuzzers)}`")
    print(f"- Worker count: `{len(fuzzers)}`")
    print(f"- Harness: `{args.harness}`")
    print(f"- Executions (sum): `{total_execs if total_execs else 'unknown'}`")
    print(f"- Exec/sec (sum): `{round(total_execs_per_sec, 2) if total_execs_per_sec else 'unknown'}`")
    print(f"- Paths total (max): `{max_paths_total if max_paths_total is not None else 'unknown'}`")
    print(f"- Crash files: `{len(crash_files)}`")
    print(f"- Actionable findings: `{len(findings)}`")
    print("")

    if not findings:
        print("No ECS_INTERNAL_ERROR asserts or hard crashes were reproduced.")
        return 0

    print("## Findings")
    print("")
    print("| Worker | File | Type | Signal | Return | Size | SHA1 |")
    print("|---|---|---|---|---:|---:|---|")
    for finding in findings:
        kind = "ECS_INTERNAL_ERROR" if finding["status"] == "ecs_internal_error" else "Crash"
        print(
            f"| {finding['worker']} | {finding['name']} | {kind} | {finding['signal'] or '-'} | "
            f"{finding['returncode']} | {finding['size']} | `{finding['sha1']}` |"
        )

    print("")
    print("## Notes")
    print("")
    for finding in findings:
        if not finding["stderr"]:
            continue
        print(f"- `{finding['name']}` stderr:")
        print("```text")
        print(finding["stderr"])
        print("```")

    return 0


if __name__ == "__main__":
    sys.exit(main())
