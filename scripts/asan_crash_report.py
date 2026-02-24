#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional


def discover_crash_files(out_dir: Path) -> List[Path]:
    crash_files: List[Path] = []
    if not out_dir.is_dir():
        return crash_files

    for worker in sorted(out_dir.iterdir()):
        crash_dir = worker / "crashes"
        if not crash_dir.is_dir():
            continue
        for entry in sorted(crash_dir.iterdir()):
            if not entry.is_file():
                continue
            if entry.name.startswith("README"):
                continue
            crash_files.append(entry)

    return crash_files


def parse_asan(stderr: str) -> Dict[str, object]:
    out: Dict[str, object] = {
        "has_asan": False,
        "asan_type": "",
        "summary": "",
        "stack": [],
    }

    err_match = re.search(r"ERROR: AddressSanitizer: ([^\n]+)", stderr)
    sum_match = re.search(r"SUMMARY: AddressSanitizer: ([^\n]+)", stderr)
    if not err_match and not sum_match:
        return out

    out["has_asan"] = True
    if err_match:
        out["asan_type"] = err_match.group(1).strip()
    if sum_match:
        out["summary"] = sum_match.group(1).strip()

    stack = re.findall(r"^\s*#\d+\s+.*$", stderr, flags=re.MULTILINE)
    out["stack"] = stack[:12]
    return out


def find_symbolizer() -> Optional[str]:
    env_path = os.environ.get("ASAN_SYMBOLIZER_PATH")
    if env_path and Path(env_path).exists():
        return env_path

    llvm_symbolizer = shutil.which("llvm-symbolizer")
    if llvm_symbolizer:
        return llvm_symbolizer

    if platform.system() == "Darwin":
        try:
            proc = subprocess.run(
                ["xcrun", "--find", "llvm-symbolizer"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            candidate = proc.stdout.strip()
            if proc.returncode == 0 and candidate and Path(candidate).exists():
                return candidate
        except FileNotFoundError:
            pass

    return None


def compile_harness(
    cc: str,
    harness_src: Path,
    flecs_src_dir: Path,
    include_dir: Path,
    output_bin: Path,
) -> List[str]:
    output_bin.parent.mkdir(parents=True, exist_ok=True)
    flecs_sources = sorted(flecs_src_dir.rglob("*.c"))
    if not flecs_sources:
        raise RuntimeError(f"No Flecs source files found under {flecs_src_dir}")

    cmd = [
        cc,
        "-std=gnu99",
        "-O1",
        "-g",
        "-fno-omit-frame-pointer",
        "-fsanitize=address",
        "-DFLECS_SCRIPT_MATH",
        "-DFLECS_USE_OS_ALLOC=",
        f"-I{include_dir}",
        f"-I{flecs_src_dir}",
        str(harness_src),
    ]
    cmd.extend(str(src) for src in flecs_sources)
    cmd.extend(["-lpthread", "-lm"])

    if platform.system() == "Linux":
        cmd.append("-lrt")

    cmd.extend(["-o", str(output_bin)])

    subprocess.run(cmd, check=True)
    return cmd


def run_case(
    harness_bin: Path,
    crash_file: Path,
    symbolizer: Optional[str],
    timeout_s: int,
) -> Dict[str, object]:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = (
        "abort_on_error=1:"
        "halt_on_error=1:"
        "symbolize=1:"
        "detect_leaks=0:"
        "allocator_may_return_null=1"
    )

    if symbolizer:
        env["ASAN_SYMBOLIZER_PATH"] = symbolizer

    proc = subprocess.run(
        [str(harness_bin), str(crash_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        timeout=timeout_s,
        check=False,
        env=env,
    )

    stderr = proc.stderr
    parsed = parse_asan(stderr)
    return {
        "returncode": proc.returncode,
        "stderr": stderr,
        "has_asan": parsed["has_asan"],
        "asan_type": parsed["asan_type"],
        "summary": parsed["summary"],
        "stack": parsed["stack"],
    }


def write_report(
    report_path: Path,
    log_dir: Path,
    compile_cmd: List[str],
    symbolizer: Optional[str],
    total_files: int,
    unique_files: int,
    results: List[Dict[str, object]],
) -> None:
    generated = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    asan_count = sum(1 for r in results if r["has_asan"])
    no_asan_count = len(results) - asan_count

    lines: List[str] = []
    lines.append("# Flecs Crash ASAN Report")
    lines.append("")
    lines.append(f"- Generated (UTC): `{generated}`")
    lines.append(f"- Crash files found: `{total_files}`")
    lines.append(f"- Unique crash contents (SHA1): `{unique_files}`")
    lines.append(f"- Crash files executed: `{len(results)}`")
    lines.append(f"- AddressSanitizer findings: `{asan_count}`")
    lines.append(f"- Non-ASAN runs: `{no_asan_count}`")
    lines.append(f"- Symbolizer: `{symbolizer or 'not found'}`")
    lines.append("- Build define: `FLECS_USE_OS_ALLOC`")
    lines.append("")
    lines.append("## Build Command")
    lines.append("")
    lines.append("```bash")
    lines.append(" ".join(compile_cmd))
    lines.append("```")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append("| SHA1 | Worker | Files | Return | ASAN | Summary |")
    lines.append("|---|---|---:|---:|---|---|")

    for r in results:
        asan_type = r["asan_type"] if r["has_asan"] else "-"
        summary = r["summary"] if r["summary"] else "-"
        lines.append(
            f"| `{r['sha1']}` | `{r['worker']}` | {len(r['paths'])} | {r['returncode']} | "
            f"`{asan_type}` | {summary} |"
        )

    lines.append("")
    lines.append("## Details")
    lines.append("")
    for r in results:
        lines.append(f"### `{r['sha1']}`")
        lines.append("")
        lines.append(f"- Worker: `{r['worker']}`")
        lines.append(f"- Representative file: `{r['paths'][0]}`")
        if len(r["paths"]) > 1:
            lines.append(f"- Duplicate files: `{len(r['paths']) - 1}`")
        lines.append(f"- Return code: `{r['returncode']}`")
        lines.append(f"- ASAN finding: `{'yes' if r['has_asan'] else 'no'}`")
        if r["asan_type"]:
            lines.append(f"- ASAN type: `{r['asan_type']}`")
        if r["summary"]:
            lines.append(f"- Summary: `{r['summary']}`")
        lines.append(f"- Full log: `{(log_dir / f'{r['sha1']}.log').name}`")
        lines.append("")
        stack = r["stack"]
        if stack:
            lines.append("```text")
            lines.extend(stack)
            lines.append("```")
            lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build ASAN harness and generate report for AFL crash files"
    )
    parser.add_argument("--out", default="out", help="AFL output directory")
    parser.add_argument(
        "--report-dir",
        default=None,
        help="Output directory for ASAN report (default: <out>/asan_report)",
    )
    parser.add_argument(
        "--cc",
        default=os.environ.get("CC", "clang"),
        help="C compiler to use",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Per-crash timeout in seconds",
    )
    parser.add_argument(
        "--no-dedupe",
        action="store_true",
        help="Run all crash files (default deduplicates by SHA1)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    out_dir = (repo_root / args.out).resolve()
    report_dir = (Path(args.report_dir).resolve() if args.report_dir else (out_dir / "asan_report"))
    report_path = report_dir / "asan_report.md"
    log_dir = report_dir / "logs"
    bin_dir = report_dir / "bin"
    harness_bin = bin_dir / "flecs_script_harness_asan"

    crash_files = discover_crash_files(out_dir)
    if not crash_files:
        print(f"No crash files found in {out_dir}")
        return 1

    # Group by content hash to avoid rerunning identical crash files by default.
    grouped: Dict[str, Dict[str, object]] = {}
    for crash in crash_files:
        data = crash.read_bytes()
        sha1 = hashlib.sha1(data).hexdigest()
        worker = crash.parent.parent.name
        if sha1 not in grouped:
            grouped[sha1] = {"sha1": sha1, "worker": worker, "paths": []}
        grouped[sha1]["paths"].append(str(crash))

    if args.no_dedupe:
        run_items = []
        for crash in crash_files:
            data = crash.read_bytes()
            sha1 = hashlib.sha1(data).hexdigest()
            worker = crash.parent.parent.name
            run_items.append({"sha1": sha1, "worker": worker, "paths": [str(crash)]})
    else:
        run_items = [grouped[k] for k in sorted(grouped.keys())]

    harness_src = repo_root / "fuzz" / "flecs_script_harness.c"
    flecs_dir = repo_root / "flecs"
    flecs_src_dir = flecs_dir / "src"
    include_dir = flecs_dir / "include"

    if not harness_src.exists() or not flecs_src_dir.exists():
        print("Harness source or Flecs source directory not found; expected paths:")
        print(f"- {harness_src}")
        print(f"- {flecs_src_dir}")
        return 1

    report_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    compile_cmd = compile_harness(
        args.cc,
        harness_src,
        flecs_src_dir,
        include_dir,
        harness_bin,
    )
    symbolizer = find_symbolizer()

    results: List[Dict[str, object]] = []
    for item in run_items:
        crash_path = Path(item["paths"][0])
        result = run_case(
            harness_bin,
            crash_path,
            symbolizer,
            args.timeout,
        )
        result["sha1"] = item["sha1"]
        result["worker"] = item["worker"]
        result["paths"] = item["paths"]
        results.append(result)

        log_path = log_dir / f"{item['sha1']}.log"
        log_path.write_text(result["stderr"], encoding="utf-8")

    # Stable ordering: ASAN findings first, then by sha1.
    results.sort(key=lambda r: (0 if r["has_asan"] else 1, r["sha1"]))

    write_report(
        report_path,
        log_dir,
        compile_cmd,
        symbolizer,
        total_files=len(crash_files),
        unique_files=len(grouped),
        results=results,
    )

    print(f"Wrote ASAN report: {report_path}")
    print(f"Wrote logs: {log_dir}")
    print(f"Cases executed: {len(results)}")
    print(f"AddressSanitizer findings: {sum(1 for r in results if r['has_asan'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
