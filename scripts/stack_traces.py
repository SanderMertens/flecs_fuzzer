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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

FRAME_RE = re.compile(r"^\s*#\d+\s+.*$")
FRAME_INDEX_RE = re.compile(r"^\s*#\d+\s+")
HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
SPACE_RE = re.compile(r"\s+")


def build_parser() -> argparse.ArgumentParser:
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
    parser.add_argument(
        "--jobs",
        type=int,
        default=max(1, (os.cpu_count() or 1)),
        help="Number of worker threads for running crash cases (default: CPU count)",
    )
    parser.add_argument(
        "--compile-jobs",
        type=int,
        default=max(1, (os.cpu_count() or 1)),
        help="Number of worker threads for compiling the ASAN harness (default: CPU count)",
    )
    return parser


def parse_args() -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be >= 1")
    if args.compile_jobs < 1:
        parser.error("--compile-jobs must be >= 1")
    return args


def resolve_paths(args: argparse.Namespace) -> Dict[str, Path]:
    repo_root = Path(__file__).resolve().parent.parent
    out_dir = (repo_root / args.out).resolve()
    report_dir = (
        Path(args.report_dir).resolve() if args.report_dir else (out_dir / "asan_report")
    )
    log_dir = report_dir / "logs"
    bin_dir = report_dir / "bin"
    harness_bin = bin_dir / "flecs_script_harness_asan"

    return {
        "repo_root": repo_root,
        "out_dir": out_dir,
        "report_dir": report_dir,
        "report_path": report_dir / "asan_report.md",
        "log_dir": log_dir,
        "harness_bin": harness_bin,
        "harness_src": repo_root / "fuzz" / "flecs_script_harness.c",
        "flecs_src_dir": repo_root / "flecs" / "src",
        "include_dir": repo_root / "flecs" / "include",
    }


def index_crash_files(
    crash_files: List[Path],
) -> tuple[Dict[str, Dict[str, object]], List[Dict[str, str]]]:
    grouped: Dict[str, Dict[str, object]] = {}
    indexed_crashes: List[Dict[str, str]] = []

    for crash in crash_files:
        data = crash.read_bytes()
        sha1 = hashlib.sha1(data).hexdigest()
        worker = crash.parent.parent.name
        indexed_crashes.append({"sha1": sha1, "worker": worker, "path": str(crash)})

        if sha1 not in grouped:
            grouped[sha1] = {"sha1": sha1, "worker": worker, "paths": []}
        grouped[sha1]["paths"].append(str(crash))

    return grouped, indexed_crashes


def build_run_items(
    grouped: Dict[str, Dict[str, object]],
    indexed_crashes: List[Dict[str, str]],
    no_dedupe: bool,
) -> List[Dict[str, object]]:
    run_items: List[Dict[str, object]] = []

    if no_dedupe:
        for index, crash in enumerate(indexed_crashes):
            run_items.append(
                {
                    "id": f"{crash['sha1']}_{index:05d}",
                    "sha1": crash["sha1"],
                    "worker": crash["worker"],
                    "paths": [crash["path"]],
                }
            )
        return run_items

    for sha1 in sorted(grouped.keys()):
        item = grouped[sha1].copy()
        item["id"] = sha1
        run_items.append(item)
    return run_items


def normalize_hex_addresses(text: str) -> str:
    return HEX_RE.sub("0x*", text)


def canonicalize_frame(frame: str) -> str:
    out = FRAME_INDEX_RE.sub("", frame.strip())
    out = normalize_hex_addresses(out)
    out = SPACE_RE.sub(" ", out).strip()
    return out


def build_trace_signature(
    stack: List[str],
    summary: str,
    asan_type: str,
    returncode: int,
) -> Tuple[str, List[str], str]:
    canonical_stack = [canonicalize_frame(frame) for frame in stack if frame.strip()]
    if canonical_stack:
        signature_source = "\n".join(canonical_stack)
    else:
        fallback_parts = [summary, asan_type, f"returncode:{returncode}"]
        signature_source = "no-stack"
        for part in fallback_parts:
            normalized = SPACE_RE.sub(" ", normalize_hex_addresses(part)).strip()
            if normalized:
                signature_source = normalized
                break

    signature = hashlib.sha1(signature_source.encode("utf-8")).hexdigest()
    return signature, canonical_stack, signature_source


def validate_harness_sources(harness_src: Path, flecs_src_dir: Path) -> bool:
    if harness_src.exists() and flecs_src_dir.exists():
        return True

    print("Harness source or Flecs source directory not found; expected paths:")
    print(f"- {harness_src}")
    print(f"- {flecs_src_dir}")
    return False


def prepare_report_dirs(report_dir: Path, log_dir: Path) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)


def execute_run_items(
    run_items: List[Dict[str, object]],
    harness_bin: Path,
    symbolizer: Optional[str],
    timeout_s: int,
    jobs: int,
    log_dir: Path,
    project_prefixes: List[str],
) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    futures = {}

    with ThreadPoolExecutor(max_workers=jobs) as executor:
        for item in run_items:
            crash_path = Path(item["paths"][0])
            future = executor.submit(
                run_case,
                harness_bin,
                crash_path,
                symbolizer,
                timeout_s,
                project_prefixes,
            )
            futures[future] = item

        completed = 0
        total = len(run_items)
        asan_hits = 0
        for future in as_completed(futures):
            item = futures[future]
            result = future.result()
            result["id"] = item["id"]
            result["sha1"] = item["sha1"]
            result["worker"] = item["worker"]
            result["paths"] = item["paths"]
            trace_sig, canonical_stack, signature_source = build_trace_signature(
                result["stack"],
                result["summary"],
                result["asan_type"],
                result["returncode"],
            )
            result["trace_sig"] = trace_sig
            result["canonical_stack"] = canonical_stack
            result["trace_source"] = signature_source
            results.append(result)

            if result["has_asan"]:
                asan_hits += 1

            log_path = log_dir / f"{item['id']}.log"
            log_path.write_text(result["stderr"], encoding="utf-8")

            completed += 1
            status = "ASAN" if result["has_asan"] else "ok"
            print_progress(
                "execute",
                completed,
                total,
                (
                    f"last_sha1={item['sha1'][:12]} rc={result['returncode']} "
                    f"status={status} asan={asan_hits}"
                ),
            )

    if run_items:
        finish_progress_line()

    return results


def print_progress(stage: str, current: int, total: int, extra: str = "") -> None:
    pct = 100.0 if total == 0 else (current / total) * 100.0
    line = f"[{stage}] {current}/{total} ({pct:5.1f}%)"
    if extra:
        line = f"{line} {extra}"

    # In non-interactive output (e.g. redirected logs), print only the final state.
    if not sys.stdout.isatty():
        if current == total:
            print(line)
        return

    last_width = getattr(print_progress, "_last_width", 0)
    padding = " " * max(0, last_width - len(line))
    sys.stdout.write("\r" + line + padding)
    sys.stdout.flush()
    setattr(print_progress, "_last_width", len(line))


def finish_progress_line() -> None:
    if not sys.stdout.isatty():
        return
    if getattr(print_progress, "_last_width", 0):
        print()
        setattr(print_progress, "_last_width", 0)


def discover_crash_files(out_dir: Path) -> List[Path]:
    crash_files: List[Path] = []
    if not out_dir.is_dir():
        return crash_files

    workers = sorted(out_dir.iterdir())
    total_workers = len(workers)
    for index, worker in enumerate(workers, 1):
        crash_dir = worker / "crashes"
        if not crash_dir.is_dir():
            print_progress("discover", index, total_workers, f"crashes={len(crash_files)}")
            continue
        for entry in sorted(crash_dir.iterdir()):
            if not entry.is_file():
                continue
            if entry.name.startswith("README"):
                continue
            crash_files.append(entry)
        print_progress("discover", index, total_workers, f"crashes={len(crash_files)}")

    if total_workers:
        finish_progress_line()

    return crash_files


def parse_asan(
    stderr: str,
    project_prefixes: Optional[List[str]] = None,
) -> Dict[str, object]:
    out: Dict[str, object] = {
        "has_asan": False,
        "asan_type": "",
        "summary": "",
        "stack": [],
    }
    if project_prefixes is None:
        project_prefixes = build_project_prefixes(Path(__file__).resolve().parent.parent)

    err_match = re.search(r"ERROR: AddressSanitizer: ([^\n]+)", stderr)
    sum_match = re.search(r"SUMMARY: AddressSanitizer: ([^\n]+)", stderr)
    if not err_match and not sum_match:
        return out

    out["has_asan"] = True
    if err_match:
        out["asan_type"] = strip_project_prefixes(err_match.group(1).strip(), project_prefixes)
    if sum_match:
        out["summary"] = strip_project_prefixes(sum_match.group(1).strip(), project_prefixes)

    out["stack"] = [
        strip_project_prefixes(frame, project_prefixes)
        for frame in extract_primary_stack(stderr, 12)
    ]
    return out


def build_project_prefixes(project_root: Path) -> List[str]:
    root_candidates = {
        str(project_root),
        str(project_root.resolve()),
        os.path.realpath(str(project_root)),
    }
    prefixes: List[str] = []
    for candidate in root_candidates:
        candidate = candidate.rstrip("/\\")
        if not candidate:
            continue
        prefixes.extend([f"{candidate}/", f"{candidate}\\"])
    return sorted(set(prefixes), key=len, reverse=True)


def strip_project_prefixes(text: str, prefixes: List[str]) -> str:
    out = text
    for prefix in prefixes:
        out = out.replace(prefix, "")
    return out


def extract_primary_stack(stderr: str, max_frames: int) -> List[str]:
    err_match = re.search(r"ERROR: AddressSanitizer: ([^\n]+)", stderr)
    lines = stderr.splitlines()
    start_line = 0
    if err_match:
        start_line = stderr[: err_match.start()].count("\n")

    stack: List[str] = []
    in_primary_stack = False
    for line in lines[start_line:]:
        if FRAME_RE.match(line):
            stack.append(line)
            in_primary_stack = True
            if len(stack) >= max_frames:
                break
            continue

        if in_primary_stack:
            break

    # Fallback for unusual formatting where no contiguous primary stack block is found.
    if not stack:
        stack = re.findall(r"^\s*#\d+\s+.*$", stderr, flags=re.MULTILINE)[:max_frames]

    return stack


def find_dsymutil() -> Optional[str]:
    dsymutil = shutil.which("dsymutil")
    if dsymutil:
        return dsymutil

    if platform.system() == "Darwin":
        try:
            proc = subprocess.run(
                ["xcrun", "--find", "dsymutil"],
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
    jobs: int,
) -> List[str]:
    output_bin.parent.mkdir(parents=True, exist_ok=True)
    flecs_sources = sorted(flecs_src_dir.rglob("*.c"))
    if not flecs_sources:
        raise RuntimeError(f"No Flecs source files found under {flecs_src_dir}")

    compile_sources = [harness_src, *flecs_sources]
    compile_flags = [
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
    ]

    obj_dir = output_bin.parent / "obj"
    if obj_dir.exists():
        shutil.rmtree(obj_dir)
    obj_dir.mkdir(parents=True, exist_ok=True)

    compile_items: List[tuple[Path, Path]] = []
    for src in compile_sources:
        if src == harness_src:
            rel = Path("harness") / src.name
        else:
            rel = src.relative_to(flecs_src_dir)
        obj_path = obj_dir / rel.with_suffix(".o")
        obj_path.parent.mkdir(parents=True, exist_ok=True)
        compile_items.append((src, obj_path))

    futures = {}
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        for src, obj_path in compile_items:
            cmd = compile_flags + ["-c", str(src), "-o", str(obj_path)]
            future = executor.submit(subprocess.run, cmd, check=True)
            futures[future] = src

        completed = 0
        total = len(compile_items)
        for future in as_completed(futures):
            src = futures[future]
            future.result()
            completed += 1
            print_progress("compile", completed, total, f"last={src.name}")

    if compile_items:
        finish_progress_line()

    link_cmd = [cc, "-fsanitize=address"]
    link_cmd.extend(str(obj_path) for _, obj_path in compile_items)
    link_cmd.extend(["-lpthread", "-lm"])

    if platform.system() == "Linux":
        link_cmd.append("-lrt")

    link_cmd.extend(["-o", str(output_bin)])

    subprocess.run(link_cmd, check=True)

    # On macOS, ASAN line info depends on DWARF data in the dSYM bundle.
    if platform.system() == "Darwin":
        dsymutil = find_dsymutil()
        if dsymutil:
            dsym_path = output_bin.with_suffix(".dSYM")
            subprocess.run(
                [dsymutil, str(output_bin), "-o", str(dsym_path)],
                check=True,
            )
        else:
            print("Warning: dsymutil not found; ASAN stack traces may miss file:line info.")

    return link_cmd


def run_case(
    harness_bin: Path,
    crash_file: Path,
    symbolizer: Optional[str],
    timeout_s: int,
    project_prefixes: List[str],
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
        env["ASAN_OPTIONS"] = (
            f"{env['ASAN_OPTIONS']}:external_symbolizer_path={symbolizer}"
        )

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

    stderr = strip_project_prefixes(proc.stderr, project_prefixes)
    parsed = parse_asan(stderr, project_prefixes=project_prefixes)
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
    trace_groups: Dict[str, Dict[str, object]] = {}
    for r in results:
        trace_sig = str(r["trace_sig"])
        if trace_sig not in trace_groups:
            trace_groups[trace_sig] = {
                "sig": trace_sig,
                "canonical_stack": list(r["canonical_stack"]),
                "items": [],
            }
        trace_groups[trace_sig]["items"].append(r)

    grouped_traces = list(trace_groups.values())
    for group in grouped_traces:
        items = list(group["items"])
        items.sort(key=lambda item: (0 if item["has_asan"] else 1, item["sha1"]))
        group["items"] = items
        group["file_count"] = sum(len(item["paths"]) for item in items)
        group["workers"] = sorted({str(item["worker"]) for item in items})
        group["representative"] = items[0]
    grouped_traces.sort(
        key=lambda group: (
            -(sum(1 for item in group["items"] if item["has_asan"])),
            -int(group["file_count"]),
            str(group["sig"]),
        )
    )

    lines: List[str] = []
    lines.append("# Flecs Crash ASAN Report")
    lines.append("")
    lines.append(f"- Generated (UTC): `{generated}`")
    lines.append(f"- Crash files found: `{total_files}`")
    lines.append(f"- Unique crash contents (SHA1): `{unique_files}`")
    lines.append(f"- Unique stack traces (canonical): `{len(grouped_traces)}`")
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
    lines.append("| SHA1 | Trace | Worker | Files | Return | ASAN | Summary |")
    lines.append("|---|---|---|---:|---:|---|---|")

    for r in results:
        asan_type = r["asan_type"] if r["has_asan"] else "-"
        summary = r["summary"] if r["summary"] else "-"
        trace_short = str(r["trace_sig"])[:12]
        lines.append(
            f"| `{r['sha1']}` | `trace:{trace_short}` | `{r['worker']}` | {len(r['paths'])} | {r['returncode']} | "
            f"`{asan_type}` | {summary} |"
        )

    lines.append("")
    lines.append("## Unique Trace Groups")
    lines.append("")
    lines.append("| Trace | Crash files | Reproducers | Workers | Representative summary |")
    lines.append("|---|---:|---:|---|---|")
    for group in grouped_traces:
        representative = group["representative"]
        rep_summary = str(representative["summary"]) if representative["summary"] else "-"
        workers = ", ".join(f"`{w}`" for w in group["workers"])
        lines.append(
            f"| `trace:{str(group['sig'])[:12]}` | {group['file_count']} | {len(group['items'])} | "
            f"{workers} | {rep_summary} |"
        )

    lines.append("")
    lines.append("## Unique Trace Details")
    lines.append("")
    for group in grouped_traces:
        trace_sig = str(group["sig"])
        lines.append(f"### `trace:{trace_sig[:12]}`")
        lines.append("")
        lines.append(f"- Signature: `{trace_sig}`")
        lines.append(f"- Crash files: `{group['file_count']}`")
        lines.append(f"- Reproducers: `{len(group['items'])}`")
        workers = ", ".join(f"`{w}`" for w in group["workers"])
        lines.append(f"- Workers: {workers if workers else '-'}")
        lines.append("")
        if group["canonical_stack"]:
            lines.append("```text")
            lines.extend(group["canonical_stack"])
            lines.append("```")
            lines.append("")

        lines.append("| SHA1 | Worker | Files | Summary | Representative file |")
        lines.append("|---|---|---:|---|---|")
        for item in group["items"]:
            item_summary = item["summary"] if item["summary"] else "-"
            lines.append(
                f"| `{item['sha1']}` | `{item['worker']}` | {len(item['paths'])} | {item_summary} | "
                f"`{item['paths'][0]}` |"
            )
        lines.append("")

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
        lines.append(f"- Trace group: `trace:{str(r['trace_sig'])[:12]}`")
        if r["asan_type"]:
            lines.append(f"- ASAN type: `{r['asan_type']}`")
        if r["summary"]:
            lines.append(f"- Summary: `{r['summary']}`")
        log_name = (log_dir / f"{r['id']}.log").name
        lines.append(f"- Full log: `{log_name}`")
        lines.append("")
        stack = r["stack"]
        if stack:
            lines.append("```text")
            lines.extend(stack)
            lines.append("```")
            lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    args = parse_args()
    paths = resolve_paths(args)

    crash_files = discover_crash_files(paths["out_dir"])
    if not crash_files:
        print(f"No crash files found in {paths['out_dir']}")
        return 1

    grouped, indexed_crashes = index_crash_files(crash_files)
    run_items = build_run_items(grouped, indexed_crashes, args.no_dedupe)

    if not validate_harness_sources(paths["harness_src"], paths["flecs_src_dir"]):
        return 1

    prepare_report_dirs(paths["report_dir"], paths["log_dir"])

    compile_cmd = compile_harness(
        args.cc,
        paths["harness_src"],
        paths["flecs_src_dir"],
        paths["include_dir"],
        paths["harness_bin"],
        args.compile_jobs,
    )
    symbolizer = find_symbolizer()
    project_prefixes = build_project_prefixes(paths["repo_root"])

    results = execute_run_items(
        run_items,
        paths["harness_bin"],
        symbolizer,
        args.timeout,
        args.jobs,
        paths["log_dir"],
        project_prefixes,
    )

    # Stable ordering: ASAN findings first, then by sha1.
    results.sort(key=lambda r: (0 if r["has_asan"] else 1, r["sha1"]))

    write_report(
        paths["report_path"],
        paths["log_dir"],
        compile_cmd,
        symbolizer,
        total_files=len(crash_files),
        unique_files=len(grouped),
        results=results,
    )

    print("[done]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
