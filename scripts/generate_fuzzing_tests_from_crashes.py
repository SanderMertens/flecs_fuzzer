#!/usr/bin/env python3
import argparse
import hashlib
import re
import subprocess
from pathlib import Path
from typing import Dict, List


def discover_crash_files(out_dir: Path) -> List[Path]:
    crash_files: List[Path] = []
    if not out_dir.is_dir():
        return crash_files

    for worker in sorted(out_dir.iterdir()):
        crash_dir = worker / "crashes"
        if not crash_dir.is_dir():
            continue
        for path in sorted(crash_dir.iterdir()):
            if not path.is_file():
                continue
            if path.name.startswith("README"):
                continue
            crash_files.append(path)
    return crash_files


def normalize_script_bytes(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\x00", b"\n")


def escape_c_bytes(data: bytes) -> str:
    out = ""
    for b in data:
        if b == 0x09:
            out += r"\t"
        elif b == 0x22:
            out += r"\""
        elif b == 0x5C:
            out += r"\\"
        elif 32 <= b <= 126:
            out += chr(b)
        else:
            out += f"\\{b:03o}"
    return out


def extract_stack_from_log(log_path: Path, max_frames: int) -> List[str]:
    if not log_path.exists():
        return []

    text = log_path.read_text(encoding="utf-8", errors="replace")
    stack = re.findall(r"^\s*#\d+\s+.*$", text, flags=re.MULTILINE)
    return stack[:max_frames]


def collect_stacks(asan_log_dir: Path, max_frames: int) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    if not asan_log_dir.is_dir():
        return result

    for log_file in sorted(asan_log_dir.glob("*.log")):
        sha1 = log_file.stem.lower()
        if not re.fullmatch(r"[0-9a-f]{40}", sha1):
            continue
        frames = extract_stack_from_log(log_file, max_frames)
        if frames:
            result[sha1] = frames
    return result


def fuzz_function_source(
    number: int,
    root_dir: Path,
    crash: Path,
    stack_frames: List[str],
) -> str:
    raw = crash.read_bytes()
    rel = crash.relative_to(root_dir).as_posix()
    sha1 = hashlib.sha1(raw).hexdigest().lower()
    normalized = normalize_script_bytes(raw)
    script_lines = normalized.split(b"\n")
    if not script_lines:
        script_lines = [b""]

    lines: List[str] = []
    lines.append(f"/* crash={rel}, sha1={sha1}")
    if stack_frames:
        lines.append(" * asan_stack:")
        for frame in stack_frames:
            lines.append(f" * {frame}")
    lines.append(" */")
    lines.append(f"void Fuzzing_{number}(void) {{")
    lines.append("    const char *expr =")
    lines.append(f'    HEAD "{escape_c_bytes(script_lines[0])}"')
    for line in script_lines[1:]:
        lines.append(f'    LINE "{escape_c_bytes(line)}"')
    lines.append("        ;")
    lines.append("")
    lines.append("    fuzz(expr);")
    lines.append("}")
    return "\n".join(lines)


def update_fuzzing_source(
    fuzzing_c: Path,
    root_dir: Path,
    crash_files: List[Path],
    stack_by_sha1: Dict[str, List[str]],
) -> int:
    text = fuzzing_c.read_text(encoding="utf-8", errors="replace")

    fn_re = re.compile(
        r"(?P<prefix>(?:/\* crash=.*?\*/\n)?)"
        r"void\s+Fuzzing_(\d+)\s*\(void\)\s*\{\n(?P<body>.*?)\n\}\n?",
        re.DOTALL,
    )
    functions = list(fn_re.finditer(text))
    if not functions:
        raise RuntimeError(f"No Fuzzing_<N> functions found in {fuzzing_c}")

    manual_numbers: List[int] = []
    for match in functions:
        number = int(match.group(2))
        prefix = match.group("prefix")
        if not prefix:
            manual_numbers.append(number)

    manual_max = max(manual_numbers) if manual_numbers else 0
    target_start = manual_max + 1
    target_numbers = list(range(target_start, target_start + len(crash_files)))

    cursor = 0
    kept_parts: List[str] = []
    for match in functions:
        number = int(match.group(2))
        if number >= target_start:
            kept_parts.append(text[cursor:match.start()])
            cursor = match.end()
    kept_parts.append(text[cursor:])
    text = "".join(kept_parts).rstrip() + "\n\n"

    generated_blocks = [
        fuzz_function_source(
            number,
            root_dir,
            crash,
            stack_by_sha1.get(hashlib.sha1(crash.read_bytes()).hexdigest().lower(), []),
        )
        for number, crash in zip(target_numbers, crash_files)
    ]
    text += "\n\n".join(generated_blocks) + "\n"

    fuzzing_c.write_text(text, encoding="utf-8")
    return max(target_numbers)


def find_matching_bracket(text: str, start_index: int) -> int:
    depth = 0
    in_string = False
    escaped = False
    for i in range(start_index, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue

        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return i

    raise RuntimeError("Could not find matching closing bracket")


def update_fuzzing_testcases(project_json: Path, total_count: int) -> None:
    text = project_json.read_text(encoding="utf-8")

    suite_pos = text.find('"id": "Fuzzing"')
    if suite_pos == -1:
        raise RuntimeError("Could not find Fuzzing testsuite in project.json")

    testcases_pos = text.find('"testcases"', suite_pos)
    if testcases_pos == -1:
        raise RuntimeError("Could not find Fuzzing testcases list in project.json")

    list_start = text.find("[", testcases_pos)
    if list_start == -1:
        raise RuntimeError("Could not find opening [ for Fuzzing testcases")

    list_end = find_matching_bracket(text, list_start)

    values = [str(i) for i in range(1, total_count + 1)]
    body = "\n" + ",\n".join(f'                "{value}"' for value in values) + "\n            "
    updated = text[: list_start + 1] + body + text[list_end:]

    project_json.write_text(updated, encoding="utf-8")


def find_git_root(path: Path) -> Path:
    current = path.resolve()
    while True:
        if (current / ".git").exists():
            return current
        if current.parent == current:
            raise RuntimeError(f"Could not find git root for {path}")
        current = current.parent


def reset_files(paths: List[Path]) -> None:
    by_repo = {}
    for path in paths:
        repo = find_git_root(path.parent)
        by_repo.setdefault(repo, []).append(path.resolve())

    for repo, repo_paths in by_repo.items():
        rel_paths = [str(p.relative_to(repo)) for p in repo_paths]
        cmd = ["git", "checkout", "--", *rel_paths]
        subprocess.run(cmd, cwd=repo, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate script/Fuzzing testcases from AFL crash files"
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root (default: current directory)",
    )
    parser.add_argument(
        "--out-dir",
        default="out",
        help="AFL output directory relative to --root",
    )
    parser.add_argument(
        "--project-json",
        default="flecs/test/script/project.json",
        help="Path to script project.json relative to --root",
    )
    parser.add_argument(
        "--fuzzing-c",
        default="flecs/test/script/src/Fuzzing.c",
        help="Path to script fuzzing source relative to --root",
    )
    parser.add_argument(
        "--asan-log-dir",
        default="out/asan_report/logs",
        help="ASAN log directory relative to --root (optional)",
    )
    parser.add_argument(
        "--stack-max-frames",
        type=int,
        default=12,
        help="Maximum ASAN stack frames to include per test comment",
    )
    parser.add_argument(
        "--reset-first",
        action="store_true",
        help="Reset fuzzing source and project.json before regenerating",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_dir = (root / args.out_dir).resolve()
    project_json = (root / args.project_json).resolve()
    fuzzing_c = (root / args.fuzzing_c).resolve()
    asan_log_dir = (root / args.asan_log_dir).resolve()

    if args.reset_first:
        reset_files([fuzzing_c, project_json])

    crash_files = discover_crash_files(out_dir)
    if not crash_files:
        print(f"No crash files found under {out_dir}")
        return 1

    stack_by_sha1 = collect_stacks(asan_log_dir, args.stack_max_frames)
    max_number = update_fuzzing_source(fuzzing_c, root, crash_files, stack_by_sha1)
    update_fuzzing_testcases(project_json, max_number)

    print(f"Discovered {len(crash_files)} crash files")
    print(f"ASAN stacks matched: {len(stack_by_sha1)}")
    print(f"Updated fuzzing tests through: Fuzzing_{max_number}")
    print(f"Updated: {fuzzing_c}")
    print(f"Updated: {project_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
