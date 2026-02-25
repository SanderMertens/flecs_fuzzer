#!/usr/bin/env python3
import argparse
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

FRAME_RE = re.compile(r"^\s*#\d+\s+.*$")
FRAME_INDEX_RE = re.compile(r"^\s*#\d+\s+")
HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
SPACE_RE = re.compile(r"\s+")


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
    return extract_primary_stack(text, max_frames)


def extract_primary_stack(text: str, max_frames: int) -> List[str]:
    err_match = re.search(r"ERROR: AddressSanitizer: ([^\n]+)", text)
    lines = text.splitlines()
    start_line = 0
    if err_match:
        start_line = text[: err_match.start()].count("\n")

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

    if not stack:
        stack = re.findall(r"^\s*#\d+\s+.*$", text, flags=re.MULTILINE)[:max_frames]

    return stack


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


def normalize_hex_addresses(text: str) -> str:
    return HEX_RE.sub("0x*", text)


def canonicalize_frame(frame: str) -> str:
    out = FRAME_INDEX_RE.sub("", frame.strip())
    out = normalize_hex_addresses(out)
    out = SPACE_RE.sub(" ", out).strip()
    return out


def stack_signature(stack_frames: List[str], crash_sha1: str) -> str:
    canonical_stack = [canonicalize_frame(frame) for frame in stack_frames if frame.strip()]
    if canonical_stack:
        signature_source = "\n".join(canonical_stack)
    else:
        # Keep unmatched crashes distinct when no ASAN stack is available.
        signature_source = f"sha1:{crash_sha1}"
    return hashlib.sha1(signature_source.encode("utf-8")).hexdigest().lower()


def select_unique_stack_crashes(
    crash_files: List[Path],
    stack_by_sha1: Dict[str, List[str]],
) -> List[Tuple[Path, List[str], int]]:
    sig_to_index: Dict[str, int] = {}
    selected: List[Tuple[Path, List[str], int]] = []
    for crash in crash_files:
        crash_sha1 = hashlib.sha1(crash.read_bytes()).hexdigest().lower()
        stack_frames = stack_by_sha1.get(crash_sha1, [])
        sig = stack_signature(stack_frames, crash_sha1)
        if sig in sig_to_index:
            index = sig_to_index[sig]
            rep_crash, rep_stack, count = selected[index]
            selected[index] = (rep_crash, rep_stack, count + 1)
            continue

        sig_to_index[sig] = len(selected)
        selected.append((crash, stack_frames, 1))

    return selected


def fuzz_function_source(
    number: int,
    root_dir: Path,
    crash: Path,
    stack_frames: List[str],
    grouped_crashes: int,
) -> str:
    raw = crash.read_bytes()
    rel = crash.relative_to(root_dir).as_posix()
    sha1 = hashlib.sha1(raw).hexdigest().lower()
    normalized = normalize_script_bytes(raw)
    script_lines = normalized.split(b"\n")
    if not script_lines:
        script_lines = [b""]

    lines: List[str] = []
    lines.append(f"/* crash={rel}, sha1={sha1}, grouped_crashes={grouped_crashes}")
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
    selected_crashes: List[Tuple[Path, List[str], int]],
    target_numbers: List[int],
) -> int:
    text = fuzzing_c.read_text(encoding="utf-8", errors="replace").rstrip()

    generated_blocks = [
        fuzz_function_source(
            number,
            root_dir,
            crash,
            stack_frames,
            grouped_crashes,
        )
        for number, (crash, stack_frames, grouped_crashes) in zip(
            target_numbers, selected_crashes
        )
    ]

    if text:
        text += "\n\n" + "\n\n".join(generated_blocks) + "\n"
    else:
        text = "\n\n".join(generated_blocks) + "\n"

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


def fuzzing_testcases_span(text: str) -> Tuple[int, int]:
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
    return list_start, list_end


def parse_used_fuzzing_numbers(project_json: Path) -> Set[int]:
    text = project_json.read_text(encoding="utf-8")
    list_start, list_end = fuzzing_testcases_span(text)
    list_body = text[list_start + 1 : list_end]

    numbers: Set[int] = set()
    for value in re.findall(r'"([^"]+)"', list_body):
        if re.fullmatch(r"[1-9]\d*", value):
            numbers.add(int(value))
    return numbers


def allocate_fuzzing_numbers(used_numbers: Set[int], count: int) -> List[int]:
    allocated: List[int] = []
    candidate = 1
    while len(allocated) < count:
        if candidate not in used_numbers:
            allocated.append(candidate)
            used_numbers.add(candidate)
        candidate += 1
    return allocated


def update_fuzzing_testcases(project_json: Path, new_numbers: List[int]) -> None:
    text = project_json.read_text(encoding="utf-8")
    list_start, list_end = fuzzing_testcases_span(text)

    list_body = text[list_start + 1 : list_end]
    values = re.findall(r'"([^"]+)"', list_body)
    existing = set(values)
    for number in new_numbers:
        value = str(number)
        if value not in existing:
            values.append(value)
            existing.add(value)

    body = "\n" + ",\n".join(f'                "{value}"' for value in values) + "\n            "
    updated = text[: list_start + 1] + body + text[list_end:]

    project_json.write_text(updated, encoding="utf-8")

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

    crash_files = discover_crash_files(out_dir)
    if not crash_files:
        print(f"No crash files found under {out_dir}")
        return 1

    stack_by_sha1 = collect_stacks(asan_log_dir, args.stack_max_frames)
    unique_stack_crashes = select_unique_stack_crashes(crash_files, stack_by_sha1)
    used_numbers = parse_used_fuzzing_numbers(project_json)
    new_numbers = allocate_fuzzing_numbers(used_numbers, len(unique_stack_crashes))
    max_number = update_fuzzing_source(
        fuzzing_c, root, unique_stack_crashes, new_numbers
    )
    update_fuzzing_testcases(project_json, new_numbers)

    print(f"Discovered {len(crash_files)} crash files")
    print(f"Unique stack traces: {len(unique_stack_crashes)}")
    print(f"ASAN stacks matched: {len(stack_by_sha1)}")
    if len(new_numbers) == 1:
        print(f"Added fuzzing test: Fuzzing_{new_numbers[0]}")
    elif new_numbers == list(range(new_numbers[0], new_numbers[-1] + 1)):
        print(f"Added fuzzing tests: Fuzzing_{new_numbers[0]}..Fuzzing_{max_number}")
    else:
        values = ", ".join(f"Fuzzing_{n}" for n in new_numbers)
        print(f"Added fuzzing tests: {values}")
    print(f"Updated: {fuzzing_c}")
    print(f"Updated: {project_json}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
