#!/usr/bin/env python3
import argparse
import base64
import datetime as dt
import hashlib
import html
import json
import os
import re
import signal
import subprocess
from typing import Dict, List, Optional, Tuple

FRAME_RE = re.compile(r"^\s*#\d+\s+.*$")
FRAME_INDEX_RE = re.compile(r"^\s*#\d+\s+")
HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
SPACE_RE = re.compile(r"\s+")
LOG_STEM_RE = re.compile(r"([0-9a-f]{40})(?:_\d+)?$")


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
    except (TypeError, ValueError, AttributeError):
        return None


def parse_float(value: str) -> Optional[float]:
    try:
        return float(value.strip())
    except (TypeError, ValueError, AttributeError):
        return None


def discover_fuzzers(out_dir: str) -> List[str]:
    result: List[str] = []
    if not os.path.isdir(out_dir):
        return result
    for name in sorted(os.listdir(out_dir)):
        stats = os.path.join(out_dir, name, "fuzzer_stats")
        if os.path.isdir(os.path.join(out_dir, name)) and os.path.exists(stats):
            result.append(name)
    return result


def parse_afl_name(name: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for part in name.split(","):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        fields[key] = value
    return fields


def signal_name(sig_text: Optional[str]) -> str:
    if not sig_text:
        return "-"
    sig = parse_int(sig_text)
    if sig is None:
        return sig_text
    try:
        return signal.Signals(sig).name
    except ValueError:
        return f"SIG{sig}"


def classify_with_harness(harness: str, testcase: str) -> Tuple[str, int, str]:
    proc = subprocess.run(
        [harness, testcase],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        check=False,
        timeout=10,
    )
    stderr = proc.stderr.strip()
    if "ECS_INTERNAL_ERROR" in stderr:
        return ("ECS_INTERNAL_ERROR", proc.returncode, stderr)
    if proc.returncode < 0 or proc.returncode > 128:
        return ("Crash", proc.returncode, stderr)
    return ("Ignored", proc.returncode, stderr)


def bytes_preview(data: bytes, n: int = 64) -> Tuple[str, str]:
    chunk = data[:n]
    hx = chunk.hex(" ")
    txt = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
    return hx, txt


def html_escape(text: str) -> str:
    return html.escape(text, quote=True)


def normalize_hex_addresses(text: str) -> str:
    return HEX_RE.sub("0x*", text)


def canonicalize_frame(frame: str) -> str:
    out = FRAME_INDEX_RE.sub("", frame.strip())
    out = normalize_hex_addresses(out)
    out = SPACE_RE.sub(" ", out).strip()
    return out


def build_trace_signature(stack_text: str, fallback: str) -> Tuple[str, str]:
    frames = [line for line in stack_text.splitlines() if line.strip()]
    canonical_frames = [canonicalize_frame(frame) for frame in frames]
    if canonical_frames:
        source = "\n".join(canonical_frames)
    else:
        source = SPACE_RE.sub(" ", normalize_hex_addresses(fallback)).strip()
        if not source:
            source = "no-stack"
    return hashlib.sha1(source.encode("utf-8")).hexdigest(), source


def extract_stack_from_log(path: str, max_frames: int) -> List[str]:
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
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


def collect_stacks(asan_log_dir: str, max_frames: int) -> Dict[str, List[str]]:
    stacks: Dict[str, List[str]] = {}
    if not os.path.isdir(asan_log_dir):
        return stacks
    for name in sorted(os.listdir(asan_log_dir)):
        if not name.endswith(".log"):
            continue
        stem = name[:-4].lower()
        match = LOG_STEM_RE.fullmatch(stem)
        if not match:
            continue
        sha1 = match.group(1)
        frames = extract_stack_from_log(os.path.join(asan_log_dir, name), max_frames)
        if frames and sha1 not in stacks:
            stacks[sha1] = frames
    return stacks


def flecs_logo_data_uri() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    logo_path = os.path.normpath(
        os.path.join(script_dir, "..", "flecs", "docs", "img", "logo_small.png")
    )
    try:
        with open(logo_path, "rb") as f:
            raw = f.read()
    except OSError:
        return ""
    return "data:image/png;base64," + base64.b64encode(raw).decode("ascii")


def generate_report(
    out_dir: str,
    html_path: str,
    harness: Optional[str],
    preview_bytes: int,
    asan_log_dir: str,
    stack_max_frames: int,
) -> int:
    fuzzers = discover_fuzzers(out_dir)
    if not fuzzers:
        print(f"No AFL fuzzer outputs found in: {out_dir}")
        return 1

    stack_by_sha1 = collect_stacks(asan_log_dir, stack_max_frames)
    rows: List[Dict[str, str]] = []
    by_hash: Dict[str, Dict[str, object]] = {}
    for fuzzer in fuzzers:
        crash_dir = os.path.join(out_dir, fuzzer, "crashes")
        if not os.path.isdir(crash_dir):
            continue
        for name in sorted(os.listdir(crash_dir)):
            if name.startswith("README"):
                continue
            path = os.path.join(crash_dir, name)
            if not os.path.isfile(path):
                continue
            with open(path, "rb") as f:
                data = f.read()

            sha1 = hashlib.sha1(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
            fields = parse_afl_name(name)
            size = len(data)
            mtime = dt.datetime.fromtimestamp(os.path.getmtime(path), tz=dt.timezone.utc)
            mtime_text = mtime.isoformat().replace("+00:00", "Z")
            hex_preview, ascii_preview = bytes_preview(data, preview_bytes)
            script_text = data.decode("utf-8", errors="replace")

            triage = "-"
            triage_rc = "-"
            triage_stderr = ""
            if harness:
                try:
                    triage, rc, triage_stderr = classify_with_harness(harness, path)
                    triage_rc = str(rc)
                except subprocess.TimeoutExpired:
                    triage = "Timeout"
                    triage_rc = "timeout"
                    triage_stderr = ""

            row = {
                "worker": fuzzer,
                "name": name,
                "path": path,
                "id": fields.get("id", "-"),
                "sig": fields.get("sig", "-"),
                "sig_name": signal_name(fields.get("sig")),
                "src": fields.get("src", "-"),
                "time": fields.get("time", "-"),
                "execs": fields.get("execs", "-"),
                "op": fields.get("op", "-"),
                "rep": fields.get("rep", "-"),
                "size": str(size),
                "sha1": sha1,
                "sha256": sha256,
                "mtime": mtime_text,
                "triage": triage,
                "triage_rc": triage_rc,
                "triage_stderr": triage_stderr,
                "hex_preview": hex_preview,
                "ascii_preview": ascii_preview,
                "script_text": script_text,
                "stack_trace": "\n".join(stack_by_sha1.get(sha1, [])),
            }
            rows.append(row)

            if sha1 not in by_hash:
                by_hash[sha1] = {
                    "count": 0,
                    "workers": set(),
                    "example": row,
                }
            by_hash[sha1]["count"] = int(by_hash[sha1]["count"]) + 1
            by_hash[sha1]["workers"].add(fuzzer)

    rows.sort(key=lambda r: (r["worker"], r["name"]))
    browser_rows: List[Dict[str, object]] = []
    for row in rows:
        trace_sig, trace_source = build_trace_signature(
            row["stack_trace"],
            f"{row['sha1']} {row['triage']} {row['sig_name']}",
        )
        browser_rows.append(
            {
                "worker": row["worker"],
                "name": row["name"],
                "path": row["path"],
                "id": row["id"],
                "sig": row["sig"],
                "sig_name": row["sig_name"],
                "src": row["src"],
                "time": row["time"],
                "execs": row["execs"],
                "op": row["op"],
                "rep": row["rep"],
                "size": row["size"],
                "sha1": row["sha1"],
                "sha256": row["sha256"],
                "mtime": row["mtime"],
                "triage": row["triage"],
                "triage_rc": row["triage_rc"],
                "triage_stderr": row["triage_stderr"],
                "hex_preview": row["hex_preview"],
                "ascii_preview": row["ascii_preview"],
                "script_text": row["script_text"],
                "stack_trace": row["stack_trace"],
                "trace_sig": trace_sig,
                "trace_source": trace_source,
                "reproducer_count": int(by_hash[row["sha1"]]["count"]),
            }
        )

    trace_groups: Dict[str, Dict[str, object]] = {}
    for idx, row in enumerate(browser_rows):
        trace_sig = str(row["trace_sig"])
        if trace_sig not in trace_groups:
            trace_groups[trace_sig] = {
                "trace_sig": trace_sig,
                "trace_source": str(row["trace_source"]),
                "canonical_stack": str(row["stack_trace"]),
                "member_indexes": [],
                "workers": set(),
                "reproducer_map": {},
            }

        group = trace_groups[trace_sig]
        group["member_indexes"].append(idx)
        group["workers"].add(str(row["worker"]))

        reproducer_map: Dict[str, Dict[str, object]] = group["reproducer_map"]  # type: ignore[assignment]
        sha1 = str(row["sha1"])
        if sha1 not in reproducer_map:
            reproducer_map[sha1] = {"index": idx, "count": 0}
        reproducer_map[sha1]["count"] = int(reproducer_map[sha1]["count"]) + 1

    trace_group_rows: List[Dict[str, object]] = []
    for trace_sig, group in trace_groups.items():
        reproducers = list(group["reproducer_map"].items())
        reproducers.sort(key=lambda item: int(item[1]["index"]))
        rep_entries = []
        for sha1, data in reproducers:
            source_row = browser_rows[int(data["index"])]
            rep_entries.append(
                {
                    "index": int(data["index"]),
                    "sha1": sha1,
                    "worker": source_row["worker"],
                    "name": source_row["name"],
                    "count": int(data["count"]),
                }
            )

        first_index = int(reproducers[0][1]["index"]) if reproducers else -1
        first_row = browser_rows[first_index] if first_index >= 0 else {}
        trace_group_rows.append(
            {
                "trace_sig": trace_sig,
                "title": str(group["trace_source"]).split("\n", 1)[0],
                "trace_source": group["trace_source"],
                "stack_trace": group["canonical_stack"],
                "member_indexes": group["member_indexes"],
                "crash_reports": len(group["member_indexes"]),
                "unique_reproducers": len(reproducers),
                "workers": sorted(group["workers"]),
                "first_index": first_index,
                "first_name": first_row.get("name", ""),
                "first_worker": first_row.get("worker", ""),
                "first_sha1": first_row.get("sha1", ""),
                "reproducers": rep_entries,
            }
        )

    trace_group_rows.sort(
        key=lambda g: (
            -int(g["crash_reports"]),
            -int(g["unique_reproducers"]),
            str(g["trace_sig"]),
        )
    )

    crashes_json = json.dumps(browser_rows).replace("</", "<\\/")
    trace_groups_json = json.dumps(trace_group_rows).replace("</", "<\\/")
    logo_data_uri = flecs_logo_data_uri()

    styles = """
:root {
  --bg: #161b22;
  --panel: #1b222c;
  --panel-soft: #1a212a;
  --border: #334154;
  --text: #c9d2dd;
  --text-strong: #d7e0ea;
  --muted: #9caabc;
  --code-bg: #171d25;
}
html, body { height: 100%; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; padding: 20px; box-sizing: border-box; display: grid; grid-template-rows: auto minmax(0, 1fr); gap: 8px; line-height: 1.45; color: var(--text); background: var(--bg); overflow: hidden; }
h1, h2, h3 { margin-top: 28px; margin-bottom: 10px; color: var(--text-strong); font-weight: 600; letter-spacing: 0.01em; }
h1:first-of-type { margin: 0 0 2px 0; }
.page-title { display: flex; align-items: baseline; margin: 0 0 2px 0; line-height: 1.1; }
.page-title-logo { width: 0.85em; height: 0.85em; object-fit: contain; display: block; flex: none; transform: translateY(0.03em); }
.page-title span { padding-left: 12px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; background: var(--panel); }
th, td { border: 1px solid var(--border); padding: 7px 9px; vertical-align: top; }
th { background: #202834; text-align: left; color: #bcc8d6; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
code { color: #a8c2df; }
pre { white-space: pre-wrap; margin: 0; overflow-wrap: anywhere; color: var(--text); }
.muted { color: var(--muted); }
.small { font-size: 12px; }
.browser { display: grid; grid-template-columns: 360px minmax(0, 1fr); gap: 20px; min-height: 0; height: 100%; }
.pane { border: 1px solid var(--border); border-radius: 10px; background: var(--panel-soft); min-height: 0; overflow: hidden; box-shadow: 0 8px 24px rgba(0, 0, 0, 0.22); }
.sidebar { padding: 16px; display: flex; flex-direction: column; min-height: 0; }
.detail { padding: 16px; min-height: 0; overflow: auto; }
.detail h3 { margin-top: 16px; margin-bottom: 8px; }
.detail > h3:first-child { margin-top: 0; }
.tabs { display: flex; align-items: flex-end; gap: 2px; margin: 0 0 8px 0; padding: 0 0 6px 0; border-bottom: 1px solid #3f4d61; }
.tab-btn { appearance: none; border: none; border-bottom: 2px solid transparent; border-radius: 0; background: transparent; color: var(--muted); padding: 4px 8px; cursor: pointer; font-size: 12px; font-weight: 600; line-height: 1.2; white-space: nowrap; }
.tab-btn:hover { color: var(--text); }
.tab-btn:focus-visible { outline: 2px solid #6f8eb8; outline-offset: 2px; border-radius: 4px; }
.tab-btn.active { color: var(--text-strong); border-bottom-color: #7fa9dd; }
#crash-filter { width: 100%; box-sizing: border-box; padding: 10px; border: 1px solid #425067; border-radius: 8px; background: #161c24; color: var(--text); }
#crash-filter::placeholder { color: var(--muted); }
#crash-count { margin-top: 10px; }
#crash-list { list-style: none; padding: 0; margin: 12px 0 0 0; overflow-y: auto; overflow-x: hidden; flex: 1; min-height: 0; }
.crash-item { width: 100%; text-align: left; border: 1px solid #3a475b; border-radius: 8px; background: #1a222d; color: var(--text); padding: 10px; margin-bottom: 10px; cursor: pointer; overflow-wrap: anywhere; }
.crash-item:hover { border-color: #566682; background: #1d2733; }
.crash-item.selected { border-color: #6f8eb8; box-shadow: 0 0 0 1px #6f8eb8 inset; background: #243142; }
.crash-title { font-weight: 600; margin-bottom: 3px; color: var(--text-strong); }
.code-block { margin-top: 10px; border: 1px solid #37465a; border-radius: 8px; background: var(--code-bg); padding: 12px; max-height: 34vh; overflow: auto; }
#detail-script { max-height: none; overflow: visible; }
.link-list { list-style: none; padding: 0; margin: 10px 0 0 0; }
.link-list li { margin-bottom: 8px; }
.link-btn { border: none; background: transparent; color: #9ec4f0; cursor: pointer; padding: 0; font: inherit; text-align: left; }
.link-btn:hover { text-decoration: underline; }
.hidden { display: none; }
@media (max-width: 1000px) {
  body { display: block; padding: 20px; overflow: auto; }
  .browser { grid-template-columns: 1fr; min-height: auto; height: auto; }
  .pane { overflow: visible; }
  .detail { overflow: visible; }
  #crash-list { max-height: 36vh; }
}
"""

    with open(html_path, "w", encoding="utf-8") as out:
        out.write("<!doctype html><html><head><meta charset='utf-8'>")
        out.write("<meta name='viewport' content='width=device-width, initial-scale=1'>")
        out.write("<title>Flecs AFL Crash Report</title>")
        out.write(f"<style>{styles}</style></head><body>")

        out.write("<h1 class='page-title'>")
        if logo_data_uri:
            out.write(
                f"<img class='page-title-logo' src='{logo_data_uri}' alt='' aria-hidden='true'>"
            )
        out.write("<span>Flecs crash browser</span></h1>")
        if not rows:
            out.write("<p class='muted'>No crash files found in this AFL output.</p>")
        else:
            out.write("<div class='browser'>")
            out.write("<div class='pane sidebar'>")
            out.write("<div class='tabs' role='tablist' aria-label='Crash browser views'>")
            out.write("<button id='tab-traces' class='tab-btn' role='tab' aria-selected='false' type='button'>Stack Traces</button>")
            out.write("<button id='tab-crashes' class='tab-btn' role='tab' aria-selected='false' type='button'>All Crashes</button>")
            out.write("</div>")
            out.write("<input id='crash-filter' type='text' placeholder='Filter by worker, sig, op, hash, file...'>")
            out.write("<div id='crash-count' class='small muted'></div>")
            out.write("<ul id='crash-list'></ul>")
            out.write("</div>")
            out.write("<div class='pane detail'>")
            out.write("<h3 id='detail-title'>Select a crash</h3>")
            out.write("<div id='detail-stack-wrap'>")
            out.write("<h3>Stack Trace</h3>")
            out.write("<pre id='detail-stack' class='code-block'></pre>")
            out.write("</div>")
            out.write("<h3>Reproducer</h3>")
            out.write("<pre id='detail-script' class='code-block'></pre>")
            out.write("<h3>Byte Preview</h3>")
            out.write("<pre id='detail-bytes' class='code-block'></pre>")
            out.write("<div id='detail-stderr-wrap'>")
            out.write("<h3>Harness Stderr</h3>")
            out.write("<pre id='detail-stderr' class='code-block'></pre>")
            out.write("</div>")
            out.write("<div id='detail-related-wrap' class='hidden'>")
            out.write("<h3>Other Reproducers</h3>")
            out.write("<ul id='detail-related' class='link-list'></ul>")
            out.write("</div>")
            out.write("</div>")
            out.write("</div>")

            out.write("<script>")
            out.write(f"const crashes = {crashes_json};")
            out.write(f"const traceGroups = {trace_groups_json};")
            out.write(
                """
const listEl = document.getElementById("crash-list");
const filterEl = document.getElementById("crash-filter");
const countEl = document.getElementById("crash-count");
const tabTracesEl = document.getElementById("tab-traces");
const tabCrashesEl = document.getElementById("tab-crashes");
const detailTitleEl = document.getElementById("detail-title");
const detailScriptEl = document.getElementById("detail-script");
const detailBytesEl = document.getElementById("detail-bytes");
const detailStackWrapEl = document.getElementById("detail-stack-wrap");
const detailStackEl = document.getElementById("detail-stack");
const detailStderrWrapEl = document.getElementById("detail-stderr-wrap");
const detailStderrEl = document.getElementById("detail-stderr");
const detailRelatedWrapEl = document.getElementById("detail-related-wrap");
const detailRelatedEl = document.getElementById("detail-related");

let mode = traceGroups.length ? "traces" : "crashes";
let selectedTrace = traceGroups.length ? 0 : -1;
let selectedCrash = crashes.length ? 0 : -1;

function firstFrameFunctionName(traceText) {
  if (!traceText) return "";
  const firstLine = traceText
    .split("\\n")
    .map((line) => line.trim())
    .find((line) => line.length > 0);
  if (!firstLine) return "";

  const withoutIndex = firstLine.replace(/^#\\d+\\s+/, "").trim();
  const inMatch = withoutIndex.match(/\\bin\\s+([^\\s(]+)/);
  if (inMatch) return inMatch[1];

  const withoutAddr = withoutIndex.replace(/^0x[0-9a-fA-F]+\\s+/, "");
  const symbolMatch = withoutAddr.match(/^([^\\s(]+)/);
  if (symbolMatch) return symbolMatch[1];

  return "";
}

function cleanTraceListTitle(titleText) {
  if (!titleText) return "";
  return titleText.replace(/^0x(?:\\*|[0-9a-fA-F]+)\\s+in\\s+/, "");
}

function syncTabs() {
  tabTracesEl.classList.toggle("active", mode === "traces");
  tabCrashesEl.classList.toggle("active", mode === "crashes");
  tabTracesEl.setAttribute("aria-selected", mode === "traces" ? "true" : "false");
  tabCrashesEl.setAttribute("aria-selected", mode === "crashes" ? "true" : "false");
}

function currentSelected() {
  return mode === "traces" ? selectedTrace : selectedCrash;
}

function setCurrentSelected(value) {
  if (mode === "traces") {
    selectedTrace = value;
  } else {
    selectedCrash = value;
  }
}

function setMode(nextMode) {
  if (nextMode !== "traces" && nextMode !== "crashes") return;
  mode = nextMode;
  if (mode === "traces" && selectedTrace < 0 && traceGroups.length) {
    selectedTrace = 0;
  }
  if (mode === "crashes" && selectedCrash < 0 && crashes.length) {
    selectedCrash = 0;
  }
  syncTabs();
  renderList();
  renderDetail();
}

function visibleCrashIndexes() {
  const q = filterEl.value.trim().toLowerCase();
  if (!q) return crashes.map((_, i) => i);
  const out = [];
  for (let i = 0; i < crashes.length; i++) {
    const c = crashes[i];
    const haystack = [
      c.worker, c.name, c.path, c.id, c.sig, c.sig_name, c.src, c.time,
      c.execs, c.op, c.rep, c.sha1, c.sha256, c.triage, c.stack_trace,
      c.reproducer_count
    ].join(" ").toLowerCase();
    if (haystack.includes(q)) out.push(i);
  }
  return out;
}

function visibleTraceIndexes() {
  const q = filterEl.value.trim().toLowerCase();
  if (!q) return traceGroups.map((_, i) => i);
  const out = [];
  for (let i = 0; i < traceGroups.length; i++) {
    const g = traceGroups[i];
    const workers = (g.workers || []).join(" ");
    const reproducers = (g.reproducers || []).map((r) => `${r.worker} ${r.name} ${r.sha1}`).join(" ");
    const haystack = [
      g.trace_sig, g.title, g.trace_source, g.stack_trace,
      g.crash_reports, g.unique_reproducers, workers, reproducers
    ].join(" ").toLowerCase();
    if (haystack.includes(q)) out.push(i);
  }
  return out;
}

function visibleIndexes() {
  return mode === "traces" ? visibleTraceIndexes() : visibleCrashIndexes();
}

function renderList() {
  const visible = visibleIndexes();
  if (!visible.includes(currentSelected())) {
    setCurrentSelected(visible.length ? visible[0] : -1);
  }

  if (mode === "traces") {
    countEl.textContent = `Showing ${visible.length} of ${traceGroups.length} unique stack traces`;
  } else {
    countEl.textContent = `Showing ${visible.length} of ${crashes.length} crashes`;
  }
  listEl.textContent = "";

  for (const idx of visible) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "crash-item";
    if (idx === currentSelected()) btn.classList.add("selected");
    btn.addEventListener("click", () => {
      setCurrentSelected(idx);
      renderList();
      renderDetail();
    });

    if (mode === "traces") {
      const g = traceGroups[idx];
      const title = document.createElement("div");
      title.className = "crash-title";
      title.textContent = cleanTraceListTitle(g.title) || `trace:${g.trace_sig.slice(0, 12)}`;
      btn.appendChild(title);

      const line1 = document.createElement("div");
      line1.className = "small muted";
      line1.textContent = `${g.crash_reports} crash reports  ${g.unique_reproducers} reproducers`;
      btn.appendChild(line1);
    } else {
      const c = crashes[idx];
      const title = document.createElement("div");
      title.className = "crash-title";
      title.textContent = `${c.worker}/${c.name}`;
      btn.appendChild(title);

      const line1 = document.createElement("div");
      line1.className = "small muted";
      line1.textContent = `sig=${c.sig} (${c.sig_name})  op=${c.op}  size=${c.size}`;
      btn.appendChild(line1);

      const line2 = document.createElement("div");
      line2.className = "small muted";
      line2.textContent = `${c.sha1.slice(0, 12)}...`;
      btn.appendChild(line2);

      const line3 = document.createElement("div");
      line3.className = "small muted";
      line3.textContent = `reproducer appears in ${c.reproducer_count} crash reports`;
      btn.appendChild(line3);
    }

    li.appendChild(btn);
    listEl.appendChild(li);
  }

  const selectedEl = listEl.querySelector(".crash-item.selected");
  if (selectedEl) {
    selectedEl.scrollIntoView({ block: "nearest" });
  }
}

function renderNoSelection() {
  detailTitleEl.textContent = mode === "traces" ? "No trace selected" : "No crash selected";
  detailScriptEl.textContent = "";
  detailBytesEl.textContent = "";
  detailStackWrapEl.classList.add("hidden");
  detailStderrWrapEl.classList.add("hidden");
  detailRelatedWrapEl.classList.add("hidden");
  detailRelatedEl.textContent = "";
}

function renderCrashDetail(index) {
  if (index < 0 || index >= crashes.length) {
    renderNoSelection();
    return;
  }
  const c = crashes[index];
  detailTitleEl.textContent = `${c.worker}/${c.name} (sig=${c.sig}, ${c.sig_name})`;
  detailScriptEl.textContent = c.script_text || "";
  detailBytesEl.textContent = `hex: ${c.hex_preview}\\n\\nascii: ${c.ascii_preview}`;

  if (c.stack_trace && c.stack_trace.trim()) {
    detailStackEl.textContent = c.stack_trace;
    detailStackWrapEl.classList.remove("hidden");
  } else {
    detailStackEl.textContent = "";
    detailStackWrapEl.classList.add("hidden");
  }

  if (c.triage_stderr && c.triage_stderr.trim()) {
    detailStderrEl.textContent = c.triage_stderr;
    detailStderrWrapEl.classList.remove("hidden");
  } else {
    detailStderrEl.textContent = "";
    detailStderrWrapEl.classList.add("hidden");
  }

  detailRelatedWrapEl.classList.add("hidden");
  detailRelatedEl.textContent = "";
}

function renderTraceDetail(index) {
  if (index < 0 || index >= traceGroups.length) {
    renderNoSelection();
    return;
  }
  const g = traceGroups[index];
  if (g.first_index < 0 || g.first_index >= crashes.length) {
    renderNoSelection();
    return;
  }

  const first = crashes[g.first_index];
  const traceName = firstFrameFunctionName(g.stack_trace) || `trace:${g.trace_sig.slice(0, 12)}`;
  detailTitleEl.textContent = `${traceName} (${g.crash_reports} crashes, ${g.unique_reproducers} reproducers)`;

  detailScriptEl.textContent = first.script_text || "";
  detailBytesEl.textContent = `hex: ${first.hex_preview}\\n\\nascii: ${first.ascii_preview}`;

  if (g.trace_source && g.trace_source.trim()) {
    detailStackEl.textContent = g.trace_source;
    detailStackWrapEl.classList.remove("hidden");
  } else {
    detailStackEl.textContent = "";
    detailStackWrapEl.classList.add("hidden");
  }

  if (first.triage_stderr && first.triage_stderr.trim()) {
    detailStderrEl.textContent = first.triage_stderr;
    detailStderrWrapEl.classList.remove("hidden");
  } else {
    detailStderrEl.textContent = "";
    detailStderrWrapEl.classList.add("hidden");
  }

  const others = (g.reproducers || []).filter((r) => r.index !== g.first_index);
  detailRelatedEl.textContent = "";
  if (!others.length) {
    detailRelatedWrapEl.classList.add("hidden");
    return;
  }

  for (const rep of others) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "link-btn";
    btn.textContent = `${rep.worker}/${rep.name} (${rep.count} crash reports, ${rep.sha1.slice(0, 12)}...)`;
    btn.addEventListener("click", () => {
      selectedCrash = rep.index;
      setMode("crashes");
    });
    li.appendChild(btn);
    detailRelatedEl.appendChild(li);
  }
  detailRelatedWrapEl.classList.remove("hidden");
}

function renderDetail() {
  if (currentSelected() < 0) {
    renderNoSelection();
    return;
  }
  if (mode === "traces") {
    renderTraceDetail(selectedTrace);
  } else {
    renderCrashDetail(selectedCrash);
  }
}

tabTracesEl.addEventListener("click", () => {
  setMode("traces");
});

tabCrashesEl.addEventListener("click", () => {
  setMode("crashes");
});

filterEl.addEventListener("input", () => {
  renderList();
  renderDetail();
});

function moveSelection(delta) {
  const visible = visibleIndexes();
  if (!visible.length) {
    if (currentSelected() !== -1) {
      setCurrentSelected(-1);
      renderList();
      renderDetail();
    }
    return;
  }

  let pos = visible.indexOf(currentSelected());
  if (pos < 0) {
    pos = delta > 0 ? -1 : visible.length;
  }

  const nextPos = Math.max(0, Math.min(visible.length - 1, pos + delta));
  const nextSelected = visible[nextPos];
  if (nextSelected === currentSelected()) {
    return;
  }

  setCurrentSelected(nextSelected);
  renderList();
  renderDetail();
}

document.addEventListener("keydown", (event) => {
  if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey) {
    return;
  }
  if (event.key !== "ArrowUp" && event.key !== "ArrowDown") {
    return;
  }

  const target = event.target;
  if (target && (target.tagName === "TEXTAREA" || target.isContentEditable)) {
    return;
  }
  if (target && target.tagName === "INPUT" && target !== filterEl) {
    return;
  }

  event.preventDefault();
  moveSelection(event.key === "ArrowDown" ? 1 : -1);
});

syncTabs();
renderList();
renderDetail();
"""
            )
            out.write("</script>")
        out.write("</body></html>")

    print(f"Wrote HTML crash report: {html_path}")
    return 0
def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AFL crash HTML report")
    parser.add_argument("--out", default="out", help="AFL output directory")
    parser.add_argument(
        "--html",
        default=None,
        help="Output HTML path (default: <out>/crash_report.html)",
    )
    parser.add_argument(
        "--harness",
        default=None,
        help="Optional harness binary for reproducing and classifying crashes",
    )
    parser.add_argument(
        "--preview-bytes",
        type=int,
        default=64,
        help="Number of bytes shown in hex/ascii previews",
    )
    parser.add_argument(
        "--asan-log-dir",
        default=None,
        help="Directory containing generated ASAN logs keyed by SHA1 (default: <out>/asan_report/logs)",
    )
    parser.add_argument(
        "--stack-max-frames",
        type=int,
        default=12,
        help="Maximum stack frames loaded from each ASAN log",
    )
    args = parser.parse_args()

    out_dir = os.path.abspath(args.out)
    html_path = os.path.abspath(args.html) if args.html else os.path.join(out_dir, "crash_report.html")
    asan_log_dir = os.path.abspath(args.asan_log_dir) if args.asan_log_dir else os.path.join(out_dir, "asan_report", "logs")

    os.makedirs(os.path.dirname(html_path), exist_ok=True)
    return generate_report(
        out_dir,
        html_path,
        args.harness,
        args.preview_bytes,
        asan_log_dir,
        args.stack_max_frames,
    )


if __name__ == "__main__":
    raise SystemExit(main())
