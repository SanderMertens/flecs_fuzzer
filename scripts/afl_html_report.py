#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import html
import json
import os
import signal
import subprocess
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


def generate_report(
    out_dir: str,
    html_path: str,
    harness: Optional[str],
    preview_bytes: int,
) -> int:
    fuzzers = discover_fuzzers(out_dir)
    if not fuzzers:
        print(f"No AFL fuzzer outputs found in: {out_dir}")
        return 1

    rows: List[Dict[str, str]] = []
    by_hash: Dict[str, Dict[str, object]] = {}
    fuzzer_stats: Dict[str, Dict[str, str]] = {}
    total_execs = 0
    total_execs_per_sec = 0.0
    max_paths_total: Optional[int] = None

    for fuzzer in fuzzers:
        stats = parse_stats(os.path.join(out_dir, fuzzer, "fuzzer_stats"))
        fuzzer_stats[fuzzer] = stats
        execs_done = parse_int(stats.get("execs_done", ""))
        if execs_done is not None:
            total_execs += execs_done
        execs_per_sec = parse_float(stats.get("execs_per_sec", ""))
        if execs_per_sec is not None:
            total_execs_per_sec += execs_per_sec
        paths_total = parse_int(stats.get("paths_total", ""))
        if paths_total is not None:
            max_paths_total = paths_total if max_paths_total is None else max(max_paths_total, paths_total)

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
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    summary = [
        ("Generated (UTC)", now),
        ("Output directory", out_dir),
        ("HTML path", html_path),
        ("Fuzzers", ", ".join(fuzzers)),
        ("Worker count", str(len(fuzzers))),
        ("Total crash files", str(len(rows))),
        ("Unique crash contents (SHA1)", str(len(by_hash))),
        ("Executions (sum)", str(total_execs) if total_execs else "unknown"),
        ("Exec/sec (sum)", str(round(total_execs_per_sec, 2)) if total_execs_per_sec else "unknown"),
        ("Paths total (max)", str(max_paths_total) if max_paths_total is not None else "unknown"),
        ("Harness triage", harness if harness else "disabled"),
    ]

    browser_rows = [
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
        }
        for row in rows
    ]
    crashes_json = json.dumps(browser_rows).replace("</", "<\\/")

    styles = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 24px; color: #e6edf3; background: #0d1117; }
h1, h2, h3 { margin-top: 24px; margin-bottom: 8px; color: #f0f6fc; }
table { border-collapse: collapse; width: 100%; font-size: 13px; background: #111821; }
th, td { border: 1px solid #273142; padding: 6px 8px; vertical-align: top; }
th { background: #151e2b; text-align: left; color: #d2dae3; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
code { color: #9ecbff; }
pre { white-space: pre-wrap; margin: 0; overflow-wrap: anywhere; color: #e6edf3; }
.muted { color: #9aa7b8; }
.pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; border: 1px solid transparent; }
.pill.crash { background: #4c1f24; color: #ffb8bf; border-color: #713039; }
.pill.internal { background: #4a3a16; color: #ffd89a; border-color: #6b5422; }
.pill.ignored { background: #1f2c3c; color: #b7c9dd; border-color: #30455f; }
.pill.timeout { background: #2d2f35; color: #c5c9d1; border-color: #454a54; }
.small { font-size: 12px; }
.browser { display: grid; grid-template-columns: 360px minmax(0, 1fr); gap: 16px; min-height: 70vh; }
.pane { border: 1px solid #273142; border-radius: 8px; background: #111821; min-height: 0; box-shadow: 0 6px 18px rgba(0, 0, 0, 0.3); }
.sidebar { padding: 12px; display: flex; flex-direction: column; }
.detail { padding: 12px; overflow: auto; }
#crash-filter { width: 100%; box-sizing: border-box; padding: 8px; border: 1px solid #3b4b62; border-radius: 6px; background: #0d1117; color: #e6edf3; }
#crash-filter::placeholder { color: #8190a3; }
#crash-count { margin-top: 8px; }
#crash-list { list-style: none; padding: 0; margin: 10px 0 0 0; overflow: auto; flex: 1; min-height: 0; }
.crash-item { width: 100%; text-align: left; border: 1px solid #2f3c50; border-radius: 6px; background: #0d141f; color: #e6edf3; padding: 8px; margin-bottom: 8px; cursor: pointer; }
.crash-item:hover { border-color: #4c6484; background: #111b2a; }
.crash-item.selected { border-color: #4b8cff; box-shadow: 0 0 0 1px #4b8cff inset; background: #162338; }
.crash-title { font-weight: 600; margin-bottom: 2px; color: #f0f6fc; }
.meta-table th { width: 190px; background: #0f1723; }
.code-block { margin-top: 8px; border: 1px solid #2a3647; border-radius: 6px; background: #0b1018; padding: 10px; max-height: 34vh; overflow: auto; }
.hidden { display: none; }
@media (max-width: 1000px) {
  .browser { grid-template-columns: 1fr; min-height: auto; }
  #crash-list { max-height: 32vh; }
}
"""

    with open(html_path, "w", encoding="utf-8") as out:
        out.write("<!doctype html><html><head><meta charset='utf-8'>")
        out.write("<meta name='viewport' content='width=device-width, initial-scale=1'>")
        out.write("<title>Flecs AFL Crash Report</title>")
        out.write(f"<style>{styles}</style></head><body>")

        out.write("<h1>Flecs AFL Crash Report</h1>")
        out.write("<table>")
        for k, v in summary:
            out.write("<tr>")
            out.write(f"<th style='width:260px'>{html_escape(k)}</th>")
            out.write(f"<td>{html_escape(v)}</td>")
            out.write("</tr>")
        out.write("</table>")

        out.write("<h2>Fuzzer Stats</h2>")
        out.write("<table><tr><th>Worker</th><th>execs_done</th><th>execs_per_sec</th><th>paths_total</th><th>cycles_done</th><th>last_update</th></tr>")
        for worker in fuzzers:
            stats = fuzzer_stats.get(worker, {})
            out.write("<tr>")
            out.write(f"<td>{html_escape(worker)}</td>")
            out.write(f"<td>{html_escape(stats.get('execs_done', '-'))}</td>")
            out.write(f"<td>{html_escape(stats.get('execs_per_sec', '-'))}</td>")
            out.write(f"<td>{html_escape(stats.get('paths_total', '-'))}</td>")
            out.write(f"<td>{html_escape(stats.get('cycles_done', '-'))}</td>")
            out.write(f"<td>{html_escape(stats.get('last_update', '-'))}</td>")
            out.write("</tr>")
        out.write("</table>")

        out.write("<h2>Crash Browser</h2>")
        if not rows:
            out.write("<p class='muted'>No crash files found in this AFL output.</p>")
        else:
            out.write("<div class='browser'>")
            out.write("<div class='pane sidebar'>")
            out.write("<input id='crash-filter' type='text' placeholder='Filter by worker, sig, op, hash, file...'>")
            out.write("<div id='crash-count' class='small muted'></div>")
            out.write("<ul id='crash-list'></ul>")
            out.write("</div>")
            out.write("<div class='pane detail'>")
            out.write("<h3 id='detail-title'>Select a crash</h3>")
            out.write("<table id='detail-meta' class='meta-table'></table>")
            out.write("<h3>Reproducer Script</h3>")
            out.write("<pre id='detail-script' class='code-block'></pre>")
            out.write("<h3>Byte Preview</h3>")
            out.write("<pre id='detail-bytes' class='code-block'></pre>")
            out.write("<div id='detail-stderr-wrap'>")
            out.write("<h3>Harness Stderr</h3>")
            out.write("<pre id='detail-stderr' class='code-block'></pre>")
            out.write("</div>")
            out.write("</div>")
            out.write("</div>")

            out.write("<script>")
            out.write(f"const crashes = {crashes_json};")
            out.write(
                """
const listEl = document.getElementById("crash-list");
const filterEl = document.getElementById("crash-filter");
const countEl = document.getElementById("crash-count");
const detailTitleEl = document.getElementById("detail-title");
const detailMetaEl = document.getElementById("detail-meta");
const detailScriptEl = document.getElementById("detail-script");
const detailBytesEl = document.getElementById("detail-bytes");
const detailStderrWrapEl = document.getElementById("detail-stderr-wrap");
const detailStderrEl = document.getElementById("detail-stderr");

let selected = crashes.length ? 0 : -1;

function triageClass(value) {
  if (value === "Crash") return "crash";
  if (value === "ECS_INTERNAL_ERROR") return "internal";
  if (value === "Timeout") return "timeout";
  return "ignored";
}

function visibleIndexes() {
  const q = filterEl.value.trim().toLowerCase();
  if (!q) return crashes.map((_, i) => i);
  const out = [];
  for (let i = 0; i < crashes.length; i++) {
    const c = crashes[i];
    const haystack = [
      c.worker, c.name, c.path, c.id, c.sig, c.sig_name, c.src, c.time,
      c.execs, c.op, c.rep, c.sha1, c.sha256, c.triage
    ].join(" ").toLowerCase();
    if (haystack.includes(q)) out.push(i);
  }
  return out;
}

function renderList() {
  const visible = visibleIndexes();
  if (!visible.includes(selected)) {
    selected = visible.length ? visible[0] : -1;
  }

  countEl.textContent = `Showing ${visible.length} of ${crashes.length} crashes`;
  listEl.textContent = "";

  for (const idx of visible) {
    const c = crashes[idx];
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "crash-item";
    if (idx === selected) btn.classList.add("selected");
    btn.addEventListener("click", () => {
      selected = idx;
      renderList();
      renderDetail();
    });

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

    const pill = document.createElement("span");
    pill.className = `pill ${triageClass(c.triage)}`;
    pill.textContent = c.triage;
    btn.appendChild(pill);

    li.appendChild(btn);
    listEl.appendChild(li);
  }
}

function renderMetaTable(c) {
  detailMetaEl.textContent = "";
  const meta = [
    ["Worker", c.worker],
    ["File", c.name],
    ["Path", c.path],
    ["Signal", `${c.sig} (${c.sig_name})`],
    ["Source", c.src],
    ["Time", c.time],
    ["Execs", c.execs],
    ["Operation", c.op],
    ["Repeat", c.rep],
    ["Size", c.size],
    ["Modified (UTC)", c.mtime],
    ["SHA1", c.sha1],
    ["SHA256", c.sha256],
    ["Triage", `${c.triage} (rc=${c.triage_rc})`]
  ];
  for (const [k, v] of meta) {
    const tr = document.createElement("tr");
    const th = document.createElement("th");
    const td = document.createElement("td");
    th.textContent = k;
    td.textContent = v;
    tr.appendChild(th);
    tr.appendChild(td);
    detailMetaEl.appendChild(tr);
  }
}

function renderDetail() {
  if (selected < 0 || selected >= crashes.length) {
    detailTitleEl.textContent = "No crash selected";
    detailMetaEl.textContent = "";
    detailScriptEl.textContent = "";
    detailBytesEl.textContent = "";
    detailStderrWrapEl.classList.add("hidden");
    return;
  }

  const c = crashes[selected];
  detailTitleEl.textContent = `${c.worker}/${c.name}`;
  renderMetaTable(c);
  detailScriptEl.textContent = c.script_text || "";
  detailBytesEl.textContent = `hex: ${c.hex_preview}\\n\\nascii: ${c.ascii_preview}`;

  if (c.triage_stderr && c.triage_stderr.trim()) {
    detailStderrEl.textContent = c.triage_stderr;
    detailStderrWrapEl.classList.remove("hidden");
  } else {
    detailStderrEl.textContent = "";
    detailStderrWrapEl.classList.add("hidden");
  }
}

filterEl.addEventListener("input", () => {
  renderList();
  renderDetail();
});

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
    args = parser.parse_args()

    out_dir = os.path.abspath(args.out)
    html_path = os.path.abspath(args.html) if args.html else os.path.join(out_dir, "crash_report.html")

    os.makedirs(os.path.dirname(html_path), exist_ok=True)
    return generate_report(out_dir, html_path, args.harness, args.preview_bytes)


if __name__ == "__main__":
    raise SystemExit(main())
