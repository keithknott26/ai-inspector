#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""AI Inspector MCP server: capture analysis for agents, without Wireshark's GUI.

Speaks the Model Context Protocol over stdio (JSON-RPC 2.0, no third-party
packages) and answers every call by running TShark with the AI Inspector engine
plugin loaded. Nothing is sent anywhere: the analysis is local and read-only.

Tools:
  analyze_capture     capture-level summary (counts, timeline, hosts, inventory)
  get_findings        findings, filtered by severity, category, protocol or text
  get_frame_findings  the engine's findings for one frame
  run_filter          packets matching a Wireshark display filter
  get_frame           one frame's decoded protocol tree
  get_report          the engine's full plain-text report

Configuration:
  AI_INSPECTOR_TSHARK   tshark binary to use (default: the development build, then PATH)
  AI_INSPECTOR_PLUGINS  extra plugin directory passed to tshark
  AI_INSPECTOR_ROOTS    ':'-separated directories; captures must live under one
                        of them (default: any readable path)
  AI_INSPECTOR_TIMEOUT  seconds per tshark run (default 120)

Usage:
  tools/mcp_server.py               # stdio server, for an MCP client
  tools/mcp_server.py --self-test   # check the wiring and exit
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "ai-inspector"
SERVER_VERSION = "1.3.0"  # keep in step with cmake/AIInspectorVersion.cmake

MAX_OUTPUT_BYTES = 8 * 1024 * 1024
SEVERITIES = {"info": 1, "note": 2, "warning": 3, "warn": 3, "error": 4}

REPO_ROOT = Path(__file__).resolve().parent.parent


class ToolError(Exception):
    """A failure the model should see and can act on."""


class TsharkError(ToolError):
    """TShark exited non-zero. Carries the exit code so callers can tell an
    invalid display filter (exit 4) from a real failure."""

    def __init__(self, returncode, message):
        super().__init__("tshark failed (exit %d): %s" % (returncode, message or "no message"))
        self.returncode = returncode
        self.message = message


# Chatter TShark prints before it gets to the point.
NOISE = ("JSON Dictionary", "Running as user", "This could be dangerous", "Capturing on ")


def clean_stderr(text):
    """Drops TShark's startup chatter so only the real message is left."""
    keep = [l for l in text.splitlines()
            if l.strip() and not l.lstrip().startswith("** (") and not any(n in l for n in NOISE)]
    return "\n".join(keep).strip() or text.strip()


# --------------------------------------------------------------------- tshark

def tshark_path():
    explicit = os.environ.get("AI_INSPECTOR_TSHARK")
    if explicit:
        if not Path(explicit).exists():
            raise ToolError("AI_INSPECTOR_TSHARK points at %s, which does not exist." % explicit)
        return explicit
    for candidate in (REPO_ROOT / "build-development" / "run" / "tshark",
                      REPO_ROOT / "build-development" / "run" / "tshark.exe"):
        if candidate.exists():
            return str(candidate)
    found = shutil.which("tshark")
    if not found:
        raise ToolError("tshark was not found. Build the development tree (tools/build-development.sh) "
                        "or set AI_INSPECTOR_TSHARK.")
    return found


def capture_path(raw):
    if not raw or not str(raw).strip():
        raise ToolError("Pass the path of a capture file.")
    p = Path(str(raw)).expanduser()
    try:
        p = p.resolve(strict=True)
    except OSError:
        raise ToolError("No such capture file: %s" % raw)
    if not p.is_file():
        raise ToolError("%s is not a file." % p)
    roots = [r for r in os.environ.get("AI_INSPECTOR_ROOTS", "").split(os.pathsep) if r]
    if roots and not any(_under(p, Path(r).expanduser().resolve()) for r in roots):
        raise ToolError("%s is outside the directories this server may read (AI_INSPECTOR_ROOTS)." % p)
    return p


def _under(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def run_tshark(args, timeout=None):
    cmd = [tshark_path()]
    plugins = os.environ.get("AI_INSPECTOR_PLUGINS")
    if plugins:
        cmd += ["--plugin-dir", plugins]
    cmd += args
    try:
        p = subprocess.run(cmd, capture_output=True,
                           timeout=timeout or float(os.environ.get("AI_INSPECTOR_TIMEOUT", "120")))
    except subprocess.TimeoutExpired:
        raise ToolError("tshark did not finish in time. Try a smaller capture or raise AI_INSPECTOR_TIMEOUT.")
    except OSError as e:
        raise ToolError("Could not run tshark: %s" % e)
    out = p.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
    err = clean_stderr(p.stderr[:20000].decode("utf-8", "replace"))
    if p.returncode != 0:
        raise TsharkError(p.returncode, err)
    return out, err


# ----------------------------------------------------------------- engine data

_summary_cache = {}


def summary(path):
    """The engine's JSON summary for a capture, cached per file revision."""
    key = (str(path), path.stat().st_mtime_ns, path.stat().st_size)
    hit = _summary_cache.get(key)
    if hit is not None:
        return hit
    try:
        out, err = run_tshark(["-r", str(path), "-q", "-z", "ai_inspector,json"])
    except ToolError as e:
        if "Invalid -z argument" in str(e):
            raise ToolError("This tshark does not have the AI Inspector engine plugin. Build the development tree "
                            "(tools/build-development.sh) and point AI_INSPECTOR_TSHARK at "
                            "build-development/run/tshark, or set AI_INSPECTOR_PLUGINS to the directory holding "
                            "ai_inspector_engine.")
        raise
    text = out.strip()
    start = text.find("{")
    if start < 0:
        raise ToolError("The AI Inspector engine produced no output. Is the ai_inspector_engine plugin "
                        "loaded by this tshark? %s" % (err or ""))
    try:
        data = json.loads(text[start:])
    except json.JSONDecodeError as e:
        raise ToolError("The engine's JSON output could not be parsed: %s" % e)
    _summary_cache.clear()  # one capture at a time keeps memory flat
    _summary_cache[key] = data
    return data


def filtered_findings(data, args):
    min_sev = SEVERITIES.get(str(args.get("min_severity", "")).strip().lower(), 0)
    category = str(args.get("category", "")).strip().lower()
    protocol = str(args.get("protocol", "")).strip().lower()
    contains = str(args.get("contains", "")).strip().lower()
    offset = max(0, int(args.get("offset", 0) or 0))
    limit = max(1, min(int(args.get("limit", 25) or 25), 200))

    matched, out = 0, []
    for f in data.get("findings", []):
        if min_sev and int(f.get("severity_level", 0)) < min_sev:
            continue
        if category and str(f.get("category", "")).lower() != category:
            continue
        if protocol and protocol not in str(f.get("protocol", "")).lower():
            continue
        if contains and contains not in " ".join(
                str(f.get(k, "")) for k in ("id", "title", "detail")).lower():
            continue
        matched += 1
        if matched > offset and len(out) < limit:
            out.append(f)
    return {"matched": matched, "returned": len(out), "offset": offset,
            "total_findings": len(data.get("findings", [])), "findings": out}


# ----------------------------------------------------------------------- tools

TOOLS = [
    {
        "name": "analyze_capture",
        "description": "Analyze a capture file with the AI Inspector engine and return capture-level context: "
                       "frames analyzed, duration, severity totals, protocol counts, categories, the findings "
                       "timeline, top hosts and the inventory (SNI, JA3/JA4, user agents, certificates). Findings "
                       "themselves come from get_findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to a .pcap or .pcapng file."},
                "include_findings": {"type": "boolean",
                                     "description": "Also include the findings array (default false)."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "get_findings",
        "description": "Findings the engine flagged in a capture: security, performance and protocol problems. "
                       "Filter by severity, category, protocol or text, and page with offset.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to a .pcap or .pcapng file."},
                "min_severity": {"type": "string", "description": "info, note, warning or error."},
                "category": {"type": "string", "description": "e.g. security, performance, protocol."},
                "protocol": {"type": "string", "description": "e.g. tls, dns, tcp."},
                "contains": {"type": "string", "description": "Text to look for in the id, title or detail."},
                "limit": {"type": "integer", "description": "Maximum findings to return (default 25, max 200)."},
                "offset": {"type": "integer", "description": "Skip this many matching findings."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "get_frame_findings",
        "description": "The engine's findings for one frame of a capture.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "frame": {"type": "integer", "description": "Frame number."},
            },
            "required": ["path", "frame"],
        },
    },
    {
        "name": "run_filter",
        "description": "Packets matching a Wireshark display filter, as a table. Use this to drill into a finding "
                       "(each finding carries a ready-made filter) or to test a hypothesis. Also reports whether the "
                       "filter compiled.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "filter": {"type": "string", "description": "Display filter, e.g. tls.handshake.type == 1."},
                "fields": {"type": "array", "items": {"type": "string"},
                           "description": "Field names to return per packet. Defaults to frame number, time, "
                                          "addresses, protocol and info."},
                "limit": {"type": "integer", "description": "Maximum packets to return (default 50, max 500)."},
            },
            "required": ["path", "filter"],
        },
    },
    {
        "name": "get_frame",
        "description": "The full decoded protocol tree of one frame, as Wireshark shows it in the detail pane.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "frame": {"type": "integer"},
            },
            "required": ["path", "frame"],
        },
    },
    {
        "name": "get_report",
        "description": "The engine's full plain-text report for a capture: every finding with counts, frames and "
                       "example values, plus the inventory.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
]

DEFAULT_FIELDS = ["frame.number", "frame.time_relative", "ip.src", "ip.dst", "_ws.col.protocol", "_ws.col.info"]


def call_tool(name, args):
    args = args or {}
    if name == "analyze_capture":
        data = dict(summary(capture_path(args.get("path"))))
        if not args.get("include_findings"):
            total = len(data.get("findings", []))
            data.pop("findings", None)
            data["findings_note"] = "%d findings omitted; call get_findings for them." % total
        return json.dumps(data, indent=1)

    if name == "get_findings":
        return json.dumps(filtered_findings(summary(capture_path(args.get("path"))), args), indent=1)

    if name == "get_frame_findings":
        path = capture_path(args.get("path"))
        frame = int(args.get("frame") or 0)
        if frame <= 0:
            raise ToolError("Pass a frame number greater than zero.")
        out, _ = run_tshark(["-r", str(path), "-Y", "frame.number == %d" % frame, "-T", "fields",
                             "-e", "ai_inspector.id", "-e", "ai_inspector.severity",
                             "-e", "ai_inspector.category", "-e", "ai_inspector.summary",
                             "-E", "separator=|"])
        rows = [r for r in out.splitlines() if r.strip(" |")]
        if not rows:
            return json.dumps({"frame": frame, "findings": []}, indent=1)
        findings = []
        for row in rows:
            parts = row.split("|")
            ids = (parts[0] if parts else "").split(",")
            sevs = (parts[1] if len(parts) > 1 else "").split(",")
            cats = (parts[2] if len(parts) > 2 else "").split(",")
            texts = (parts[3] if len(parts) > 3 else "").split(",")
            for i, fid in enumerate(x for x in ids if x):
                findings.append({"id": fid,
                                 "severity": sevs[i] if i < len(sevs) else "",
                                 "category": cats[i] if i < len(cats) else "",
                                 "summary": texts[i] if i < len(texts) else ""})
        return json.dumps({"frame": frame, "findings": findings}, indent=1)

    if name == "run_filter":
        path = capture_path(args.get("path"))
        expr = str(args.get("filter") or "").strip()
        if not expr:
            raise ToolError("Pass a display filter.")
        fields = [str(f) for f in (args.get("fields") or DEFAULT_FIELDS) if str(f).strip()][:20]
        limit = max(1, min(int(args.get("limit", 50) or 50), 500))
        cmd = ["-r", str(path), "-Y", expr, "-T", "fields", "-E", "separator=\t", "-E", "header=y",
               "-c", str(limit * 4)]
        for f in fields:
            cmd += ["-e", f]
        try:
            out, err = run_tshark(cmd)
        except TsharkError as e:
            # A filter the compiler rejects is an answer, not a server failure.
            # TShark exits 4 for a bad command line, and the filter is the only
            # part of this command line the model controls.
            if e.returncode == 4:
                return json.dumps({"filter": expr, "valid": False,
                                   "reason": e.message.replace("tshark: ", "", 1).strip(),
                                   "packets": []}, indent=1)
            raise
        lines = out.splitlines()
        header = lines[0].split("\t") if lines else fields
        rows = [dict(zip(header, l.split("\t"))) for l in lines[1:limit + 1]]
        return json.dumps({"filter": expr, "valid": True, "returned": len(rows),
                           "truncated": len(lines) - 1 > len(rows), "packets": rows}, indent=1)

    if name == "get_frame":
        path = capture_path(args.get("path"))
        frame = int(args.get("frame") or 0)
        if frame <= 0:
            raise ToolError("Pass a frame number greater than zero.")
        out, _ = run_tshark(["-r", str(path), "-Y", "frame.number == %d" % frame, "-V"])
        if not out.strip():
            raise ToolError("Frame %d is not in this capture." % frame)
        return out[:200000]

    if name == "get_report":
        path = capture_path(args.get("path"))
        summary(path)  # surfaces a missing plugin with a useful message
        out, _ = run_tshark(["-r", str(path), "-q", "-z", "ai_inspector,report"])
        return out[:200000] or "The engine produced no report for this capture."

    raise ToolError("No tool named '%s'." % name)


# ---------------------------------------------------------------- MCP plumbing

def result(rid, payload):
    return {"jsonrpc": "2.0", "id": rid, "result": payload}


def error(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def handle(msg):
    """Returns a response object, or None for notifications."""
    rid = msg.get("id")
    method = msg.get("method")
    params = msg.get("params") or {}

    if method == "initialize":
        asked = params.get("protocolVersion")
        return result(rid, {
            "protocolVersion": asked if isinstance(asked, str) and asked else PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": "Packet capture analysis. Start with analyze_capture for the shape of a capture, then "
                            "get_findings for what the engine flagged, then run_filter or get_frame to verify a "
                            "finding against the packets. Every tool takes the capture file's path.",
        })
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return result(rid, {})
    if method == "tools/list":
        return result(rid, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        try:
            text = call_tool(name, params.get("arguments"))
            return result(rid, {"content": [{"type": "text", "text": text}], "isError": False})
        except ToolError as e:
            return result(rid, {"content": [{"type": "text", "text": str(e)}], "isError": True})
        except Exception as e:  # never take the server down over one call
            return result(rid, {"content": [{"type": "text", "text": "%s: %s" % (type(e).__name__, e)}],
                                "isError": True})
    if rid is None:
        return None
    return error(rid, -32601, "Unknown method: %s" % method)


def serve(stdin=None, stdout=None):
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(error(None, -32700, "Parse error")) + "\n")
            stdout.flush()
            continue
        for one in (msg if isinstance(msg, list) else [msg]):
            reply = handle(one)
            if reply is not None:
                stdout.write(json.dumps(reply) + "\n")
                stdout.flush()


def self_test():
    """Checks the protocol surface, and the tshark wiring when one is available."""
    ok = True

    def check(label, cond, detail=""):
        nonlocal ok
        ok = ok and bool(cond)
        print("%s %s%s" % ("PASS" if cond else "FAIL", label, (" - " + detail) if detail and not cond else ""))

    init = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": PROTOCOL_VERSION}})
    check("initialize", init["result"]["serverInfo"]["name"] == SERVER_NAME)
    check("notifications are silent", handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None)
    listed = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
    check("tools/list", len(listed) == len(TOOLS))
    for t in listed:
        check("schema %s" % t["name"],
              t["inputSchema"]["type"] == "object" and "path" in t["inputSchema"]["properties"]
              and len(t["description"]) > 30)
    check("unknown method", handle({"jsonrpc": "2.0", "id": 3, "method": "nope"})["error"]["code"] == -32601)
    missing = handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                      "params": {"name": "get_findings", "arguments": {"path": "/definitely/not/here.pcap"}}})
    check("missing file is a tool error, not a crash", missing["result"]["isError"])
    unknown = handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "nope"}})
    check("unknown tool", unknown["result"]["isError"])

    fake = {"findings": [
        {"id": "a", "severity_level": 4, "category": "security", "protocol": "TLS", "title": "Weak cipher"},
        {"id": "b", "severity_level": 2, "category": "performance", "protocol": "DNS", "title": "Slow lookup"}]}
    check("severity filter", filtered_findings(fake, {"min_severity": "warning"})["matched"] == 1)
    check("category filter", filtered_findings(fake, {"category": "performance"})["matched"] == 1)
    check("text filter", filtered_findings(fake, {"contains": "cipher"})["matched"] == 1)
    check("paging", filtered_findings(fake, {"limit": 1, "offset": 1})["returned"] == 1)

    try:
        binary = tshark_path()
        print("     tshark: %s" % binary)
        cap = os.environ.get("AI_INSPECTOR_TEST_CAPTURE")
        if cap and Path(cap).exists():
            started = time.time()
            data = json.loads(call_tool("analyze_capture", {"path": cap}))
            check("analyze_capture on %s" % cap, "capture" in data)
            print("     analyzed in %.1fs" % (time.time() - started))
        else:
            print("     no capture to analyze (set AI_INSPECTOR_TEST_CAPTURE to run the end-to-end check)")
    except ToolError as e:
        print("     tshark unavailable: %s" % e)

    print("self-test %s" % ("passed" if ok else "FAILED"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true", help="check the server and exit")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
