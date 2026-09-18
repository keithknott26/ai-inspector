#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""AI Inspector MCP server: capture analysis for agents, without Wireshark's GUI.

Speaks the Model Context Protocol over stdio (JSON-RPC 2.0, no third-party
packages) and answers every call by running TShark with the AI Inspector engine
plugin loaded. Analysis is local and read-only; results go to the MCP client,
which may forward them to its configured AI provider.

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
  AI_INSPECTOR_ROOTS    os.pathsep-separated directories; captures must live under one
                        of them (default: any readable path)
  AI_INSPECTOR_TIMEOUT  seconds per tshark run (default 120)

Usage:
  tools/mcp_server.py               # stdio server, for an MCP client
  tools/mcp_server.py --self-test   # check the wiring and exit
"""
import argparse
import json
import math
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "ai-inspector"
SERVER_VERSION = "1.3.0"  # keep in step with cmake/AIInspectorVersion.cmake

MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_STDERR_BYTES = 20000
MAX_INPUT_CHARS = 1024 * 1024
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
    """Drain both pipes concurrently, enforcing limits before buffering output."""
    cmd = [tshark_path(), "-n"]
    plugins = os.environ.get("AI_INSPECTOR_PLUGINS")
    if plugins:
        cmd += ["--plugin-dir", plugins]
    cmd += args
    try:
        seconds = float(timeout if timeout is not None else os.environ.get("AI_INSPECTOR_TIMEOUT", "120"))
    except (TypeError, ValueError):
        raise ToolError("AI_INSPECTOR_TIMEOUT must be a positive, finite number.")
    if not math.isfinite(seconds) or seconds <= 0:
        raise ToolError("AI_INSPECTOR_TIMEOUT must be a positive, finite number.")

    buffers = [bytearray(), bytearray()]
    failures = []
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, bufsize=0)
    except OSError as e:
        raise ToolError("Could not run tshark: %s" % e)

    def drain(pipe, index, limit, label):
        try:
            while True:
                chunk = pipe.read(65536)
                if not chunk:
                    break
                if len(buffers[index]) + len(chunk) > limit:
                    failures.append("tshark %s exceeded %d bytes. Use a narrower filter or smaller capture."
                                    % (label, limit))
                    p.kill()
                    break
                buffers[index].extend(chunk)
        except OSError as e:
            failures.append("Could not read tshark %s: %s" % (label, e))
            p.kill()
        finally:
            pipe.close()

    readers = [
        threading.Thread(target=drain, args=(p.stdout, 0, MAX_OUTPUT_BYTES, "output")),
        threading.Thread(target=drain, args=(p.stderr, 1, MAX_STDERR_BYTES, "stderr")),
    ]
    for reader in readers:
        reader.start()
    try:
        p.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        raise ToolError("tshark did not finish in time. Try a smaller capture or raise AI_INSPECTOR_TIMEOUT.")
    finally:
        if p.poll() is None:
            p.kill()
        p.wait()
        for reader in readers:
            reader.join()
    if failures:
        raise ToolError(failures[0])
    out = buffers[0].decode("utf-8", "replace")
    err = clean_stderr(buffers[1].decode("utf-8", "replace"))
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


def validate_arguments(name, args):
    """Validate the simple tool schemas without adding a JSON Schema dependency."""
    tool = next((t for t in TOOLS if t["name"] == name), None)
    if tool is None:
        raise ToolError("No tool named '%s'." % name)
    if not isinstance(args, dict):
        raise ToolError("Tool arguments must be an object.")
    schema = tool["inputSchema"]
    for key in schema.get("required", []):
        if key not in args:
            raise ToolError("Missing required argument: %s." % key)
    types = {"string": str, "integer": int, "boolean": bool, "array": list}
    for key, spec in schema["properties"].items():
        if key not in args:
            continue
        value = args[key]
        if type(value) is not types[spec["type"]]:
            raise ToolError("%s must be of type %s." % (key, spec["type"]))
        if spec["type"] == "array" and any(not isinstance(item, str) or not item.strip() for item in value):
            raise ToolError("%s must contain non-empty field names." % key)


def packet_layers(text):
    """Parse selected-field JSON; never treat malformed output as an empty result."""
    try:
        packets = json.loads(text)
        if not isinstance(packets, list):
            raise ValueError("expected a packet array")
        layers = [packet["_source"]["layers"] for packet in packets]
        if any(not isinstance(layer, dict) for layer in layers):
            raise ValueError("expected field objects")
        for layer in layers:
            for values in layer.values():
                if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                    raise ValueError("expected arrays of field values")
        return layers
    except (ValueError, KeyError, TypeError, RecursionError) as e:
        raise ToolError("TShark's packet JSON could not be parsed: %s" % e)


def call_tool(name, args):
    args = {} if args is None else args
    validate_arguments(name, args)
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
        out, _ = run_tshark(["-r", str(path), "-Y", "frame.number == %d" % frame, "-T", "json",
                             "-e", "ai_inspector.id", "-e", "ai_inspector.severity",
                             "-e", "ai_inspector.category", "-e", "ai_inspector.finding"])
        findings = []
        for layer in packet_layers(out):
            ids, sevs, cats, texts = [layer.get("ai_inspector." + key, [])
                                     for key in ("id", "severity", "category", "finding")]
            # All four fields are emitted once per finding by the engine. Fail
            # explicitly if that contract changes instead of misaligning evidence.
            if len({len(ids), len(sevs), len(cats), len(texts)}) != 1:
                raise ToolError("The engine returned mismatched finding fields.")
            for fid, sev, cat, text in zip(ids, sevs, cats, texts):
                findings.append({"id": fid,
                                 "severity": sev, "category": cat, "summary": text})
        return json.dumps({"frame": frame, "findings": findings}, indent=1)

    if name == "run_filter":
        path = capture_path(args.get("path"))
        expr = str(args.get("filter") or "").strip()
        if not expr:
            raise ToolError("Pass a display filter.")
        fields = [str(f) for f in (args.get("fields") or DEFAULT_FIELDS) if str(f).strip()][:20]
        limit = max(1, min(int(args.get("limit", 50) or 50), 500))
        # -c caps INPUT packets, including nonmatches. Scan the whole capture;
        # limit only the returned rows, and report resource failures as errors.
        cmd = ["-r", str(path), "-Y", expr, "-T", "json"]
        for f in fields:
            cmd += ["-e", f]
        try:
            out, err = run_tshark(cmd)
        except TsharkError as e:
            # A filter the compiler rejects is an answer, not a server failure.
            # Invalid requested fields are tool errors, not invalid filters.
            if e.returncode == 4 and "Some fields aren't valid" not in e.message:
                return json.dumps({"filter": expr, "valid": False,
                                   "reason": e.message.replace("tshark: ", "", 1).strip(),
                                   "packets": []}, indent=1)
            raise
        layers = packet_layers(out)
        rows = [{field: ",".join(layer.get(field, [])) for field in fields} for layer in layers[:limit]]
        return json.dumps({"filter": expr, "valid": True, "returned": len(rows),
                           "scan_complete": True, "truncated": len(layers) > len(rows), "packets": rows}, indent=1)

    if name == "get_frame":
        path = capture_path(args.get("path"))
        frame = int(args.get("frame") or 0)
        if frame <= 0:
            raise ToolError("Pass a frame number greater than zero.")
        out, _ = run_tshark(["-r", str(path), "-Y", "frame.number == %d" % frame, "-V"])
        if not out.strip():
            raise ToolError("Frame %d is not in this capture." % frame)
        return out if len(out) <= 200000 else out[:200000] + "\n... (truncated)"

    if name == "get_report":
        path = capture_path(args.get("path"))
        summary(path)  # surfaces a missing plugin with a useful message
        out, _ = run_tshark(["-r", str(path), "-q", "-z", "ai_inspector,report"])
        if len(out) > 200000:
            return out[:200000] + "\n... (truncated)"
        return out or "The engine produced no report for this capture."

    raise ToolError("No tool named '%s'." % name)


# ---------------------------------------------------------------- MCP plumbing

def result(rid, payload):
    return {"jsonrpc": "2.0", "id": rid, "result": payload}


def error(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def handle(msg):
    """Returns a response object, or None for notifications."""
    if not isinstance(msg, dict):
        return error(None, -32600, "Invalid Request: expected an object.")
    rid = msg.get("id")
    if rid is not None and type(rid) not in (str, int):
        return error(None, -32600, "Invalid Request: id must be a string or integer.")
    method = msg.get("method")
    if msg.get("jsonrpc") != "2.0" or not isinstance(method, str) or not method:
        return error(rid, -32600, "Invalid Request: expected jsonrpc 2.0 and a method.")
    # Notifications must not produce responses or accidentally execute tools.
    if "id" not in msg:
        return None
    params = msg.get("params", {})
    if not isinstance(params, dict):
        return error(rid, -32602, "Invalid params: expected an object.")

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
        if not isinstance(name, str) or not name:
            return error(rid, -32602, "Invalid params: expected a tool name.")
        if "arguments" in params and not isinstance(params["arguments"], dict):
            return error(rid, -32602, "Invalid params: arguments must be an object.")
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
    while True:
        line = stdin.readline(MAX_INPUT_CHARS + 1)
        if not line:
            break
        if len(line) > MAX_INPUT_CHARS:
            # Drain this message in bounded chunks, preserving the next request.
            while line and not line.endswith("\n"):
                line = stdin.readline(MAX_INPUT_CHARS + 1)
            stdout.write(json.dumps(error(None, -32600, "Request exceeds the input size limit.")) + "\n")
            stdout.flush()
            continue
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except (ValueError, RecursionError):
            stdout.write(json.dumps(error(None, -32700, "Parse error")) + "\n")
            stdout.flush()
            continue
        # The advertised MCP revision uses individual messages, not batches.
        reply = handle(msg)
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
