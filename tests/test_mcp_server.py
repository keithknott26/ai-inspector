#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""MCP regressions: stdlib only; set MCP_TEST_TSHARK for stock-TShark tests."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("mcp_server", ROOT / "tools" / "mcp_server.py")
mcp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mcp)


def packet_json(*layers):
    return json.dumps([{"_source": {"layers": layer}} for layer in layers])


def request(method="ping", **params):
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}


class ProtocolTests(unittest.TestCase):
    def serve(self, messages):
        output = io.StringIO()
        mcp.serve(io.StringIO(messages), output)
        return [json.loads(line) for line in output.getvalue().splitlines()]

    def test_invalid_envelopes_do_not_prevent_next_request(self):
        for bad in (None, 42, True, "text", [], [request()], {},
                    {"jsonrpc": "1.0", "id": 2, "method": "ping"},
                    {"jsonrpc": "2.0", "id": {}, "method": "ping"},
                    {"jsonrpc": "2.0", "id": True, "method": "ping"},
                    {"jsonrpc": "2.0", "id": 2, "method": []}):
            with self.subTest(bad=bad):
                replies = self.serve(json.dumps(bad) + "\n" + json.dumps(request()) + "\n")
                self.assertEqual(replies[0]["error"]["code"], -32600)
                self.assertEqual(replies[1]["result"], {})

    def test_bad_params_are_rejected(self):
        for value in (None, 3, [], "text", False):
            with self.subTest(value=value):
                msg = request("initialize")
                msg["params"] = value
                self.assertEqual(mcp.handle(msg)["error"]["code"], -32602)
                msg = request("tools/call", name="run_filter", arguments=value)
                self.assertEqual(mcp.handle(msg)["error"]["code"], -32602)
        self.assertEqual(mcp.handle(request("tools/call", name=[]))["error"]["code"], -32602)

    def test_parse_errors_and_deep_json_preserve_connection(self):
        for text in ("{oops", "[" * 2000 + "]" * 2000):
            with self.subTest(text=text[:10]):
                replies = self.serve(text + "\n" + json.dumps(request()) + "\n")
                # Python builds differ in their JSON recursion limit. A deeply
                # nested array may parse but is still an invalid MCP envelope.
                expected = (-32700,) if text == "{oops" else (-32700, -32600)
                self.assertIn(replies[0]["error"]["code"], expected)
                self.assertEqual(replies[1]["result"], {})

    def test_real_stdio_process_recovers_after_malformed_input(self):
        process = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "mcp_server.py")],
            input=("null\n" + json.dumps(request("initialize", protocolVersion=mcp.PROTOCOL_VERSION))
                   + "\n" + json.dumps(request("tools/list")) + "\n").encode(),
            capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, b"")
        replies = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual(replies[0]["error"]["code"], -32600)
        self.assertEqual(replies[1]["result"]["serverInfo"]["name"], "ai-inspector")
        self.assertEqual(len(replies[2]["result"]["tools"]), 6)

    def test_oversized_message_is_drained(self):
        with patch.object(mcp, "MAX_INPUT_CHARS", 100):
            replies = self.serve("x" * 500 + "\n" + json.dumps(request()) + "\n")
        self.assertEqual(len(replies), 2)
        self.assertEqual(replies[0]["error"]["code"], -32600)
        self.assertEqual(replies[1]["result"], {})

    def test_oversized_message_at_eof(self):
        with patch.object(mcp, "MAX_INPUT_CHARS", 100):
            replies = self.serve("x" * 500)
        self.assertEqual(len(replies), 1)
        self.assertEqual(replies[0]["error"]["code"], -32600)

    def test_notifications_are_silent_and_do_not_execute_tools(self):
        with patch.object(mcp, "call_tool") as call:
            for method in ("notifications/initialized", "notifications/cancelled", "ping", "tools/call"):
                self.assertIsNone(mcp.handle({"jsonrpc": "2.0", "method": method}))
            call.assert_not_called()

    def test_zero_and_string_ids_are_preserved(self):
        for rid in (0, "request-1"):
            msg = request()
            msg["id"] = rid
            self.assertEqual(mcp.handle(msg)["id"], rid)

    def test_tool_failures_do_not_prevent_next_request(self):
        with patch.object(mcp, "call_tool", side_effect=RuntimeError("test failure")):
            replies = self.serve(json.dumps(request("tools/call", name="get_report", arguments={}))
                                 + "\n" + json.dumps(request()) + "\n")
        self.assertTrue(replies[0]["result"]["isError"])
        self.assertEqual(replies[1]["result"], {})

    def test_tool_argument_types(self):
        cases = [
            ("run_filter", {"path": [], "filter": "tcp"}),
            ("run_filter", {"path": "x", "filter": "tcp", "fields": "frame.number"}),
            ("run_filter", {"path": "x", "filter": "tcp", "fields": [42]}),
            ("run_filter", {"path": "x", "filter": "tcp", "fields": [" "]}),
            ("run_filter", {"path": "x", "filter": "tcp", "limit": True}),
            ("get_frame", {"path": "x", "frame": 1.5}),
            ("get_frame", {"frame": 1}),
            ("analyze_capture", {"path": "x", "include_findings": "false"}),
        ]
        for name, args in cases:
            with self.subTest(name=name, args=args), patch.object(mcp, "run_tshark") as run:
                reply = mcp.handle(request("tools/call", name=name, arguments=args))
                self.assertTrue(reply["result"]["isError"])
                run.assert_not_called()


class ToolTests(unittest.TestCase):
    def setUp(self):
        p = patch.object(mcp, "capture_path", return_value=Path("/test.pcap"))
        p.start()
        self.addCleanup(p.stop)

    def test_findings_keep_delimiters_unicode_and_alignment(self):
        texts = ['SSL 2.0/3.0 negotiated (POODLE, broken)', 'pipe |, quote " and tab\t雪']
        data = packet_json({"ai_inspector.id": ["tls.ssl_negotiated", "test.second"],
                            "ai_inspector.severity": ["4", "2"],
                            "ai_inspector.category": ["security", "protocol"],
                            "ai_inspector.finding": texts})
        with patch.object(mcp, "run_tshark", return_value=(data, "")) as run:
            result = json.loads(mcp.call_tool("get_frame_findings", {"path": "x", "frame": 1}))
        self.assertEqual([f["summary"] for f in result["findings"]], texts)
        self.assertEqual([f["id"] for f in result["findings"]], ["tls.ssl_negotiated", "test.second"])
        cmd = run.call_args.args[0]
        self.assertIn("ai_inspector.finding", cmd)
        self.assertNotIn("ai_inspector.summary", cmd)
        self.assertEqual(cmd[cmd.index("-T") + 1], "json")

    def test_missing_finding_field_is_an_error_not_misaligned_evidence(self):
        data = packet_json({"ai_inspector.id": ["one"], "ai_inspector.finding": ["title"]})
        with patch.object(mcp, "run_tshark", return_value=(data, "")):
            with self.assertRaisesRegex(mcp.ToolError, "mismatched"):
                mcp.call_tool("get_frame_findings", {"path": "x", "frame": 1})

    def test_no_findings(self):
        for data in ("[]", packet_json({})):
            with self.subTest(data=data), patch.object(mcp, "run_tshark", return_value=(data, "")):
                result = json.loads(mcp.call_tool("get_frame_findings", {"path": "x", "frame": 1}))
                self.assertEqual(result["findings"], [])

    def test_late_match_command_has_no_input_packet_limit(self):
        with patch.object(mcp, "run_tshark", return_value=(packet_json({"frame.number": ["1000"]}), "")) as run:
            result = json.loads(mcp.call_tool("run_filter", {
                "path": "x", "filter": "frame.number == 1000", "fields": ["frame.number"], "limit": 1}))
        self.assertNotIn("-c", run.call_args.args[0])
        self.assertTrue(result["scan_complete"])
        self.assertFalse(result["truncated"])
        self.assertEqual(result["packets"], [{"frame.number": "1000"}])

    def test_output_limit_does_not_change_scan_completeness(self):
        data = packet_json(*[{"frame.number": [str(n)]} for n in range(3)])
        with patch.object(mcp, "run_tshark", return_value=(data, "")):
            result = json.loads(mcp.call_tool("run_filter", {
                "path": "x", "filter": "frame", "fields": ["frame.number"], "limit": 2}))
        self.assertEqual(result["returned"], 2)
        self.assertTrue(result["truncated"])
        self.assertTrue(result["scan_complete"])

    def test_empty_complete_search(self):
        with patch.object(mcp, "run_tshark", return_value=("[]", "")):
            result = json.loads(mcp.call_tool("run_filter", {"path": "x", "filter": "tcp"}))
        self.assertEqual(result["returned"], 0)
        self.assertFalse(result["truncated"])
        self.assertTrue(result["scan_complete"])

    def test_filter_values_preserve_control_characters_and_missing_fields(self):
        value = 'tab\tnewline\nquote"pipe|comma,'
        data = packet_json({"frame.number": ["1"], "test.value": [value]})
        with patch.object(mcp, "run_tshark", return_value=(data, "")):
            result = json.loads(mcp.call_tool("run_filter", {
                "path": "x", "filter": "frame", "fields": ["frame.number", "test.value", "missing"]}))
        self.assertEqual(result["packets"][0], {"frame.number": "1", "test.value": value, "missing": ""})

    def test_malformed_packet_json_is_not_an_empty_result(self):
        for data in ("", "{", "{}", "[null]", packet_json({"frame.number": "1"})):
            with self.subTest(data=data), patch.object(mcp, "run_tshark", return_value=(data, "")):
                with self.assertRaises(mcp.ToolError):
                    mcp.call_tool("run_filter", {"path": "x", "filter": "frame"})

    def test_invalid_filter_and_invalid_field_are_distinct(self):
        with patch.object(mcp, "run_tshark", side_effect=mcp.TsharkError(4, "tshark: bad filter")):
            result = json.loads(mcp.call_tool("run_filter", {"path": "x", "filter": "bad"}))
        self.assertFalse(result["valid"])
        with patch.object(mcp, "run_tshark", side_effect=mcp.TsharkError(4, "Some fields aren't valid:\n bogus")):
            with self.assertRaises(mcp.TsharkError):
                mcp.call_tool("run_filter", {"path": "x", "filter": "frame", "fields": ["bogus"]})

    def test_overflow_and_timeout_are_not_reported_as_complete(self):
        for message in ("output exceeded", "did not finish in time"):
            with self.subTest(message=message), patch.object(mcp, "run_tshark", side_effect=mcp.ToolError(message)):
                result = mcp.handle(request("tools/call", name="run_filter", arguments={"path": "x", "filter": "tcp"}))
                self.assertTrue(result["result"]["isError"])
                self.assertNotIn("scan_complete", result["result"]["content"][0]["text"])

    def test_text_truncation_is_explicit(self):
        with patch.object(mcp, "run_tshark", return_value=("x" * 200001, "")), patch.object(mcp, "summary"):
            for name, args in (("get_frame", {"path": "x", "frame": 1}), ("get_report", {"path": "x"})):
                self.assertTrue(mcp.call_tool(name, args).endswith("... (truncated)"))


class ProcessTests(unittest.TestCase):
    def run_child(self, script, timeout=5):
        real_popen = subprocess.Popen
        children = []

        def spawn(cmd, **kwargs):
            self.assertEqual(cmd[:2], ["test-tshark", "-n"])
            child = real_popen([sys.executable, "-c", script], **kwargs)
            children.append(child)
            return child

        with patch.object(mcp, "tshark_path", return_value="test-tshark"), \
                patch.object(mcp.subprocess, "Popen", side_effect=spawn), \
                patch.object(mcp, "MAX_OUTPUT_BYTES", 1024), \
                patch.object(mcp, "MAX_STDERR_BYTES", 1024):
            try:
                return mcp.run_tshark([], timeout=timeout)
            finally:
                for child in children:
                    self.assertIsNotNone(child.poll(), "child must be reaped")
                    self.assertTrue(child.stdout.closed)
                    self.assertTrue(child.stderr.closed)

    def test_exact_limit_succeeds(self):
        out, _ = self.run_child("import os; os.write(1, b'x' * 1024)")
        self.assertEqual(len(out), 1024)

    def test_stdout_overflow_is_explicit(self):
        with self.assertRaisesRegex(mcp.ToolError, "output exceeded"):
            self.run_child("import os; os.write(1, b'x' * 1025)")

    def test_stderr_overflow_is_explicit(self):
        with self.assertRaisesRegex(mcp.ToolError, "stderr exceeded"):
            self.run_child("import os; os.write(2, b'x' * 1025)")

    def test_both_pipes_are_drained_without_deadlock(self):
        with self.assertRaisesRegex(mcp.ToolError, "exceeded"):
            self.run_child("import os\nwhile True:\n os.write(1, b'x' * 512)\n os.write(2, b'e' * 512)")

    def test_timeout_kills_and_reaps_child(self):
        with self.assertRaisesRegex(mcp.ToolError, "did not finish in time"):
            self.run_child("import time; time.sleep(30)", timeout=0.1)

    def test_nonzero_exit_preserves_tshark_error(self):
        with self.assertRaises(mcp.TsharkError) as caught:
            self.run_child("import os, sys; os.write(2, b'bad filter'); sys.exit(4)")
        self.assertEqual(caught.exception.returncode, 4)
        self.assertEqual(caught.exception.message, "bad filter")

    def test_invalid_utf8_is_replaced(self):
        self.assertEqual(self.run_child("import os; os.write(1, b'\\xff')")[0], "\ufffd")

    def test_invalid_timeout_is_rejected_before_spawn(self):
        for value in ("bad", "nan", "inf", "0", "-1"):
            with self.subTest(value=value), patch.object(mcp, "tshark_path", return_value="test-tshark"), \
                    patch.dict(os.environ, {"AI_INSPECTOR_TIMEOUT": value}), patch.object(mcp.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(mcp.ToolError, "positive, finite"):
                    mcp.run_tshark([])
                spawn.assert_not_called()


@unittest.skipUnless(os.environ.get("MCP_TEST_TSHARK"), "set MCP_TEST_TSHARK to a stock tshark binary")
class RealTsharkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = shutil.which(os.environ["MCP_TEST_TSHARK"])
        if not cls.binary:
            raise RuntimeError("MCP_TEST_TSHARK was set but the binary was not found")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.capture = Path(cls.tmp.name) / "late-match.pcap"
        # Ethernet + IPv4 + UDP. Checksums are irrelevant to these field tests.
        ethernet = bytes.fromhex("00112233445566778899aabb0800")
        payload = b"MCP regression"
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(payload), 0, 0, 64, 17, 0,
                         bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
        udp = struct.pack("!HHHH", 1234, 9999, 8 + len(payload), 0)
        packet = ethernet + ip + udp + payload
        with cls.capture.open("wb") as f:
            f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for n in range(1000):
                f.write(struct.pack("<IIII", n, 0, len(packet), len(packet)))
                f.write(packet)

    def setUp(self):
        env = patch.dict(os.environ, {"AI_INSPECTOR_TSHARK": self.binary,
                                     "AI_INSPECTOR_PLUGINS": "", "AI_INSPECTOR_ROOTS": "",
                                     "AI_INSPECTOR_TIMEOUT": "30"})
        env.start()
        self.addCleanup(env.stop)

    def test_match_after_old_scan_limit(self):
        result = json.loads(mcp.call_tool("run_filter", {
            "path": str(self.capture), "filter": "frame.number == 1000", "fields": ["frame.number"], "limit": 1}))
        self.assertEqual(result["packets"], [{"frame.number": "1000"}])
        self.assertTrue(result["scan_complete"])
        self.assertFalse(result["truncated"])

    def test_row_limit_and_no_match(self):
        result = json.loads(mcp.call_tool("run_filter", {
            "path": str(self.capture), "filter": "udp", "fields": ["frame.number"], "limit": 2}))
        self.assertEqual(result["returned"], 2)
        self.assertTrue(result["truncated"])
        self.assertTrue(result["scan_complete"])
        result = json.loads(mcp.call_tool("run_filter", {"path": str(self.capture), "filter": "tcp"}))
        self.assertEqual(result["returned"], 0)
        self.assertTrue(result["scan_complete"])

    def test_default_columns(self):
        result = json.loads(mcp.call_tool("run_filter", {"path": str(self.capture), "filter": "frame.number == 1"}))
        self.assertEqual(result["packets"][0]["frame.number"], "1")
        self.assertEqual(result["packets"][0]["ip.src"], "192.0.2.1")

    def test_actual_invalid_filter_and_field(self):
        result = json.loads(mcp.call_tool("run_filter", {"path": str(self.capture), "filter": "not.a.field == 1"}))
        self.assertFalse(result["valid"])
        with self.assertRaises(mcp.TsharkError):
            mcp.call_tool("run_filter", {"path": str(self.capture), "filter": "udp", "fields": ["not.a.field"]})

    def test_repeated_finding_fields_from_tshark_json(self):
        real_run = mcp.run_tshark
        fixture = ROOT / "tests" / "fixtures" / "mcp_findings.lua"
        with patch.object(mcp, "run_tshark",
                          side_effect=lambda args: real_run(["-X", "lua_script:" + str(fixture)] + args)):
            result = json.loads(mcp.call_tool("get_frame_findings", {"path": str(self.capture), "frame": 1}))
        self.assertEqual([f["id"] for f in result["findings"]], ["test.first", "test.second"])
        self.assertEqual(result["findings"][0]["summary"], "SSL 2.0/3.0 negotiated (POODLE, broken)")
        self.assertEqual(result["findings"][1]["summary"], 'Quote "ok", pipe | and tab\tend')


if __name__ == "__main__":
    unittest.main()
