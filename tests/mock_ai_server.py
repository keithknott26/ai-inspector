#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Local mock of the Anthropic Messages and OpenAI Chat Completions APIs for tests.

Paths: /anthropic/v1/messages, /openai/v1/chat/completions, /broken (non-JSON),
/slow (sleeps), /redirect (302). Requests are appended to --log as JSON lines.

When a request declares "tools" and carries no tool results yet, the mock asks
for one tool call (get_findings when offered, otherwise the first tool); the
next request, which carries the results, gets the normal text answer. This
exercises the client's tool loop end to end.
"""
import argparse
import http.server
import json
import time


def chunks(text, n=7):
    return [text[i:i + n] for i in range(0, len(text), n)]


class Handler(http.server.BaseHTTPRequestHandler):
    log_path = None
    key = "test-key-123"

    def log_message(self, *a):
        pass

    def reply(self, code, obj=None, raw=None, headers=None):
        data = raw if raw is not None else json.dumps(obj).encode()
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def sse(self, events, done=False):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        for ev in events:
            self.wfile.write(("event: x\ndata: %s\n\n" % json.dumps(ev)).encode())
            self.wfile.flush()
            time.sleep(0.005)
        if done:
            self.wfile.write(b"data: [DONE]\n\n")
        self.close_connection = True

    @staticmethod
    def wants_tool_call(req):
        if not req.get("tools"):
            return False
        for m in req.get("messages", []):
            if m.get("role") == "tool":
                return False
            c = m.get("content")
            if isinstance(c, list) and any(isinstance(b, dict) and b.get("type") == "tool_result" for b in c):
                return False
        return True

    @staticmethod
    def pick_tool(req):
        names = [t.get("name") or t.get("function", {}).get("name") for t in req.get("tools") or []]
        names = [n for n in names if n]
        if "get_findings" in names:
            return "get_findings", {"min_severity": "warning", "limit": 5}
        return (names[0] if names else "unknown"), {}

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.log_path:
            with open(self.log_path, "a") as f:
                f.write(json.dumps({"path": self.path, "headers": dict(self.headers), "body": body.decode("utf-8", "replace")}) + "\n")
        if self.path.startswith("/slow"):
            time.sleep(30)
        if self.path.startswith("/redirect"):
            return self.reply(302, {}, headers={"Location": "http://127.0.0.1:1/steal"})
        if self.path.startswith("/broken"):
            return self.reply(200, raw=b"<html>not json</html>")
        req = json.loads(body)
        stream = bool(req.get("stream"))
        want_tool = self.wants_tool_call(req)
        tool_name, tool_args = self.pick_tool(req)
        text_for = lambda who: ("%s turn %d\n\n## Summary\nSee frame 3 and `tcp.flags.syn == 1`.\n\n```chart\n"
                                '{"type":"bar","title":"Mock chart","labels":["a","b"],"series":[{"name":"n","values":[1,2]}]}'
                                "\n```\n") % (who, len(req["messages"]))
        if self.path.startswith("/anthropic") and self.headers.get("x-api-key") == self.key and stream and want_tool:
            return self.sse([{"type": "message_start"},
                             {"type": "content_block_start", "index": 0,
                              "content_block": {"type": "tool_use", "id": "toolu_1", "name": tool_name}}] +
                            [{"type": "content_block_delta", "index": 0,
                              "delta": {"type": "input_json_delta", "partial_json": c}}
                             for c in chunks(json.dumps(tool_args), 5)] +
                            [{"type": "content_block_stop", "index": 0},
                             {"type": "message_delta", "delta": {"stop_reason": "tool_use"}}, {"type": "message_stop"}])
        if self.path.startswith("/openai") and stream and want_tool:
            return self.sse([{"choices": [{"delta": {"tool_calls": [
                                  {"index": 0, "id": "call_1", "type": "function",
                                   "function": {"name": tool_name, "arguments": ""}}]}, "finish_reason": None}]}] +
                            [{"choices": [{"delta": {"tool_calls": [
                                  {"index": 0, "function": {"arguments": c}}]}, "finish_reason": None}]}
                             for c in chunks(json.dumps(tool_args), 5)] +
                            [{"choices": [{"delta": {}, "finish_reason": "tool_calls"}]}], done=True)
        if self.path.startswith("/anthropic") and self.headers.get("x-api-key") == self.key and stream:
            return self.sse([{"type": "message_start"}] +
                            [{"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": c}}
                             for c in chunks(text_for("MOCK-ANTHROPIC"))] +
                            [{"type": "message_delta", "delta": {"stop_reason": "end_turn"}}, {"type": "message_stop"}])
        if self.path.startswith("/openai") and stream:
            return self.sse([{"choices": [{"delta": {"content": c}, "finish_reason": None}]} for c in chunks(text_for("MOCK-OPENAI"))] +
                            [{"choices": [{"delta": {}, "finish_reason": "stop"}]}], done=True)
        if self.path.startswith("/anthropic"):
            if self.headers.get("x-api-key") != self.key:
                return self.reply(401, {"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}})
            if want_tool:
                return self.reply(200, {"type": "message", "stop_reason": "tool_use",
                                        "content": [{"type": "tool_use", "id": "toolu_1", "name": tool_name, "input": tool_args}]})
            return self.reply(200, {"type": "message", "stop_reason": "end_turn",
                                    "content": [{"type": "text", "text": "MOCK-ANTHROPIC turn %d" % len(req["messages"])}]})
        if want_tool:
            return self.reply(200, {"choices": [{"finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None,
                "tool_calls": [{"id": "call_1", "type": "function",
                                "function": {"name": tool_name, "arguments": json.dumps(tool_args)}}]}}]})
        return self.reply(200, {"choices": [{"finish_reason": "stop",
                                             "message": {"role": "assistant", "content": "MOCK-OPENAI turn %d" % len(req["messages"])}}]})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--log")
    ap.add_argument("--port-file")
    a = ap.parse_args()
    Handler.log_path = a.log
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    if a.port_file:
        with open(a.port_file, "w") as f:
            f.write(str(srv.server_address[1]))
    srv.serve_forever()


if __name__ == "__main__":
    main()
