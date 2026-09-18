# MCP server

`tools/mcp_server.py` exposes the AI Inspector engine over the [Model Context
Protocol](https://modelcontextprotocol.io) so an agent — Claude Desktop, Claude
Code, or anything else that speaks MCP — can analyze capture files without
opening Wireshark.

It is a single Python file with no third-party dependencies. Every call shells
out to TShark with the `ai_inspector_engine` plugin loaded. Nothing leaves the
machine: the server neither makes network requests nor talks to an AI provider.
Captures are opened read-only.

## Requirements

A TShark that loads the engine plugin. The development build is the easy one:

```sh
sh tools/build-development.sh
export AI_INSPECTOR_TSHARK="$PWD/build-development/run/tshark"
```

The server also finds `build-development/run/tshark` on its own, and falls back
to `tshark` on `PATH` (which will only work if the plugin is installed for it).

Check the wiring:

```sh
tools/mcp_server.py --self-test
```

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `analyze_capture` | `path`, `include_findings` | Frames, duration, severity totals, protocol counts, categories, findings timeline, top hosts, inventory (SNI, JA3/JA4, user agents, certificates) |
| `get_findings` | `path`, `min_severity`, `category`, `protocol`, `contains`, `limit`, `offset` | Matching findings with counts, first/last frame and a ready-made display filter |
| `get_frame_findings` | `path`, `frame` | What the engine flagged on one frame |
| `run_filter` | `path`, `filter`, `fields`, `limit` | Matching packets as rows. An invalid filter comes back as `"valid": false` with the compiler's reason, not as an error |
| `get_frame` | `path`, `frame` | One frame's full decoded protocol tree |
| `get_report` | `path` | The engine's plain-text report |

The summary is cached per file revision, so a session that calls
`analyze_capture` then several `get_findings` runs TShark once.

## Configuration

| Variable | Purpose |
|---|---|
| `AI_INSPECTOR_TSHARK` | TShark binary to use |
| `AI_INSPECTOR_PLUGINS` | Extra plugin directory passed to TShark (`--plugin-dir`) |
| `AI_INSPECTOR_ROOTS` | `:`-separated directories the server may read captures from. Unset means any readable path — set it when the agent is not fully trusted |
| `AI_INSPECTOR_TIMEOUT` | Seconds per TShark run (default 120) |

## Connecting a client

Claude Desktop (`claude_desktop_config.json`) or any client with the same shape:

```json
{
  "mcpServers": {
    "ai-inspector": {
      "command": "python3",
      "args": ["/path/to/ai-inspector/tools/mcp_server.py"],
      "env": {
        "AI_INSPECTOR_TSHARK": "/path/to/ai-inspector/build-development/run/tshark",
        "AI_INSPECTOR_ROOTS": "/Users/you/captures"
      }
    }
  }
}
```

Claude Code:

```sh
claude mcp add ai-inspector -- python3 /path/to/ai-inspector/tools/mcp_server.py
```

Then ask in plain language: *"Analyze ~/captures/incident.pcapng — what are the
security findings, and show me the packets behind the worst one."* The agent
calls `analyze_capture`, `get_findings`, then `run_filter` with the filter the
finding carries.

## Notes

- The server is stateless apart from the summary cache; restarting it loses
  nothing.
- A failing tool returns `isError` with a readable message rather than killing
  the connection, so an agent can correct itself and retry.
- Output is bounded (8 MB per TShark run, 200 KB per frame dump or report), so a
  large capture cannot flood the agent's context.
