# Architecture

AI Inspector targets the Wireshark 4.7 development branch, pinned in
`cmake/AIInspectorVersion.cmake`, because that branch provides the dedicated Qt UI
plugin API (`uiqt_register_plugin`).

## Components

```
┌──────────────────────── Wireshark process ─────────────────────────┐
│                                                                    │
│  epan plugin: ai_inspector_engine.so        ui plugin: ai_inspector.so
│  ───────────────────────────────────        ──────────────────────────
│  protocol "ai_inspector"                    Tools > AI Inspector menu (plugin_if)
│  post-dissector + Analyzer                  InspectorPanel (QDockWidget)
│  fields ai_inspector.*, expert info,          ├─ Dashboard / ChartWidget
│  preferences                                  ├─ Findings table + detail
│  State (findings, heuristics,                 ├─ ChatView ── AiClient ──► HTTPS
│  timeline, inventory)                         └─ Report
│        │                                           ▲
│        │ tap "ai_inspector"                        │ Host (injected callbacks)
│        └─► ai_inspector_tap_data_t ──► tap listener ┘
│            (carries ai_inspector_engine_api_t)
│                                                                    │
│  tshark -z ai_inspector,report|json  (stat tap in the engine)      │
└────────────────────────────────────────────────────────────────────┘
```

### Why two plugins

`uiqt_plugin_init()` runs after `epan_init()`, so a UI plugin cannot register
dissector fields, expert infos or preferences during normal registration. The
analysis therefore lives in an epan plugin, which also works in TShark. The Qt code
lives in a UI plugin, which only Wireshark loads.

### The engine ↔ UI boundary

The two shared objects never link against each other. The engine registers the tap
`ai_inspector` and queues an `ai_inspector_tap_data_t` for each frame. That record
points to `ai_inspector_engine_api_t` (`native/common/ai_inspector_api.h`), a
versioned table of C functions:

| Function | Returns |
|---|---|
| `generation()` | a counter that changes whenever capture state resets |
| `summary_json(max)` | capture totals, protocols, findings, categories, timeline, top hosts, inventory |
| `frame_findings_json(frame)` | findings for one frame |
| `report_text()` | plain-text report |
| `free_string()` | frees returned strings |

Only C types and JSON cross the boundary. Increase `AI_INSPECTOR_API_ABI` whenever
the table or its semantics change.

## Engine

- **Fields.** About 150 fields are primed with `set_postdissector_wanted_hfids()`, so
  their values exist on the first pass without a visible tree. Field IDs are resolved
  in the init routine. A field missing from a Wireshark build only disables the
  related checks, and the report lists the missing fields.
- **Analysis once.** `Analyzer::run()` runs on the first pass (`!PINFO_FD_VISITED`).
  Later passes only render cached findings, so filtering and redissection give
  consistent results.
- **Findings.** Each finding has a severity (Info/Note/Warning/Error), a category
  (security/performance/protocol/anomaly/inventory), a protocol label, a stable ID, a
  title, an optional detail and a display filter.
- **Limits.** At most 24 findings per frame, a configurable number of annotations per
  ID (counts continue), 4096 finding types, 200k heuristic keys, 500k timeline
  seconds. The port-scan tracker stops tracking a pair once it has reported it.
- **Performance.** 151k mixed frames with full dissection take 28.3 s without the
  engine and 28.6–29.7 s with it.

## UI plugin

| File | Responsibility |
|---|---|
| `ai_inspector_ui.cpp` | Registration, menu, tap listener, Wireshark adapter (`Host`), selected-packet tree dump, display-filter validation (`dfilter_compile`) |
| `panel.*` | Tabs, findings filtering, stale-capture guard, request building |
| `dashboard.*` | KPI cards and charts from the summary JSON |
| `charts.*` | QPainter charts (bar, horizontal bar, donut, line, stacked), theme from the palette (light/dark), chart spec validation |
| `chat_view.*` | Transcript rendering: Markdown (no raw HTML), inline charts, validated filter chips, frame links |
| `ai_client.*` | Async streaming client (Anthropic Messages, OpenAI Chat Completions), timeouts, cancel, bounded history, the tool-call loop |
| `engine_tools.*` | The tools the assistant may call, answered from the `Host` callbacks |
| `redactor.*` | Address placeholders (reversible locally), credential scrubbing |
| `settings.*` | Settings dialog, environment overrides, key file |
| `selftest.*` | In-application integration test (`AI_INSPECTOR_UI_SELFTEST=1`) |

### Request pipeline

```
capture summary JSON (+ selected packet tree with sensitive values removed)
  → scrubSecrets()          always: credential values, password=/token= parameters
  → Redactor::apply()       default on: IPv4/IPv6/MAC → IP-n / IP6-n / MAC-n
  → AiClient::ask()         HTTPS (http only for localhost), no redirects, streaming
  → ChatView                Redactor::restore() for display, Markdown without HTML,
                            charts validated, filters compiled before they are clickable
```

### Tool calls

With tool calling on (the default), the first message carries no capture data at all.
`EngineTools` declares six tools; `AiClient` runs the loop:

```
ask() → sendRound() → response contains tool_use / tool_calls
      → EngineTools::run() via the panel's handler
          arguments  ← Redactor::restore()   (the model works in placeholder space)
          results    → scrubSecrets() → Redactor::apply()
      → tool_result messages appended → sendRound() again
      → …at most maxToolRounds() (6); the last round is sent with no tools offered
      → finished(): the model's text plus a line per tool consulted
```

Tools are answered from the same `Host` callbacks the rest of the panel uses, so they
inherit the engine's generation guard and need no new engine ABI. Results are capped
(60 000 characters per call) and unknown tool names come back as errors rather than
failing the request, so a model that invents a tool can correct itself.

### MCP server

`tools/mcp_server.py` is a separate, GUI-free path to the same engine: a stdio JSON-RPC
server that shells out to TShark with `-z ai_inspector,json|report`, `-Y` and `-V`. It
shares no code with the plugins — it only depends on the engine's documented TShark
interface — which is what keeps it a single dependency-free file. See `docs/mcp.md`.

### Rules that keep it stable

- **Host window.** Found by Qt introspection: exactly one `WiresharkMainWindow`, and an
  ambiguous host is refused. The `gui_data` passed to menu callbacks is not a widget.
- **Plugin lifetime.** Wireshark deletes the main window, cleans up epan, unloads UI
  plugins and only then destroys `QApplication`. Nothing from the UI plugin may
  outlive the main window: no `qApp`-parented objects, and no
  `QTimer::singleShot(…, qApp, lambda)`.
- **Stale captures.** Actions compare the engine generation from when the data was
  shown with the current one, and refresh instead of acting if they differ.
- **Threads.** Everything runs on the GUI thread. The engine mutex protects State
  against API calls made during dissection callbacks.

## Known upstream issue

In the 4.7 development snapshot, `PacketList::~PacketList()` can trigger
`applyOverlayActiveState()` on a partly destroyed object if the packet list has
keyboard focus while the window is deleted. The self-test moves focus to the panel
before it exits.

## Possible upstream improvement

A provider-independent dock-registration API for Qt UI plugins would replace the
main-window discovery and define ownership and lifetime. See `docs/publishing.md`.
