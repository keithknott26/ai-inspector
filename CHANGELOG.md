# Changelog

All notable changes to AI Inspector. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The version is defined in
`cmake/AIInspectorVersion.cmake`.

## [Unreleased]

## [1.3.0] - 2026-09-17

### Added
- **The assistant pulls capture data on demand.** Instead of one large JSON block in the
  first message, it calls back into the engine: `get_findings` (filtered by severity,
  category, protocol or text, with paging), `get_capture_summary`, `get_frame_findings`,
  `get_selected_packet`, `get_report` and `validate_filter`. Requests start small, answers
  can drill into whatever the question needs, and the transcript records which data was
  consulted. Works with Anthropic and OpenAI tool calling, streaming or not; tool arguments
  are un-redacted on the way in and results redacted on the way out, so the model still only
  sees placeholders. A Settings checkbox turns it off for models without tool calling.
- **MCP server** (`tools/mcp_server.py`): the engine over the Model Context Protocol, so an
  agent can analyze a capture without opening Wireshark. Tools: `analyze_capture`,
  `get_findings`, `get_frame_findings`, `run_filter`, `get_frame`, `get_report`. Single file,
  no third-party dependencies, local and read-only, with `--self-test` and an
  `AI_INSPECTOR_ROOTS` allowlist. See `docs/mcp.md`.

### Fixed
- The unit tests no longer overwrite real AI Inspector preferences. On macOS QSettings uses
  CFPreferences, which ignores both `HOME` and `QSettings::setDefaultFormat()`, so a test run
  was saving its own provider, model and limits over the developer's settings — which then
  looked like the Settings dialog refusing to keep a chosen provider. The store now honours
  `AI_INSPECTOR_SETTINGS_FILE`, the tests point it at a temporary file, and they refuse to
  run if that redirect does not take effect.
- Settings: a provider forced by `AI_INSPECTOR_PROVIDER` no longer looks like the saved
  setting being ignored. The dialog now names every environment override, including the
  provider, and says which variable to unset. Saving an endpoint that belongs to a different
  provider asks for confirmation.

### Changed
- "Findings sent to AI" now defaults to 500 for Anthropic and OpenAI (150 for
  OpenAI-compatible servers, which usually have small context windows). With tool calls on
  this is a ceiling on what the assistant may pull, not what is sent up front.
- Settings: the three privacy choices (address redaction, the decoded packet tree, tool
  calls) are grouped under one "Privacy" heading. All three are on by default, and a test
  now holds them there.
- Smoother transcript while an answer streams in: settled messages are cached instead of
  re-parsed from Markdown on every tick, the document swap no longer lets the scroll bar
  flicker back to the top, blocks that have only half arrived (an open code fence, a partial
  table row) are held back until they are complete, and updates run on a steady cadence.

## [1.2.1] - 2026-09-17

### Fixed
- Windows packaging: stage the Qt translation catalogs and the HTML user guide (or a
  placeholder) so NSIS no longer aborts on an empty folder, and install asciidoctor in CI.
- Windows artifacts are packed with 7-Zip and verified, so a missing portable zip fails the
  build instead of passing silently.
- Releases are published with the GitHub CLI (the release action fails on Windows runners).

## [1.2.0] - 2026-09-17

### Added
- Windows support: `tools/build-windows.ps1`, an NSIS installer containing both plugins,
  a portable build and a plugins-only zip, published from tagged releases by GitHub Actions.
- Settings dialog: provider defaults fill the endpoint URL, the model is a dropdown that can
  load the models available to your key, the API key field holds an environment variable name
  (only the name is stored), and timeout, max response tokens and findings sent to AI accept
  **Auto** values chosen per provider.

### Fixed
- MSVC portability in shared helpers and unit-test warning flags.
- Tests run the interpreter CMake found instead of `python3`, decode tool output as UTF-8,
  and no longer read or overwrite the developer's real settings on macOS.
- Windows packaging no longer fails when the Qt install ships no translation catalogs.

## [1.1.0] - 2026-09-17

### Changed
- Renamed the project from "Wireshark Assist" to **AI Inspector**. Plugin files are now
  `ai_inspector_engine.so` / `ai_inspector.so`, display-filter fields `ai_inspector.*`,
  TShark statistic `-z ai_inspector,…`, environment variables `AI_INSPECTOR_*`, settings
  organisation `AI-Inspector`. An API key saved under the old name is still read.
- The assistant streams answers, shows elapsed time and can be stopped; each triage starts
  a fresh conversation (a repeated triage no longer resends earlier context).
- Default Anthropic model is `claude-haiku-4-5`.

### Added
- Overview dashboard: KPI cards; severity, timeline, traffic, category, host, protocol and
  encryption-version charts with drill-down.
- Findings tab search, severity/category filters and a detail pane.
- Assistant answers render Markdown, inline charts (```chart blocks), frame links and
  suggested filters validated with Wireshark's display-filter compiler; host names and
  addresses become working filters.
- Redacted addresses are restored locally in answers.
- `ANTHROPIC_MODEL` and `ANTHROPIC_BASE_URL` support.
- Engine summary JSON: `categories`, `timeline`, `top_hosts`.
- `tools/fetch-wireshark.sh`, `tools/package.sh`, GitLab CI, single version source.

### Fixed
- Crash on exit on macOS when timers created by the UI plugin outlived the unloaded library.
- The development app bundle did not load plugins or find dumpcap (`tools/run-wireshark.sh`).
- Assistant filter links could apply invalid filters (e.g. bare host names).

## [1.0.0] - 2026-09-17

### Added
- Native analysis engine (epan post-dissector) with findings for TLS/DTLS/X.509, QUIC,
  Bluetooth LE, TCP/IP/ICMP, DNS, HTTP/2, SSH, SMB, Kerberos, LDAP, RDP, 802.11 and
  cleartext protocols; expert info, `ai_inspector.*` fields and TShark report/JSON.
- Qt UI plugin with findings, report and AI assistant (Anthropic, OpenAI,
  OpenAI-compatible), address redaction and credential scrubbing.
- Unit tests, synthetic capture generator and integration tests including an
  in-application self-test.
