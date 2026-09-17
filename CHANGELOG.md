# Changelog

All notable changes to AI Inspector. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The version is defined in
`cmake/AIInspectorVersion.cmake`.

## [Unreleased]

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
