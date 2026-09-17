# AI Inspector for Wireshark

AI Inspector is a pair of native Wireshark plugins:

- **Analysis engine.** A protocol analysis engine that flags security, performance and protocol problems in common protocols.
- **Dockable panel.** A panel with an overview dashboard, a searchable findings list, and an AI assistant that explains captures and individual packets.

The analysis runs locally and works without any AI provider. The assistant is optional. It supports Anthropic (Claude), OpenAI, or any OpenAI-compatible endpoint such as a local Ollama.

## Features

**Analysis engine** (`ai_inspector_engine`, epan plugin)

- Runs as a post-dissector on every frame. Findings appear in:
  - the packet details tree;
  - Expert Information;
  - display-filter fields (`ai_inspector.*`);
  - TShark (`-z ai_inspector,report` or `-z ai_inspector,json`).
- Protocol coverage:

  | Area | Examples |
  |---|---|
  | TLS / DTLS / X.509 | SSLv3 and TLS 1.0/1.1 negotiated, NULL/EXPORT/RC4/DES/3DES suites, expired certificates, SHA-1 signatures, alerts, SNI/JA3/JA4 inventory |
  | QUIC | version negotiation, draft/legacy versions, 0-RTT, CONNECTION_CLOSE errors |
  | Bluetooth LE | legacy pairing, Just Works, short keys, LTK without encryption, cleartext GATT writes |
  | TCP / IP / ICMP | port and stealth scans, retransmissions, zero windows, high RTT, redirects |
  | DNS / HTTP | tunneling, NXDOMAIN bursts, attack patterns, scanner user agents, cleartext credentials |
  | LAN and legacy | ARP spoofing, rogue DHCP, SMBv1, Kerberos RC4, LDAP simple bind, FTP/Telnet/SNMP/MQTT, 802.11 WEP and deauth floods |

- Bounded memory, no network access, about 1–5% overhead on large captures.

**Panel** (`ai_inspector`, Qt UI plugin). Open it from Tools > AI Inspector.

- **Overview.** KPI cards and charts: severity, findings over time, traffic, categories, hosts, protocols and encryption versions. Click a chart to drill in.
- **Findings.** Search, severity and category filters, a detail pane, and one-click go-to-packet or apply-filter.
- **Assistant.**
  - Streaming answers, with Stop and elapsed-time display.
  - Capture triage, explain the selected packet, and follow-up questions.
  - Answers can include native charts, clickable display filters (validated with Wireshark's compiler) and frame links.
- **Report.** A plain-text findings report you can save or copy.

## Compatibility

| Item | Requirement |
|---|---|
| Wireshark | 4.7 development branch (Qt UI plugin API), pinned in `cmake/AIInspectorVersion.cmake` |
| Qt | 6.x, the same Qt Wireshark is built with |
| Platforms | macOS (developed and tested), Linux (CI) |

Plugins are binary modules. They must be built with the same Wireshark source revision, compiler and Qt as the Wireshark that loads them. They cannot be dropped into Wireshark 4.6 or an unrelated Wireshark build.

## Quick start

```sh
git clone <this repository> ai-inspector
cd ai-inspector
sh tools/build-development.sh --gui-test   # fetches Wireshark, builds, tests
sh tools/run-wireshark.sh                  # starts the development Wireshark
```

Then open a capture and choose **Tools > AI Inspector > Open Inspector Panel**.

Build prerequisites:

- **macOS:** Xcode command line tools, plus `brew install cmake ninja qt glib libgcrypt c-ares pcre2 speexdsp python`.
- **Linux:** see the package list in `.gitlab-ci.yml`.

`docs/development-setup.md` covers the details.

## Configuration

**Engine preferences.** Edit > Preferences > Protocols > AI_INSPECTOR.

| Preference | Default | Meaning |
|---|---|---|
| `ai_inspector.enabled` | on | Run the analysis |
| `ai_inspector.min_severity` | Info | Lowest severity shown in packet details |
| `ai_inspector.max_per_id` | 2000 | Per-finding annotation cap (counts continue) |
| `ai_inspector.rtt_ms` | 500 | Latency threshold (TCP/DNS; HTTP uses 4×) |
| `ai_inspector.scan_ports` | 40 | Distinct ports that count as a port scan |

**AI assistant.** Panel > ⚙ Settings, or environment variables (not saved):

| Variable | Purpose |
|---|---|
| `AI_INSPECTOR_API_KEY` | API key for any provider |
| `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`, `ANTHROPIC_BASE_URL` | Anthropic key, model and base URL |
| `OPENAI_API_KEY` | OpenAI key |
| `AI_INSPECTOR_PROVIDER` | `anthropic`, `openai` or `compatible` |
| `AI_INSPECTOR_ENDPOINT`, `AI_INSPECTOR_MODEL` | Endpoint and model overrides |
| `AI_INSPECTOR_KEY_FILE` | Alternate key file (default `~/.config/ai-inspector/api_key`, mode 600) |

macOS apps started from Finder do not see shell variables. Start Wireshark with `tools/run-wireshark.sh` from a terminal, or save the key in Settings.

**TShark.**

```sh
tshark -r capture.pcapng -q -z ai_inspector,report       # text report
tshark -r capture.pcapng -q -z ai_inspector,json         # machine-readable summary
tshark -r capture.pcapng -Y 'ai_inspector.severity >= 3' # packets with warnings or errors
```

## Privacy and safety

- **What is sent.** Only analysis results (findings, counts, timeline, hosts) and, when you explain a packet, that packet's decoded tree. Raw capture bytes are never sent.
- **Addresses.** IP and MAC addresses are replaced with placeholders such as `IP-3(private)` before sending. Answers show the real values again, locally only.
- **Credentials.** Credential fields (Authorization, cookies, passwords, SNMP communities, SMP keys) and `password=`/`token=` URL parameters are always removed.
- **Endpoints.** Plain `http://` is refused except for localhost, and redirects are not followed.
- **Answers.** Model output is untrusted text. Raw HTML is not interpreted and no remote resources load. Filters and packet jumps only happen when you click them, and only after validation.

## Project layout

```
cmake/AIInspectorVersion.cmake  version and pinned Wireshark commit (single source of truth)
native/common/                  C ABI between the plugins and shared helpers
native/engine/                  analysis engine plugin
native/ui/                      Qt UI plugin (panel, dashboard, charts, chat, AI client, settings)
tests/                          unit tests, mock AI server, integration runner
tools/                          fetch, build, run, package, test-capture generator
docs/                           architecture, development setup, publishing guide
```

## Testing

```sh
cmake -S . -B build-tests -G Ninja && cmake --build build-tests && ctest --test-dir build-tests
python3 tests/run_tests.py --build-dir build-development --gui
```

- **Unit tests.** Engine helpers, the AI client against a local mock server (streaming, errors, timeouts), redaction, settings, charts, chat rendering and panel behaviour.
- **Integration tests.** They generate synthetic captures and check the expected findings in TShark. They then run a self-test inside a real Wireshark, including AI round trips against the mock server with leak checks.

## Packaging

```sh
sh tools/package.sh --build-dir build-development
```

This creates two files in `dist/`:

- **Source archive.** `ai-inspector-<version>-src.tar.gz`.
- **Binary bundle.** Tied to the exact Wireshark build, and contains `MANIFEST.txt` and `install.sh`.

## Documentation

- [docs/architecture.md](docs/architecture.md): how the plugins work and the design rules.
- [docs/development-setup.md](docs/development-setup.md): building, running and debugging.
- [docs/publishing.md](docs/publishing.md): GitLab project, CI, releases and the upstream Wireshark route.
- [CONTRIBUTING.md](CONTRIBUTING.md): workflow, style, and how to add checks and charts.
- [CHANGELOG.md](CHANGELOG.md).

## License

GPL-2.0-or-later, the same as Wireshark. See [LICENSE](LICENSE).

AI output can be wrong. Verify conclusions against the packets.
