# AI Inspector for Wireshark

Find security, performance, and protocol issues in packet captures. Analyze locally in Wireshark, use optional AI explanations, or connect an agent through MCP.

No AI provider is required for local analysis. The assistant supports Anthropic, OpenAI, and OpenAI-compatible endpoints, including local Ollama.

![Capture triage with findings and clickable frame links](docs/images/assistant-triage.png)

## Get started

**Windows:** Download the installer or portable ZIP from [Releases](https://github.com/keithknott26/ai-inspector/releases). Both include Wireshark and the plugins.

1. Install, or unzip the portable build and run `Wireshark.exe`.
2. Open a capture.
3. Choose **Tools > AI Inspector > Open Inspector Panel**.

Live capture also needs [Npcap](https://npcap.com); opening saved captures does not.

**macOS and Linux:** [Build from source](docs/development-setup.md). Prebuilt packages are not available yet.

> AI Inspector targets a pinned Wireshark 4.7 development build with Qt 6. Use the bundled Windows build or build Wireshark and the plugins together. The plugins-only ZIP is for the matching release build, not a separately installed Wireshark.

## Features

- **Local analysis:** Flag weak encryption, cleartext credentials, suspicious traffic, and performance issues across TLS, QUIC, TCP/IP, DNS, HTTP, Bluetooth LE, and other protocols.
- **Dashboard and findings:** Explore charts, search and filter findings, jump to packets, and export a text report.
- **Optional AI assistant:** Triage captures, explain packets, and ask follow-up questions with streaming answers, charts, and clickable frame links.
- **TShark and MCP:** Get command-line reports or let an agent query captures without opening the GUI.

## AI and agent setup

Open **Settings** in the panel to choose a provider, model, and API key. See [Configuration](docs/configuration.md) for local endpoints, environment variables, and engine preferences.

For agent access, follow the [MCP setup guide](docs/mcp.md). The server requires TShark with the AI Inspector engine plugin.

## Privacy and limitations

- **Local engine:** Analysis runs locally without an AI provider.
- **AI assistant:** Sends analysis results and, when enabled and requested, the selected packet's decoded tree to your configured provider. IP/MAC redaction is on by default; recognized credential fields and patterns are scrubbed, but this is not guaranteed anonymization.
- **MCP:** Returns capture data to your client without the assistant's automatic redaction. The client may forward results to its AI provider.
- **Review required:** Findings are indicators, not proof of an attack. Verify AI conclusions against the packets.

## Documentation

- [Configuration and TShark usage](docs/configuration.md)
- [MCP setup and tools](docs/mcp.md)
- [Building, testing, and debugging](docs/development-setup.md)
- [Architecture](docs/architecture.md)
- [Contributing](CONTRIBUTING.md) · [Publishing](docs/publishing.md) · [Changelog](CHANGELOG.md)

## License

[GPL-2.0-or-later](LICENSE), the same as Wireshark.
