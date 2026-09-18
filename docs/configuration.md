# Configuration

AI Inspector's local analysis works without an AI provider. Configure the optional assistant in the panel's **Settings** dialog.

## AI assistant

- **Provider:** Fills in the default endpoint URL and model. Supports Anthropic, OpenAI, and OpenAI-compatible endpoints such as local Ollama.
- **Model:** Choose from the dropdown or enter a model name. **Refresh** loads the models available to your key.
- **API key:** Enter an environment-variable name, such as `ANTHROPIC_API_KEY`, to save only the name. A pasted key is stored in `~/.config/ai-inspector/api_key`, or `%APPDATA%\AI-Inspector\api_key` on Windows.
- **Request timeout, Max response tokens, Findings sent to AI:** Leave on **Auto** for provider-appropriate defaults, or enter an override.
- **Tool calls:** Let the assistant request capture data as needed. Turn this off for models that do not support tool calling.

The assistant accepts HTTPS endpoints and permits plain HTTP only for localhost. Redirects are not followed.

## Environment variables

Environment overrides take precedence over saved settings and are not written to disk.

| Variable | Purpose |
|---|---|
| `AI_INSPECTOR_API_KEY` | API key for any provider |
| `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`, `ANTHROPIC_BASE_URL` | Anthropic key, model, and base URL |
| `OPENAI_API_KEY` | OpenAI key |
| `AI_INSPECTOR_PROVIDER` | `anthropic`, `openai`, or `compatible` |
| `AI_INSPECTOR_ENDPOINT`, `AI_INSPECTOR_MODEL` | Endpoint and model overrides |
| `AI_INSPECTOR_KEY_FILE` | Alternate key file |
| `AI_INSPECTOR_SETTINGS_FILE` | Use this INI file instead of the system settings store |

macOS apps started from Finder do not see shell variables. Start Wireshark from a terminal with `tools/run-wireshark.sh`, or save the key in Settings.

## Engine preferences

Open **Edit > Preferences > Protocols > AI_INSPECTOR**.

| Preference | Default | Meaning |
|---|---|---|
| `ai_inspector.enabled` | on | Run the analysis |
| `ai_inspector.min_severity` | Info | Lowest severity shown in packet details |
| `ai_inspector.max_per_id` | 2000 | Per-finding annotation cap; counts continue |
| `ai_inspector.rtt_ms` | 500 | Latency threshold in milliseconds; HTTP uses 4× |
| `ai_inspector.scan_ports` | 40 | Distinct ports that count as a port scan |

## TShark

Use TShark from a build with the engine plugin loaded. Findings are available as reports, JSON, and `ai_inspector.*` display-filter fields.

```sh
tshark -r capture.pcapng -q -z ai_inspector,report       # text report
tshark -r capture.pcapng -q -z ai_inspector,json         # machine-readable summary
tshark -r capture.pcapng -Y 'ai_inspector.severity >= 3' # packets with warnings or errors
```

For agent access, see [MCP setup](mcp.md). For build instructions and plugin-loading checks, see [Development setup](development-setup.md).
