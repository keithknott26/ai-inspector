# Development setup

## 1. Prerequisites

**macOS**
```sh
xcode-select --install
brew install cmake ninja qt glib libgcrypt c-ares pcre2 speexdsp python git
```

**Ubuntu 24.04**: see the package list in `.gitlab-ci.yml`.

## 2. Get the Wireshark source

```sh
sh tools/fetch-wireshark.sh
```

This clones Wireshark into `upstream/wireshark` and checks out the commit pinned in
`cmake/AIInspectorVersion.cmake`. `upstream/` is ignored by git. If you already have a
Wireshark clone, you can point `WIRESHARK_REPO` at it.

## 3. Build, test, install

```sh
sh tools/build-development.sh              # build + unit + integration tests
sh tools/build-development.sh --gui-test   # also run the in-application self-test
sh tools/build-development.sh --skip-tests # build only
```

What the script does:

1. **Registers the plugins.** Writes two small untracked CMake stubs in the Wireshark
   tree, `plugins/epan/ai_inspector_engine/` and `plugins/ui/ai_inspector/`. Each one
   includes the real build files from `native/`. No Wireshark source file is changed.
2. **Builds.** Configures `build-development/` with
   `CUSTOM_PLUGIN_SRC_DIR="epan/ai_inspector_engine;ui/ai_inspector"` and builds
   `wireshark`, `tshark`, `dumpcap` and both plugins with one compiler and one Qt.
3. **Tests.** Runs `ctest` and `tests/run_tests.py` (it creates a virtualenv with scapy
   and cryptography in the build directory).
4. **Installs.** Leaves the plugins in the build's plugin folder (default).
   `--install personal` copies them to `~/.local/lib/wireshark/plugins/<X-Y>/{epan,ui}`
   instead.

A first build takes 30–60 minutes. After editing plugin sources, rebuild only the
plugins:

```sh
cmake --build build-development --target ai_inspector_engine ai_inspector
```

## 4. Run

```sh
sh tools/run-wireshark.sh [-r capture.pcapng]
build-development/run/tshark -r capture.pcapng -q -z ai_inspector,report
```

On macOS the GUI binary is inside `run/wireshark.app`, where Wireshark does not
detect the build directory. `run-wireshark.sh` sets `WIRESHARK_PLUGIN_DIR` and links
`dumpcap` next to the binary.

## 5. Tests in detail

| Suite | Command |
|---|---|
| Unit | `cmake -S . -B build-tests -G Ninja && cmake --build build-tests && ctest --test-dir build-tests` |
| Integration | `python3 tests/run_tests.py --build-dir build-development [--gui]` |
| Test captures only | `python3 tools/make-test-captures.py /tmp/ai-inspector-captures` |

The unit tests run a local mock AI server (`tests/mock_ai_server.py`), which
supports streaming and non-streaming responses for both provider APIs. The
integration test starts Wireshark with `AI_INSPECTOR_UI_SELFTEST=1`. It drives the
real panel against the mock server and checks that no credentials or raw addresses
are sent.

Useful environment variables:

| Variable | Purpose |
|---|---|
| `AI_INSPECTOR_UI_SELFTEST=1` | Run the in-app self-test and exit |
| `AI_INSPECTOR_UI_SELFTEST_FRAME=N` | Frame the self-test explains |
| `AI_INSPECTOR_UI_SCREENSHOTS=dir` | Save panel screenshots during the self-test |
| `AI_INSPECTOR_PROVIDER` / `_ENDPOINT` / `_MODEL` / `_API_KEY` / `_KEY_FILE` | AI settings overrides |

## 6. Debugging tips

- **Engine output.** `tshark -r file -T fields -e frame.number -e ai_inspector.id`
  shows findings per frame.
- **Plugin loading.** Help > About Wireshark > Plugins shows whether both plugins
  loaded. `tshark -G plugins` lists the engine.
- **Crashes on quit.** Check for Qt objects or timers that outlive the main window
  (see docs/architecture.md). On macOS, crash reports are in
  `~/Library/Logs/DiagnosticReports`.
- **Memory checks (Linux).** `valgrind build-development/run/tshark -r capture -q -z ai_inspector,report`.
