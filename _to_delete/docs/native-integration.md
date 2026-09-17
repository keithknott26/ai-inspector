# Native integration architecture

Target: Wireshark development branch (4.7.x), upstream commit
`c910cf86a6bd8a805addd07253d0e19165a46904`, which has the dedicated Qt UI plugin API
(`uiqt_register_plugin`). The legacy 4.6 adapter prototype has been retired.

## Why two plugins

`uiqt_plugin_init()` runs after `epan_init()`, so a UI plugin cannot register dissector
fields, expert infos or preferences in the normal registration phase. The work is split:

```
epan plugin: wireshark_assist_engine            ui plugin: wireshark_assist
  proto "ws_assist", hf fields, expert infos,     Tools > Wireshark Assist menu (plugin_if)
  preferences, post-dissector                     QDockWidget panel on WiresharkMainWindow
  analyzers (TLS, QUIC, BLE, DNS, HTTP, ...)      AI client (QNetworkAccessManager, async)
  tap "ws_assist"  ── assist_tap_data_t ──▶        tap listener → engine API table
  stat tap: tshark -z ws_assist,report|json       plugin_if: goto frame, apply filter,
                                                    capture_file (selected packet tree)
```

The tap carries a pointer to `assist_engine_api_t` (`native/common/assist_api.h`), a
versioned C function table that returns JSON or text. The two shared objects never link
against each other, and C++ types never cross the boundary.

## Engine design

- **Fields.** Uses `set_postdissector_wanted_hfids()` with about 150 fields, so values
  are available on the first pass without a visible tree. Field IDs are resolved in the
  init routine; missing fields only disable the related checks and are listed in the
  report.
- **Analysis once.** Analysis runs once per frame, on the first pass (`!PINFO_FD_VISITED`).
  Later passes render cached findings, so filtering and redissection are consistent.
- **State.** All state is reset in the init routine, and a generation counter increments
  on every reset.
- **Memory bounds.** 24 findings per frame; a configurable number of annotations per
  finding ID (counts keep increasing); 4096 finding types; 200k tracked heuristic keys.
  The port-scan tracker stops per-pair tracking once a pair is reported.
- **Locking.** A mutex guards state for API calls made from the UI.
- **Performance.** Measured on 151k frames of mixed traffic with full dissection:
  28.3 s baseline versus 28.6–29.7 s with the engine.

## UI design

- **Host window.** Found by Qt introspection: exactly one `WiresharkMainWindow`, and an
  ambiguous host is refused. The callback's `gui_data` is not a `QWidget` and is never
  cast.
- **Stale-capture guard.** Findings record the engine generation. "Go to packet" and
  "Apply filter" refuse to act, and refresh the list instead, if the capture changed.
- **Explain packet.** Reads `capture_file::edt->tree` for the selected frame through
  `plugin_if_get_capture_file`, on the GUI thread. Hidden items and the assist subtree
  are skipped, and output is capped at 600 lines / 32k characters.
- **Secrets.** Values of sensitive fields are collected and scrubbed from every line,
  then address redaction is applied.
- **Requests.** One at a time, with a timeout, cancel, no redirects, a 4 MB response cap,
  and a bounded history of 6 exchanges.

## Verification (Linux, GCC 13 and Clang, Qt 6.4, same upstream revision)

- Both plugins compile with Wireshark's `-Werror` flags. All sources also pass Clang with
  `-Wshorten-64-to-32 -Wcomma -Wdocumentation -Wmissing-prototypes -Werror` (AppleClang's
  extra warnings).
- 91 integration checks, including a self-test inside a running Wireshark (offscreen Qt):
  dock, findings table, report, go to frame, selected-packet tree, display filter, and AI
  triage plus explain for both provider protocols, with leak checks.
- Qt unit tests pass under AddressSanitizer and UBSan. Valgrind memcheck is clean on all
  test and fuzz captures.

Not verified here: the macOS build itself (Homebrew Qt 6.10.1, AppleClang) and real
provider endpoints. Run `sh tools/build-development.sh --gui-test` on the Mac for that.

## Upstream path

A provider-independent dock-registration API for Qt UI plugins would remove the
main-window discovery. See `docs/upstream-plan.md`.
