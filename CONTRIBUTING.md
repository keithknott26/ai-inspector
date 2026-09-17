# Contributing to AI Inspector

Thanks for helping. This guide covers the workflow, code conventions and the two
most common changes: adding an analysis check and adding a chart.

## Workflow

1. Create a branch from `main`: `git switch -c feature/short-description`.
2. Build and test locally (see [docs/development-setup.md](docs/development-setup.md)):
   ```sh
   sh tools/build-development.sh --gui-test
   ```
3. Commit in small, focused commits (see *Commit messages*).
4. Push and open a merge request against `main`. CI runs the unit tests on every
   push; the full plugin build runs on `main`, tags, or when triggered manually.
5. A reviewer approves, then the MR is merged (squash or rebase, no merge commits).

## Merge request checklist

- [ ] `ctest --test-dir build-tests` passes.
- [ ] `python3 tests/run_tests.py --build-dir build-development --gui` passes.
- [ ] New checks have a test packet in `tools/make-test-captures.py` and an entry in
      `tests/run_tests.py` (`EXPECT`, and `FORBID` for false-positive guards).
- [ ] No new compiler warnings (the engine is built with Wireshark's `-Werror`; also
      check with Clang, which macOS uses).
- [ ] User-visible changes are listed under *Unreleased* in `CHANGELOG.md`.
- [ ] Docs updated when behaviour, settings or filters change.
- [ ] Nothing sends additional capture data to AI providers without redaction and a
      settings/privacy review.

## Code conventions

- C++17 and Qt 6. 4-space indentation, ~130 columns; `.clang-format` and `.editorconfig`
  describe the style. Format only lines you change (`git clang-format`).
- Every source file starts with `SPDX-License-Identifier: GPL-2.0-or-later`.
- Engine code must not depend on Qt. UI code must not call Wireshark APIs outside
  `native/ui/ai_inspector_ui.cpp` and `native/ui/selftest.cpp`; everything else goes
  through `aiinspector::Host` so it stays unit-testable.
- The engine <-> UI boundary is the C ABI in `native/common/ai_inspector_api.h`.
  Changing it requires bumping `AI_INSPECTOR_API_ABI`.
- **Plugin lifetime:** Wireshark unloads UI plugins before `QApplication` is destroyed.
  Never use `QTimer::singleShot(..., qApp, lambda)` or objects parented to `qApp`.
  Parent objects to widgets we own and use queued `QMetaObject::invokeMethod` on them.
- Treat all packet data and all model output as untrusted: bound sizes, escape or
  clean text, never execute or auto-apply anything.

## Adding an analysis check

The step-by-step guide is at the top of `native/engine/ai_inspector_engine.cpp`. In short:

1. Add any new field names to `AI_INSPECTOR_FIELDS`.
2. Implement the logic in the matching `Analyzer` method and call
   `add(severity, category, "PROTO", "proto.id", "Title", detail, filter)`.
3. Choose a stable, lowercase, dotted ID; it is used in filters, tests and AI context.
4. Keep memory bounded (`bump()`, `once()`, existing caps).
5. Add a synthetic packet and the expected ID to the tests.

Severity guidance: **Error** = exploitable or clearly broken security; **Warning** =
likely problem or strong indicator; **Note** = worth attention; **Info** = context.

## Adding a dashboard chart

1. If the data is not in the summary JSON yet, add it in `build_summary_json()` in the
   engine (keep it small; this JSON is also sent to the AI provider).
2. In `native/ui/dashboard.cpp`, create a `ChartWidget` in the constructor and fill a
   `ChartSpec` in `setSummary()`.
3. Add a panel assertion in `tests/ui_tests.cpp` if the chart has interactions.

## Commit messages

```
area: short imperative summary (<= 72 chars)

Why the change is needed and what it does. Wrap at 72 columns.
```

Areas: `engine`, `ui`, `ai`, `tests`, `build`, `docs`, `ci`.

If a change was created with help from an AI coding assistant, say so in the MR
description and add a trailer such as `Assisted-by: Claude` to the commits, so
reviewers know to review with that in mind.

## Releasing

1. Bump `cmake/AIInspectorVersion.cmake` and move *Unreleased* entries in
   `CHANGELOG.md` under the new version.
2. Merge to `main`, then tag: `git tag -a v1.2.0 -m "AI Inspector 1.2.0" && git push --tags`.
3. The tag pipeline builds and packages `dist/`; attach the artifacts to a GitLab
   release (Deploy > Releases).
