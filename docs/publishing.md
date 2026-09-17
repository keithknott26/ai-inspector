# Publishing AI Inspector

This guide covers putting the project on GitLab, getting CI green, and cutting releases. It also covers the optional route of contributing to upstream Wireshark.

## 1. Create the repository

```sh
cd ai-inspector                      # the project root (contains README.md)
git init -b main
git add .
git status                           # check: no build-*/, dist/, upstream/ or API keys
git commit -m "Initial import of AI Inspector 1.1.0"
```

`.gitignore` already excludes build output, `dist/`, the fetched Wireshark tree (`upstream/`) and local files. Never commit `~/.config/ai-inspector/api_key` or a `.env` file.

## 2. Create the GitLab project and push

1. On GitLab choose **New project > Create blank project**.
2. Name it `ai-inspector`, pick a group and visibility, and **untick** "Initialize repository with a README".
3. Push:

```sh
git remote add origin git@gitlab.com:<group>/ai-inspector.git   # or the HTTPS URL
git push -u origin main
```

Recommended project settings:

- **Settings > Repository > Protected branches:** protect `main` (merge via MR only).
- **Settings > Merge requests:** require pipelines to succeed; enable "Delete source branch" by default.
- **Settings > CI/CD > Runners:** the `plugin-build` job needs a runner with ~8 GB RAM and ~15 GB disk (it compiles Wireshark). GitLab's shared `saas-linux-medium` or larger works, or register your own runner.

## 3. CI pipeline

`.gitlab-ci.yml` defines two stages:

| Job | When | What |
|---|---|---|
| `unit-tests` | every push and MR | builds and runs `ctest` (engine helpers, AI client vs mock server, redaction, charts, panel) |
| `plugin-build` | tags, default branch, or manual | fetches the pinned Wireshark, builds both plugins, runs integration + GUI self-test, packages `dist/` |

`plugin-build` uses ccache, so the first run is slow (~30–60 min) and later runs are much faster.

## 4. Release

1. Bump the version in `cmake/AIInspectorVersion.cmake`.
2. Move the `[Unreleased]` notes in `CHANGELOG.md` under the new version.
3. Commit, then tag:

```sh
git commit -am "Release 1.1.0"
git tag -a v1.1.0 -m "AI Inspector 1.1.0"
git push origin main --tags
```

4. When the tag pipeline finishes, open **Deploy > Releases > New release**, select the tag, paste the changelog section, and link the `dist/` artifacts from the `plugin-build` job (source tarball and binary bundle).

The binary bundle only works with a Wireshark built from the same commit, compiler and Qt (see `MANIFEST.txt`). For most users the source tarball plus `tools/build-development.sh` is the supported install path.

## 5. Updating the Wireshark pin

1. Change `AI_INSPECTOR_WIRESHARK_COMMIT` in `cmake/AIInspectorVersion.cmake`.
2. Run `sh tools/fetch-wireshark.sh && sh tools/build-development.sh --gui-test`.
3. Fix any API breaks (the Qt plugin API in 4.7 is still moving), note it in the changelog, and open an MR.

## 6. Optional: contributing upstream to Wireshark

Wireshark development happens at <https://gitlab.com/wireshark/wireshark>. Plugins can stay out of tree indefinitely; upstreaming is only worth it for pieces with broad value.

1. Read Wireshark's `CONTRIBUTING.md` and the Developer's Guide (coding style, commit messages, no C++ exceptions across the epan boundary).
2. Fork `wireshark/wireshark` on GitLab and create a topic branch.
3. Good candidates, smallest first:
   - individual expert-info checks added directly to the relevant dissector (e.g. weak TLS suites in `packet-tls-utils.c`);
   - a public Qt plugin API for adding a dock widget (today the UI plugin locates the main window itself);
   - the engine as `plugins/epan/ai_inspector` (larger review; the AI client would likely stay out of tree).
4. Open an MR against `master`, fill in the template, and disclose AI-assisted code as Wireshark's contribution policy requires.
5. Expect review iterations; keep this project compatible with the pinned commit in the meantime.
