# Upstream contribution path

The supplied merge-request URL is a listing filtered for open requests containing
`openai`. It is not a specific proposal or an approval to merge an assistant.

Official source: https://gitlab.com/wireshark/wireshark.git

The local checkout is on `codex/native-assistant-feasibility`. Repository-local
hooks and the commit template are configured according to CONTRIBUTING.md.
No fork, remote push, commit, merge request, or message to maintainers has been
created. The prototype currently lives outside the upstream tree.

## Distinguish distribution from upstream inclusion

- A separately distributed native plugin does not inherently require an upstream
  merge request. It can use existing extension APIs and a tested installer.
- Including a plugin in Wireshark's source/distribution, or adding a core UI
  extension API, goes through a public fork, topic branch, tests, and merge request.
- Upstream review does not guarantee acceptance or availability in a particular
  Wireshark release.

## Proposed first upstream discussion/change

Assess a small, provider-independent dock extension API for Qt UI plugins.
The purpose is to avoid discovering internal main-window classes and to give
plugins a defined ownership/lifecycle contract.

Suggested scope to discuss (not implemented):

1. Register a named dock-widget factory, materialized on the GUI thread once a
   main window exists.
2. Define host ownership, close/reopen behavior, and layout persistence.
3. Associate capture actions with the correct host and expose a capture-generation
   identifier so delayed results cannot act on a replacement capture.
4. Extend the native plugin demo with a minimal dock and add focused lifecycle
   coverage.

Keep provider authentication, cloud requests, model selection, and AI prompting
out of this first infrastructure change. This is an engineering recommendation,
not an expressed requirement or acceptance decision from Wireshark maintainers.
The assistant could then use that API as an external plugin; a later proposal
could address bundling if maintainers want it.

## Contribution requirements checked

- Use the current upstream source and a focused topic branch.
- Build/test before submission; the current prototype is not MR-ready.
- Follow the repository style, license and shipped hooks.
- Include `Assisted-by: OpenAI Codex` in commits and disclose assistance in the MR.
- Submit through a public personal GitLab fork; allow maintainer edits as the
  developer guide requests.

References:

- [CONTRIBUTING.md](https://gitlab.com/wireshark/wireshark/-/blob/c910cf86a6bd8a805addd07253d0e19165a46904/CONTRIBUTING.md)
- [Developer contribution guide](https://www.wireshark.org/docs/wsdg_html_chunked/ChSrcContribute.html)
- [Out-of-tree plugin example](https://gitlab.com/wireshark/wireshark/-/tree/c910cf86a6bd8a805addd07253d0e19165a46904/doc/plugins.example)
