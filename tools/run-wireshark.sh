#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Launch the development Wireshark with the AI Inspector plugins.
# On macOS the GUI binary lives inside run/wireshark.app, where Wireshark does
# not detect the build directory, so point it at the build's plugin folder.
set -eu
ai_inspector_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${AI_INSPECTOR_BUILD_DIR:-"$ai_inspector_root/build-development"}
exe="$build_dir/run/wireshark"
[ -x "$build_dir/run/wireshark.app/Contents/MacOS/wireshark" ] && exe="$build_dir/run/wireshark.app/Contents/MacOS/wireshark"
[ -x "$exe" ] || { echo "Wireshark not built: run tools/build-development.sh" >&2; exit 1; }
# The GUI looks for dumpcap next to its own binary; inside the app bundle it isn't there.
exe_dir=$(dirname "$exe")
if [ -x "$build_dir/run/dumpcap" ] && [ ! -e "$exe_dir/dumpcap" ]; then
  ln -s "$build_dir/run/dumpcap" "$exe_dir/dumpcap"
fi
WIRESHARK_PLUGIN_DIR="$build_dir/run/plugins/wireshark"
export WIRESHARK_PLUGIN_DIR
exec "$exe" "$@"
