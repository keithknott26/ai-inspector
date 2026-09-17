#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Fetch the Wireshark source revision AI Inspector is developed against into
# upstream/wireshark (a separate git checkout, not part of this repository).
#
#   sh tools/fetch-wireshark.sh            # clone or update to the pinned commit
#   WIRESHARK_REPO=<url> sh tools/fetch-wireshark.sh
#
# The pinned commit lives in cmake/AIInspectorVersion.cmake
# (AI_INSPECTOR_WIRESHARK_COMMIT). Update it there when moving to a newer
# Wireshark, then rebuild and re-run the tests.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dest="$root/upstream/wireshark"
repo=${WIRESHARK_REPO:-https://gitlab.com/wireshark/wireshark.git}
commit=$(sed -n 's/^set(AI_INSPECTOR_WIRESHARK_COMMIT "\([0-9a-f]*\)").*/\1/p' "$root/cmake/AIInspectorVersion.cmake")
[ -n "$commit" ] || { echo "Could not read AI_INSPECTOR_WIRESHARK_COMMIT" >&2; exit 1; }

command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 1; }

if [ ! -d "$dest/.git" ]; then
  echo "Cloning Wireshark into $dest"
  mkdir -p "$dest"
  git -C "$dest" init -q
  git -C "$dest" remote add origin "$repo"
fi

current=$(git -C "$dest" rev-parse HEAD 2>/dev/null || true)
if [ "$current" = "$commit" ]; then
  echo "Wireshark already at $commit"
  exit 0
fi

echo "Fetching Wireshark $commit"
git -C "$dest" fetch --depth 1 origin "$commit"
git -C "$dest" checkout -q --detach "$commit"
echo "Wireshark checked out at $(git -C "$dest" rev-parse --short HEAD)"
