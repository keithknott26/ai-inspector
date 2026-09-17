#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build a distributable Wireshark.app + .dmg (macOS) that contains the
# AI Inspector plugins, optionally signed with a Developer ID and notarized.
#
#   sh tools/make-mac-dmg.sh [--build-dir DIR] [--sign "Your Name (TEAMID)"] [--notary-profile NAME]
#
#   --sign            Developer ID identity, WITHOUT the "Developer ID Application: " prefix.
#                     List yours with: security find-identity -v -p codesigning
#   --notary-profile  keychain profile created once with:
#                     xcrun notarytool store-credentials NAME --apple-id you@example.com --team-id TEAMID
#
# Without --sign the app is ad-hoc signed and users must clear the quarantine flag.
set -eu
say() { printf '\n==> %s\n' "$*"; }

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir="$root/build-release-mac"
identity=""
notary_profile=""
while [ $# -gt 0 ]; do
  case "$1" in
    --build-dir) build_dir=$2; shift 2 ;;
    --sign) identity=$2; shift 2 ;;
    --notary-profile) notary_profile=$2; shift 2 ;;
    -h|--help) sed -n '3,15p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
[ "$(uname -s)" = Darwin ] || { echo "macOS only" >&2; exit 1; }
[ -z "$notary_profile" ] || [ -n "$identity" ] || { echo "--notary-profile requires --sign" >&2; exit 2; }

upstream="$root/upstream/wireshark"
[ -f "$upstream/CMakeLists.txt" ] || sh "$root/tools/fetch-wireshark.sh"
mkdir -p "$upstream/plugins/epan/ai_inspector_engine" "$upstream/plugins/ui/ai_inspector"
printf 'include("${AI_INSPECTOR_SOURCE_DIR}/native/engine/CMakeLists.txt")\n' > "$upstream/plugins/epan/ai_inspector_engine/CMakeLists.txt"
printf 'include("${AI_INSPECTOR_SOURCE_DIR}/native/ui/CMakeLists.txt")\n' > "$upstream/plugins/ui/ai_inspector/CMakeLists.txt"

brew_prefix=$(brew --prefix)
python3 -m pip install --quiet --user dmgbuild biplist 2>/dev/null || python3 -m pip install --quiet --break-system-packages dmgbuild biplist

# A separate build dir with the app bundle enabled (the dev build turns it off).
say "Configuring $build_dir"
cmake -S "$upstream" -B "$build_dir" -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_PREFIX_PATH="$(brew --prefix qt);$brew_prefix" \
  -DENABLE_APPLICATION_BUNDLE=ON -DBUILD_stratoshark=OFF \
  -DCUSTOM_PLUGIN_SRC_DIR="epan/ai_inspector_engine;ui/ai_inspector" \
  -DAI_INSPECTOR_SOURCE_DIR="$root"

export CODE_SIGN_IDENTITY="$identity"   # read by Wireshark's osx-app.sh / osx-dmg.sh
say "Building app bundle${identity:+ (signing as $identity)}"
cmake --build "$build_dir" --target wireshark_app_bundle

app="$build_dir/run/Wireshark.app"
find "$app/Contents/PlugIns" -name 'ai_inspector*' | grep -q . || { echo "AI Inspector plugins missing from $app" >&2; exit 1; }

say "Building disk image"
cmake --build "$build_dir" --target wireshark_dmg
dmg=$(ls -t "$build_dir"/run/Wireshark*.dmg | grep -v dSYM | head -1)

if [ -n "$notary_profile" ]; then
  say "Notarizing $dmg (usually a few minutes)"
  xcrun notarytool submit "$dmg" --keychain-profile "$notary_profile" --wait
  xcrun stapler staple "$dmg"
  spctl --assess --type open --context context:primary-signature --verbose=2 "$dmg"
fi

say "Done"
echo "Disk image: $dmg"
