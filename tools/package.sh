#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Package AI Inspector.
#
#   sh tools/package.sh [--build-dir DIR] [--source-only]
#
# Produces in dist/:
#   ai-inspector-<version>-src.tar.gz
#       Source release (git archive of HEAD when run in a git checkout).
#   ai-inspector-<version>-<os>-<arch>-wireshark-<commit>.tar.gz
#       Binary plugins for the Wireshark build in --build-dir, with MANIFEST.txt
#       (exact Wireshark commit, Qt and compiler) and install.sh.
#
# Binary plugins only work in a Wireshark built from the same source revision,
# compiler and Qt. They are not a substitute for building against the target.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir="$root/build-development"
source_only=0
while [ $# -gt 0 ]; do
  case "$1" in
    --build-dir) build_dir=$2; shift 2 ;;
    --source-only) source_only=1; shift ;;
    -h|--help) sed -n '3,17p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

ver() { sed -n "s/^set($1 \\([0-9]*\\)).*/\\1/p" "$root/cmake/AIInspectorVersion.cmake"; }
version="$(ver AI_INSPECTOR_VERSION_MAJOR).$(ver AI_INSPECTOR_VERSION_MINOR).$(ver AI_INSPECTOR_VERSION_PATCH)"
ws_commit=$(sed -n 's/^set(AI_INSPECTOR_WIRESHARK_COMMIT "\([0-9a-f]*\)").*/\1/p' "$root/cmake/AIInspectorVersion.cmake")
dist="$root/dist"
mkdir -p "$dist"

# ---- source archive
src="$dist/ai-inspector-$version-src.tar.gz"
if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$root" archive --format=tar.gz --prefix="ai-inspector-$version/" -o "$src" HEAD
else
  base=$(basename "$root")
  # Anchored excludes: only top-level build/upstream folders, not files such as
  # tools/build-development.sh.
  tar -C "$root/.." -czf "$src" --anchored \
    --exclude="$base/upstream" --exclude="$base/build" --exclude="$base/build-*" --exclude="$base/dist" \
    --exclude="$base/Claude outputs" --exclude='*/__pycache__' --exclude='*/.DS_Store' "$base"
fi
echo "Source archive: $src"
[ "$source_only" = 1 ] && exit 0

# ---- binary bundle
engine=$(find "$build_dir/run" -name 'ai_inspector_engine.so' -path '*/epan/*' 2>/dev/null | head -1)
ui=$(find "$build_dir/run" -name 'ai_inspector.so' -path '*/ui/*' 2>/dev/null | head -1)
if [ -z "$engine" ] || [ -z "$ui" ]; then
  echo "Built plugins not found under $build_dir/run (run tools/build-development.sh first)" >&2
  exit 1
fi
plugin_ver_dir=$(basename "$(dirname "$(dirname "$engine")")")
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
name="ai-inspector-$version-$os-$arch-wireshark-$(printf %.10s "$ws_commit")"
stage=$(mktemp -d)
mkdir -p "$stage/$name/plugins/$plugin_ver_dir/epan" "$stage/$name/plugins/$plugin_ver_dir/ui"
cp "$engine" "$stage/$name/plugins/$plugin_ver_dir/epan/"
cp "$ui" "$stage/$name/plugins/$plugin_ver_dir/ui/"
cp "$root/README.md" "$root/LICENSE" "$root/CHANGELOG.md" "$stage/$name/"

qt=$(sed -n 's/^Qt6Core_DIR:PATH=//p' "$build_dir/CMakeCache.txt" 2>/dev/null | head -1)
cc=$(sed -n 's/^CMAKE_CXX_COMPILER:[A-Z]*=//p' "$build_dir/CMakeCache.txt" 2>/dev/null | head -1)
cat > "$stage/$name/MANIFEST.txt" <<MANIFEST
AI Inspector $version
Wireshark source commit : $ws_commit
Plugin directory id     : $plugin_ver_dir
Platform                : $os $arch
Qt package              : ${qt:-unknown}
C++ compiler            : ${cc:-unknown} $("${cc:-c++}" --version 2>/dev/null | head -1)
Built                   : $(date -u +%Y-%m-%dT%H:%M:%SZ)

These binaries load only in a Wireshark built from the commit above with the
same compiler and Qt. Install with ./install.sh or copy plugins/ into your
personal plugin folder (see README.md).
MANIFEST

cat > "$stage/$name/install.sh" <<'INSTALL'
#!/bin/sh
# Copies the plugins into the per-user Wireshark plugin folder.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
dest=${1:-"$HOME/.local/lib/wireshark/plugins"}
mkdir -p "$dest"
cp -R "$here/plugins/." "$dest/"
echo "Installed into $dest"
find "$dest" -name 'ai_inspector*.so'
echo "Restart Wireshark, then open Tools > AI Inspector."
INSTALL
chmod +x "$stage/$name/install.sh"
tar -C "$stage" -czf "$dist/$name.tar.gz" "$name"
rm -rf "$stage"
echo "Binary bundle : $dist/$name.tar.gz"
