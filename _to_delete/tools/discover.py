#!/usr/bin/env python3
"""Read-only Wireshark discovery: the first part of a future graphical installer."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def inspect(tshark):
    def run(*args):
        return subprocess.run([str(tshark), *args], check=True, capture_output=True,
                              text=True, timeout=20).stdout
    version_text = run("--version")
    version = re.search(r"TShark \(Wireshark\) (\d+\.\d+\.\d+)", version_text)
    if not version:
        raise ValueError("Unrecognized TShark version output")
    folders = {}
    for line in run("-G", "folders").splitlines():
        name, sep, value = line.partition(":")
        if sep:
            folders[name.strip()] = value.strip()
    personal = folders.get("Personal Plugins")
    if not personal:
        raise ValueError("TShark did not report a personal plugin directory")
    # Let TShark supply its versioned path: macOS uses 4-6, not 4.6.
    result = {"tshark": str(tshark), "version": version.group(1),
              "native_plugin_root": personal,
              "legacy_epan_plugin_directory": str(Path(personal) / "epan"),
              "ui_plugin_directory_candidate": str(Path(personal) / "ui"),
              "lua_plugin_directory": folders.get("Personal Lua Plugins"),
              "installation_performed": False}
    result["note"] = "The installer must choose a tested artifact and plugin type for this exact supported host; a candidate path does not prove UI plugin support."
    gui = tshark.parent / ("Wireshark.exe" if sys.platform == "win32" else "Wireshark")
    if gui.is_file():
        gui_version = subprocess.run([str(gui), "--version"], check=True,
                                     capture_output=True, text=True, timeout=20).stdout
        qt = re.search(r"\+Qt\s+(\d+\.\d+\.\d+)", gui_version)
        result["wireshark"] = str(gui)
        result["qt_version"] = qt.group(1) if qt else None
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tshark", type=Path, help="Inspect a particular installation")
    args = parser.parse_args()
    candidates = [args.tshark] if args.tshark else []
    if not args.tshark:
        candidates += [Path("/Applications/Wireshark.app/Contents/MacOS/tshark"),
                       Path.home() / "Applications/Wireshark.app/Contents/MacOS/tshark"]
        for key in ("ProgramFiles", "ProgramFiles(x86)"):
            if os.environ.get(key):
                candidates.append(Path(os.environ[key]) / "Wireshark/tshark.exe")
        if shutil.which("tshark"):
            candidates.append(Path(shutil.which("tshark")))
    found, errors, seen = [], [], set()
    for candidate in candidates:
        if not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            found.append(inspect(resolved))
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            errors.append({"path": str(resolved), "error": str(error)})
    print(json.dumps({"installations": found, "errors": errors}, indent=2))
    return 0 if found else 1


if __name__ == "__main__":
    raise SystemExit(main())
