#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Integration tests for the native AI Inspector plugins.

  python3 tests/run_tests.py --build-dir build-development [--gui]

1. Generates synthetic captures (tools/make-test-captures.py; needs scapy + cryptography).
2. Runs the built TShark with the analysis engine and checks the expected
   finding IDs, -z ai_inspector,report|json, two-pass filtering and fuzz robustness.
3. With --gui, starts the built Wireshark with AI_INSPECTOR_UI_SELFTEST=1 against a
   local mock AI server (Anthropic and OpenAI protocols) and checks that no
   addresses or credentials leave the process.
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EXPECT = {
    "tls.pcap": ["tls.client_offers_weak", "tls.no_sni", "tls.deprecated_version", "tls.weak_cipher.rc4",
                 "x509.expired", "tls.alert.unknown_ca", "tls.weak_cipher.64_bit_block_cipher_sweet32",
                 "tls.ssl_negotiated", "tls.ssl_protocol"],
    "quic.pcap": ["quic.version_negotiation", "quic.draft_version", "quic.zero_rtt", "quic.nonstandard_port"],
    "ble.pcap": ["btle.device_name_advertised", "btsmp.legacy_pairing", "btsmp.just_works", "btsmp.short_key",
                 "btsmp.no_mitm", "btsmp.ltk_cleartext", "btatt.cleartext_write", "btsmp.pairing_failed"],
    "dns_http.pcap": ["dns.tunneling_suspect", "dns.any_query", "dns.nxdomain_burst", "http.scanner_ua",
                      "http.attack_pattern", "http.basic_auth_cleartext", "http.server_error",
                      "http.secret_in_uri", "http.cookie_cleartext"],
    "misc.pcap": ["tcp.xmas_scan", "tcp.null_scan", "tcp.port_scan", "ftp.cleartext_password", "ftp.cleartext_login",
                  "telnet.session", "smb.v1", "ntp.monlist", "arp.mac_changed", "dhcp.multiple_servers",
                  "icmp.redirect", "snmp.default_community", "ssh.v1", "rdp.standard_security",
                  "ldap.simple_bind_cleartext", "mqtt.cleartext_credentials"],
    "wlan.pcap": ["wlan.deauth_flood", "wlan.wep"],
    "fuzz.pcap": [],
    "fuzz_ble.pcap": [],
}
# Findings that must NOT appear (false-positive guards).
FORBID = {
    "tls.pcap": [],
    "fuzz.pcap": ["tcp.port_scan"],
}
SECRETS = ["s3cret", "hunter2", "YWRtaW46aHVudGVyMg", "password=secret", "sid=abc"]

failures = []


def check(name, cond, info=""):
    print(("  ok   " if cond else "  FAIL ") + name + ("" if cond else "\n       " + str(info)[:600]))
    if not cond:
        failures.append(name)


def find(build, name):
    cap = name[:1].upper() + name[1:]
    for pattern in (f"run/{name}", f"run/*/{name}.exe", f"run/{name}.exe", f"run/Wireshark.app/Contents/MacOS/{name}", f"run/Wireshark.app/Contents/MacOS/{cap}",
                    f"run/{cap}.app/Contents/MacOS/{cap}"):
        hits = glob.glob(os.path.join(build, pattern))
        if hits:
            return hits[0]
    return shutil.which(name)


def run_text(cmd, **kw):
    """subprocess.run that always returns str stdout/stderr (never None), decoding as UTF-8.

    Avoids text=True: on Windows a decode error in subprocess's reader thread
    leaves stdout as None instead of raising."""
    p = subprocess.run(cmd, capture_output=True, **kw)
    p.stdout = (p.stdout or b"").decode("utf-8", "replace")
    p.stderr = (p.stderr or b"").decode("utf-8", "replace")
    return p


def tshark(exe, args, env=None, timeout=300):
    e = dict(os.environ)
    e.update(env or {})
    return run_text([exe] + args, env=e, timeout=timeout)


def test_engine(exe, caps):
    print("TShark engine")
    p = tshark(exe, ["-G", "plugins"])
    check("engine plugin loaded", "ai_inspector_engine" in p.stdout, p.stdout[-400:] + p.stderr[-400:])
    for cap, expected in EXPECT.items():
        path = os.path.join(caps, cap)
        p = tshark(exe, ["-r", path, "-T", "fields", "-e", "ai_inspector.id"])
        check(f"{cap}: exit 0", p.returncode == 0, p.stderr)
        ids = {x for line in p.stdout.splitlines() for x in line.split(",") if x}
        for x in expected:
            check(f"{cap}: {x}", x in ids, sorted(ids))
        for x in FORBID.get(cap, []):
            check(f"{cap}: no {x}", x not in ids, sorted(ids))
        p = tshark(exe, ["-r", path, "-q", "-z", "ai_inspector,report"])
        check(f"{cap}: -z report", p.returncode == 0 and "capture findings report" in p.stdout, p.stderr[-300:])
        p = tshark(exe, ["-r", path, "-q", "-z", "ai_inspector,json"])
        try:
            doc = json.loads(p.stdout.strip().splitlines()[-1])
            ok = doc["capture"]["frames_analyzed"] > 0 and {f["id"] for f in doc["findings"]} >= set(expected)
        except Exception as exc:  # noqa: BLE001
            ok, doc = False, exc
        check(f"{cap}: -z json", ok, doc)
        if expected:
            p = tshark(exe, ["-2", "-r", path, "-Y", "ai_inspector.severity >= 3", "-T", "fields", "-e", "frame.number"])
            check(f"{cap}: two-pass filter on ai_inspector.severity", p.returncode == 0 and p.stdout.strip() != "", p.stderr[-300:])
    p = tshark(exe, ["-r", os.path.join(caps, "misc.pcap"), "-q", "-z", "ai_inspector,bogus"])
    check("invalid -z mode rejected", p.returncode != 0 and "invalid -z ai_inspector mode" in p.stderr, p.stderr[-300:])
    p = tshark(exe, ["-r", os.path.join(caps, "misc.pcap"), "-o", "ai_inspector.enabled:FALSE", "-T", "fields", "-e", "ai_inspector.id"])
    check("preference disables analysis", p.returncode == 0 and p.stdout.strip() == "", p.stdout[:200])
    p = tshark(exe, ["-r", os.path.join(caps, "misc.pcap"), "-o", "ai_inspector.scan_ports:100", "-T", "fields", "-e", "ai_inspector.id"])
    check("scan threshold preference honored", "tcp.port_scan" not in p.stdout, "")


def test_gui(exe, tshark_exe, caps):
    print("Wireshark UI plugin (in-application self-test)")
    tmp = tempfile.mkdtemp(prefix="ai_inspector_gui_")
    log, port_file = os.path.join(tmp, "mock.log"), os.path.join(tmp, "port")
    server = subprocess.Popen([sys.executable, os.path.join(ROOT, "tests", "mock_ai_server.py"), "--log", log, "--port-file", port_file])
    try:
        for _ in range(100):
            if os.path.exists(port_file) and os.path.getsize(port_file):
                break
            time.sleep(0.1)
        port = open(port_file).read().strip()
        runs = [("misc.pcap", "anthropic", "anthropic/v1/messages", 'ftp.request.command == "PASS"'),
                ("dns_http.pcap", "openai", "openai/v1/chat/completions", "http.authorization")]
        for cap, provider, path, frame_filter in runs:
            frame = tshark(tshark_exe, ["-r", os.path.join(caps, cap), "-Y", frame_filter, "-T", "fields", "-e", "frame.number"]).stdout.split()
            if os.path.exists(log):
                os.unlink(log)
            env = dict(os.environ, AI_INSPECTOR_UI_SELFTEST="1", AI_INSPECTOR_UI_SELFTEST_FRAME=frame[0] if frame else "0",
                       AI_INSPECTOR_PROVIDER=provider, AI_INSPECTOR_API_KEY="test-key-123",
                       AI_INSPECTOR_ENDPOINT=f"http://127.0.0.1:{port}/{path}",
                       AI_INSPECTOR_KEY_FILE=os.path.join(tmp, "api_key"))
            plugin_root = os.path.join(os.path.dirname(tshark_exe), "plugins", "wireshark")
            if os.path.isdir(plugin_root):
                # The macOS GUI binary sits inside run/wireshark.app and does not detect the build dir.
                env.setdefault("WIRESHARK_PLUGIN_DIR", plugin_root)
            if sys.platform.startswith("linux"):
                env.setdefault("QT_QPA_PLATFORM", "offscreen")
            try:
                p = run_text([exe, "-r", os.path.join(caps, cap)], env=env, timeout=180)
            except subprocess.TimeoutExpired as exc:
                err = (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
                check(f"{cap} via {provider}: self-test finished", False,
                      "Wireshark did not exit; is the ai_inspector UI plugin loaded?\n" + err[-600:])
                continue
            lines = [l for l in p.stderr.splitlines() if l.startswith("AI_INSPECTOR_UI_SELFTEST")]
            for l in lines:
                if " FAIL " in l:
                    print("       " + l)
            check(f"{cap} via {provider}: self-test passed", p.returncode == 0 and any("PASSED" in l for l in lines),
                  "\n".join(lines[-10:]) or p.stderr[-800:])
            body = open(log).read() if os.path.exists(log) else ""
            check(f"{cap}: AI requests sent", body.count('"path"') == 2, body[:200])
            leaked = [s for s in SECRETS if s in body]
            check(f"{cap}: no credentials sent", not leaked, leaked)
            check(f"{cap}: raw addresses redacted", "10.0.0." not in body and "IP-" in body, "")
    finally:
        server.kill()
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", default=os.path.join(ROOT, "build-development"))
    ap.add_argument("--captures", help="use existing captures instead of generating")
    ap.add_argument("--gui", action="store_true", help="also run the in-application UI self-test")
    a = ap.parse_args()

    caps = a.captures
    if not caps:
        caps = tempfile.mkdtemp(prefix="ai_inspector_caps_")
        p = run_text([sys.executable, os.path.join(ROOT, "tools", "make-test-captures.py"), caps])
        if p.returncode:
            sys.exit("capture generation failed (pip install scapy cryptography):\n" + p.stderr[-800:])
    ts = find(a.build_dir, "tshark")
    if not ts:
        sys.exit("tshark not found under " + a.build_dir)
    test_engine(ts, caps)
    if a.gui:
        ws = find(a.build_dir, "wireshark") or find(a.build_dir, "Wireshark")
        if not ws:
            check("wireshark executable found", False, a.build_dir)
        else:
            test_gui(ws, ts, caps)
    print(f"\n{len(failures)} failure(s)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
