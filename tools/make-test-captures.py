#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures exercising AI Inspector analyzers.

No real traffic is captured; all addresses are documentation/private ranges.
Requires: scapy, cryptography.
"""
import datetime
import os
import random
import struct
import sys

from scapy.all import (ARP, BOOTP, DHCP, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap, DNS, DNSQR, DNSRR)
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_IND, BTLE_DATA
from scapy.layers.bluetooth import (L2CAP_Hdr, SM_Hdr, SM_Pairing_Request, SM_Encryption_Information,
                                    SM_Failed, ATT_Hdr, ATT_Write_Request, EIR_Hdr, EIR_CompleteLocalName)
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth, Dot11WEP
from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind
from scapy.asn1.asn1 import ASN1_OID

random.seed(7)
OUT = sys.argv[1] if len(sys.argv) > 1 else "captures"
os.makedirs(OUT, exist_ok=True)
T0 = 1780000000.0  # 2026-05-28
_t = [T0]


def ts(pkts):
    for p in pkts:
        _t[0] += 0.01
        p.time = _t[0]
    return pkts


class TcpFlow:
    """Minimal bidirectional TCP flow with correct sequence numbers."""

    def __init__(self, cli, srv, sport, dport):
        self.c, self.s, self.sp, self.dp = cli, srv, sport, dport
        self.cseq, self.sseq = 1000, 5000
        self.pkts = []

    def handshake(self):
        self.pkts += [
            Ether() / IP(src=self.c, dst=self.s) / TCP(sport=self.sp, dport=self.dp, flags="S", seq=self.cseq - 1),
            Ether() / IP(src=self.s, dst=self.c) / TCP(sport=self.dp, dport=self.sp, flags="SA", seq=self.sseq - 1, ack=self.cseq),
            Ether() / IP(src=self.c, dst=self.s) / TCP(sport=self.sp, dport=self.dp, flags="A", seq=self.cseq, ack=self.sseq),
        ]
        return self

    def send(self, data, from_client=True):
        if from_client:
            p = Ether() / IP(src=self.c, dst=self.s) / TCP(sport=self.sp, dport=self.dp, flags="PA", seq=self.cseq, ack=self.sseq) / Raw(data)
            self.cseq += len(data)
        else:
            p = Ether() / IP(src=self.s, dst=self.c) / TCP(sport=self.dp, dport=self.sp, flags="PA", seq=self.sseq, ack=self.cseq) / Raw(data)
            self.sseq += len(data)
        self.pkts.append(p)
        return self


# ----------------------------------------------------------------------------- TLS
def tls_record(ctype, body, version=0x0303):
    return struct.pack("!BHH", ctype, version, len(body)) + body


def hs(htype, body):
    return struct.pack("!B", htype) + len(body).to_bytes(3, "big") + body


def client_hello(suites, sni=None):
    body = struct.pack("!H", 0x0303) + os.urandom(32) + b"\x00"
    cs = b"".join(struct.pack("!H", s) for s in suites)
    body += struct.pack("!H", len(cs)) + cs + b"\x01\x00"
    ext = b""
    if sni:
        name = sni.encode()
        entry = b"\x00" + struct.pack("!H", len(name)) + name
        lst = struct.pack("!H", len(entry)) + entry
        ext += struct.pack("!HH", 0, len(lst)) + lst
    body += struct.pack("!H", len(ext)) + ext
    return hs(1, body)


def server_hello(version, suite):
    body = struct.pack("!H", version) + os.urandom(32) + b"\x00" + struct.pack("!H", suite) + b"\x00" + b"\x00\x00"
    return hs(2, body)


def make_cert(expired=True):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy.example.test")])
    nb = datetime.datetime(2015, 1, 1)
    na = datetime.datetime(2020, 1, 1) if expired else datetime.datetime(2045, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1234).not_valid_before(nb).not_valid_after(na))
    try:
        c = cert.sign(key, hashes.SHA1())
    except Exception:  # some OpenSSL builds refuse SHA1 signing
        c = cert.sign(key, hashes.SHA256())
    return c.public_bytes(serialization.Encoding.DER)


def certificate_msg(der):
    one = len(der).to_bytes(3, "big") + der
    return hs(11, len(one).to_bytes(3, "big") + one)


def tls_pcap():
    pk = []
    f = TcpFlow("10.0.0.5", "203.0.113.10", 51000, 443).handshake()
    f.send(tls_record(22, client_hello([0x0005, 0x0001, 0x0017, 0xc02f])))            # RC4, NULL, EXPORT, GCM; no SNI
    f.send(tls_record(22, server_hello(0x0301, 0x0005) + certificate_msg(make_cert(True)), 0x0301), False)
    f.send(tls_record(21, b"\x02\x30", 0x0301))                                      # fatal unknown_ca
    pk += f.pkts
    g = TcpFlow("10.0.0.6", "203.0.113.11", 51001, 443).handshake()
    g.send(tls_record(22, client_hello([0x1301, 0xc02f], sni="good.example.test")))
    g.send(tls_record(22, server_hello(0x0303, 0x000a), 0x0303), False)             # 3DES
    pk += g.pkts
    h = TcpFlow("10.0.0.7", "203.0.113.12", 51002, 443).handshake()
    h.send(tls_record(22, client_hello([0x002f], sni="old.example.test"), 0x0300))
    h.send(tls_record(22, server_hello(0x0300, 0x002f), 0x0300), False)            # SSLv3
    pk += h.pkts
    wrpcap(os.path.join(OUT, "tls.pcap"), ts(pk))


# ----------------------------------------------------------------------------- QUIC
def varint2(n):
    return struct.pack("!H", 0x4000 | n)


def quic_long(first, version, dcid, payload_len=1100, sport=50000, dport=443):
    body = bytes([first]) + struct.pack("!I", version) + bytes([len(dcid)]) + dcid + b"\x00"
    if (first & 0x30) == 0:  # Initial: token length
        body += b"\x00"
    body += varint2(payload_len) + os.urandom(payload_len)
    return Ether() / IP(src="10.0.0.20", dst="198.51.100.20") / UDP(sport=sport, dport=dport) / Raw(body)


def quic_pcap():
    pk = []
    dcid = os.urandom(8)
    pk.append(quic_long(0xc3, 0x00000001, dcid))                     # v1 Initial
    pk.append(quic_long(0xc3, 0xff00001d, os.urandom(8)))            # draft-29 Initial
    pk.append(quic_long(0xd3, 0x00000001, dcid, 200))                # 0-RTT
    # Version Negotiation echoes the client's connection IDs (client SCID is empty).
    vn = bytes([0xc0]) + b"\x00\x00\x00\x00" + b"\x00" + bytes([len(dcid)]) + dcid + struct.pack("!I", 1) + struct.pack("!I", 0x6b3343cf)
    pk.insert(1, Ether() / IP(src="198.51.100.20", dst="10.0.0.20") / UDP(sport=443, dport=50000) / Raw(vn))
    pk.append(quic_long(0xc3, 0x00000001, os.urandom(8), sport=50002, dport=4433))   # non-standard port
    wrpcap(os.path.join(OUT, "quic.pcap"), ts(pk))


# ----------------------------------------------------------------------------- BLE
def ble_pcap():
    pk = []
    adv = BTLE() / BTLE_ADV() / BTLE_ADV_IND(AdvA="c0:ff:ee:00:00:01",
                                             data=[EIR_Hdr() / EIR_CompleteLocalName(local_name=b"SmartLock")])
    pk.append(adv)
    aa = 0x5A3C9E71

    def data(payload, llid=2):
        return BTLE(access_addr=aa) / BTLE_DATA(LLID=llid) / payload

    pk.append(data(L2CAP_Hdr(cid=6) / SM_Hdr() / SM_Pairing_Request(iocap=3, oob=0, authentication=0x01,
                                                                    max_key_size=7, initiator_key_distribution=1,
                                                                    responder_key_distribution=1)))
    pk.append(data(L2CAP_Hdr(cid=6) / SM_Hdr() / SM_Encryption_Information(ltk=os.urandom(16))))
    pk.append(data(L2CAP_Hdr(cid=4) / ATT_Hdr() / ATT_Write_Request(gatt_handle=0x0012, data=b"\x01")))
    pk.append(data(L2CAP_Hdr(cid=6) / SM_Hdr() / SM_Failed(reason=5)))
    wrpcap(os.path.join(OUT, "ble.pcap"), ts(pk), linktype=251)


# ----------------------------------------------------------------------------- DNS / HTTP
def dns_http_pcap():
    pk = []
    cli, dns = "10.0.0.30", "10.0.0.53"
    label = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(56))
    pk.append(Ether() / IP(src=cli, dst=dns) / UDP(sport=40000, dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname=label + ".exfil.example.test")))
    pk.append(Ether() / IP(src=cli, dst=dns) / UDP(sport=40001, dport=53) / DNS(id=2, rd=1, qd=DNSQR(qname="example.test", qtype=255)))
    for i in range(55):
        q = DNSQR(qname="%s.dga.test" % "".join(random.choice("qwrtypsdfghjklzxcvbnm") for _ in range(12)))
        pk.append(Ether() / IP(src=cli, dst=dns) / UDP(sport=41000 + i, dport=53) / DNS(id=100 + i, rd=1, qd=q))
        pk.append(Ether() / IP(src=dns, dst=cli) / UDP(sport=53, dport=41000 + i) / DNS(id=100 + i, qr=1, rcode=3, qd=q))

    f = TcpFlow("10.0.0.31", "192.0.2.80", 52000, 80).handshake()
    f.send(b"GET /download.php?file=../../../../etc/passwd HTTP/1.1\r\nHost: shop.example.test\r\n"
           b"User-Agent: sqlmap/1.7.2#stable (https://sqlmap.org)\r\nAuthorization: Basic YWRtaW46aHVudGVyMg==\r\n\r\n")
    f.send(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n", False)
    f.send(b"GET /login?user=bob&password=secret HTTP/1.1\r\nHost: shop.example.test\r\nCookie: sid=abc\r\n\r\n")
    f.send(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", False)
    pk += f.pkts
    wrpcap(os.path.join(OUT, "dns_http.pcap"), ts(pk))


# ----------------------------------------------------------------------------- misc
def misc_pcap():
    pk = []
    atk, victim = "10.0.0.66", "10.0.0.10"
    pk.append(Ether() / IP(src=atk, dst=victim) / TCP(sport=60000, dport=22, flags="FPU"))
    pk.append(Ether() / IP(src=atk, dst=victim) / TCP(sport=60001, dport=22, flags=""))
    for port in range(1, 61):
        pk.append(Ether() / IP(src=atk, dst=victim) / TCP(sport=61000, dport=port, flags="S"))

    ftp = TcpFlow("10.0.0.40", "192.0.2.21", 53000, 21).handshake()
    ftp.send(b"220 ready\r\n", False).send(b"USER alice\r\n").send(b"331 pw\r\n", False).send(b"PASS s3cret\r\n")
    pk += ftp.pkts

    tel = TcpFlow("10.0.0.41", "192.0.2.23", 53001, 23).handshake()
    tel.send(b"\xff\xfd\x18login: ", False).send(b"root\r\n")
    pk += tel.pkts

    smb1 = b"\xffSMB" + b"\x72" + b"\x00" * 27 + b"\x00\x00\x00"
    nb = b"\x00" + len(smb1).to_bytes(3, "big") + smb1
    s = TcpFlow("10.0.0.42", "10.0.0.45", 53002, 445).handshake()
    s.send(nb)
    pk += s.pkts

    ntp7 = bytes([0x17, 0x00, 0x03, 0x2a]) + b"\x00" * 4
    pk.append(Ether() / IP(src=atk, dst="192.0.2.123") / UDP(sport=50123, dport=123) / Raw(ntp7))

    pk.append(Ether(src="02:00:00:00:00:01") / ARP(op=2, psrc="10.0.0.1", hwsrc="02:00:00:00:00:01", pdst=victim))
    pk.append(Ether(src="02:00:00:00:00:66") / ARP(op=2, psrc="10.0.0.1", hwsrc="02:00:00:00:00:66", pdst=victim))

    for srv, mac in (("10.0.0.1", "02:00:00:00:00:01"), ("10.0.0.99", "02:00:00:00:00:99")):
        pk.append(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=srv, dst="255.255.255.255") / UDP(sport=67, dport=68)
                  / BOOTP(op=2, yiaddr="10.0.0.200", chaddr=b"\x02\x00\x00\x00\x00\x10")
                  / DHCP(options=[("message-type", "offer"), ("server_id", srv), "end"]))

    pk.append(Ether() / IP(src="10.0.0.254", dst=victim) / ICMP(type=5, code=1, gw="10.0.0.66") / IP(src=victim, dst="8.8.8.8") / UDP())

    pk.append(Ether() / IP(src=atk, dst="10.0.0.161") / UDP(sport=50161, dport=161)
              / SNMP(community="public", PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))])))

    ssh = TcpFlow("10.0.0.43", "192.0.2.22", 53003, 22).handshake()
    ssh.send(b"SSH-1.5-OpenSSH_2.0\r\n", False)
    pk += ssh.pkts

    rdp = TcpFlow("10.0.0.44", "10.0.0.33", 53004, 3389).handshake()
    rdp.send(bytes.fromhex("03000013") + bytes.fromhex("0ee00000000000") + bytes.fromhex("0100080000000000"))
    pk += rdp.pkts

    ldap_bind = bytes.fromhex("3012020101600d020103040263 6e8004 70617373".replace(" ", ""))
    ld = TcpFlow("10.0.0.46", "10.0.0.38", 53005, 389).handshake()
    ld.send(ldap_bind)
    pk += ld.pkts

    cid = b"dev1"
    user, pw = b"sensor", b"hunter2"
    vh = b"\x00\x04MQTT\x04\xc2\x00\x3c"
    payload = struct.pack("!H", len(cid)) + cid + struct.pack("!H", len(user)) + user + struct.pack("!H", len(pw)) + pw
    rem = vh + payload
    mq = TcpFlow("10.0.0.47", "192.0.2.83", 53006, 1883).handshake()
    mq.send(b"\x10" + bytes([len(rem)]) + rem)
    pk += mq.pkts

    wrpcap(os.path.join(OUT, "misc.pcap"), ts(pk))


def wlan_pcap():
    pk = []
    bssid = "02:11:22:33:44:55"
    for _ in range(25):
        pk.append(RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7))
    pk.append(RadioTap() / Dot11(type=2, subtype=0, FCfield="protected", addr1=bssid, addr2="02:00:00:00:00:10", addr3=bssid)
              / Dot11WEP(iv=b"\x01\x02\x03", keyid=0, wepdata=os.urandom(40)))
    wrpcap(os.path.join(OUT, "wlan.pcap"), ts(pk))


def fuzz_pcap():
    """Random payloads on analyzed ports: the plugin must never raise."""
    pk = []
    for i in range(1500):
        kind = i % 7
        data = os.urandom(random.randint(1, 1400))
        if kind == 0:
            pk.append(Ether() / IP(src="10.9.0.1", dst="10.9.0.2") / UDP(sport=40000 + i % 100, dport=443) / Raw(data))
        elif kind == 1:
            pk.append(Ether() / IP(src="10.9.0.1", dst="10.9.0.2") / TCP(sport=40000 + i % 100, dport=443, flags="PA", seq=i) / Raw(data))
        elif kind == 2:
            pk.append(Ether() / IP(src="10.9.0.1", dst="10.9.0.2") / UDP(sport=53, dport=40000) / Raw(data))
        elif kind == 3:
            pk.append(Ether() / IP(src="10.9.0.1", dst="10.9.0.2") / TCP(sport=80, dport=40000, flags="PA", seq=i) / Raw(data))
        elif kind == 4:
            pk.append(Ether() / IP(src="10.9.0.1", dst="10.9.0.2") / TCP(sport=445, dport=40000, flags="PA", seq=i) / Raw(data))
        elif kind == 5:
            pk.append(Ether() / IP(src="10.9.0.1", dst="10.9.0.2") / UDP(sport=123, dport=161) / Raw(data))
        else:
            pk.append(Ether() / IP(src="10.9.0.1", dst="10.9.0.2", flags="MF", frag=random.randint(0, 50)) / Raw(data))
    wrpcap(os.path.join(OUT, "fuzz.pcap"), ts(pk))
    ble = [BTLE(access_addr=random.getrandbits(32)) / BTLE_DATA(LLID=random.randint(1, 3)) / Raw(os.urandom(random.randint(0, 30)))
           for _ in range(400)]
    wrpcap(os.path.join(OUT, "fuzz_ble.pcap"), ts(ble), linktype=251)


if __name__ == "__main__":
    tls_pcap()
    quic_pcap()
    ble_pcap()
    dns_http_pcap()
    misc_pcap()
    wlan_pcap()
    fuzz_pcap()
    print("captures written to", OUT)
