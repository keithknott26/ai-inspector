// SPDX-License-Identifier: GPL-2.0-or-later
//
// Wireshark Assist analysis engine (epan plugin).
//
// A post-dissector that inspects every frame on the first dissection pass and
// records findings for TCP/IP, DNS, HTTP/1-2, TLS/DTLS/X.509, QUIC, Bluetooth
// LE (LL, SMP, ATT, HCI), 802.11, SSH, SMB, Kerberos, LDAP, RDP and cleartext
// application protocols. Findings are shown in the packet tree, as expert info,
// as filterable ws_assist.* fields, through `tshark -z ws_assist,report|json`,
// and to the Qt UI plugin through the "ws_assist" tap (see assist_api.h).

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/stat_tap_ui.h>
#include <epan/tap.h>
#include <epan/to_str.h>
#include <epan/ftypes/ftypes.h>
#include <wsutil/wmem/wmem.h>

#include "assist_api.h"
#include "assist_util.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <map>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

extern "C" {
void proto_register_wireshark_assist_engine(void);
void proto_reg_handoff_wireshark_assist_engine(void);
}

using namespace assist;

namespace {

const char *const ENGINE_VERSION = "1.0.0";
constexpr size_t MAX_TRACKED_KEYS = 200000;
constexpr size_t MAX_FRAME_FINDINGS = 24;
constexpr size_t MAX_EXAMPLES = 3;
constexpr size_t MAX_TIMELINE_SECONDS = 500000;
constexpr int64_t TIMELINE_BUCKETS = 60;

// ------------------------------------------------------------------ field table
#define ASSIST_FIELDS(X) \
    X(FRAME_LEN, "frame.len") X(FRAME_PROTOCOLS, "frame.protocols") \
    X(IP_SRC, "ip.src") X(IP_DST, "ip.dst") X(IP_TTL, "ip.ttl") X(IP_MF, "ip.flags.mf") \
    X(IP_FRAG_OFFSET, "ip.frag_offset") X(IPV6_SRC, "ipv6.src") X(IPV6_DST, "ipv6.dst") X(IGMP, "igmp") \
    X(ICMP_TYPE, "icmp.type") X(ICMP_CODE, "icmp.code") X(ICMPV6_TYPE, "icmpv6.type") \
    X(ARP_OPCODE, "arp.opcode") X(ARP_SRC_IP, "arp.src.proto_ipv4") X(ARP_SRC_MAC, "arp.src.hw_mac") \
    X(ARP_DUP, "arp.duplicate-address-detected") \
    X(TCP_SRCPORT, "tcp.srcport") X(TCP_DSTPORT, "tcp.dstport") X(TCP_STREAM, "tcp.stream") X(TCP_FLAGS, "tcp.flags") \
    X(TCP_RETRANS, "tcp.analysis.retransmission") X(TCP_ZERO_WIN, "tcp.analysis.zero_window") \
    X(TCP_LOST, "tcp.analysis.lost_segment") X(TCP_ACK_RTT, "tcp.analysis.ack_rtt") \
    X(TCP_OOO, "tcp.analysis.out_of_order") \
    X(UDP_SRCPORT, "udp.srcport") X(UDP_DSTPORT, "udp.dstport") \
    X(DNS_RESPONSE, "dns.flags.response") X(DNS_RCODE, "dns.flags.rcode") X(DNS_QRY_NAME, "dns.qry.name") \
    X(DNS_QRY_TYPE, "dns.qry.type") X(DNS_TIME, "dns.time") X(DNS_UNSOLICITED, "dns.unsolicited") \
    X(DNS_RETRANS, "dns.retransmission") X(DNS_TRUNCATED, "dns.flags.truncated") \
    X(DHCP_MSG, "dhcp.option.dhcp") X(DHCP_SERVER_ID, "dhcp.option.dhcp_server_id") \
    X(HTTP_METHOD, "http.request.method") X(HTTP_URI, "http.request.uri") X(HTTP_HOST, "http.host") \
    X(HTTP_UA, "http.user_agent") X(HTTP_AUTHZ, "http.authorization") X(HTTP_AUTHBASIC, "http.authbasic") \
    X(HTTP_COOKIE, "http.cookie") X(HTTP_CODE, "http.response.code") X(HTTP_TIME, "http.time") \
    X(HTTP2_RST, "http2.rst_stream.error") X(HTTP2_GOAWAY, "http2.goaway.error") \
    X(TLS_RECORD_VERSION, "tls.record.version") X(TLS_HS_TYPE, "tls.handshake.type") \
    X(TLS_HS_VERSION, "tls.handshake.version") X(TLS_SUPPORTED_VERSION, "tls.handshake.extensions.supported_version") \
    X(TLS_CIPHERSUITE, "tls.handshake.ciphersuite") X(TLS_SNI, "tls.handshake.extensions_server_name") \
    X(TLS_ALPN, "tls.handshake.extensions_alpn_str") X(TLS_ALERT, "tls.alert_message.desc") \
    X(TLS_JA3, "tls.handshake.ja3") X(TLS_JA4, "tls.handshake.ja4") X(TLS_HEARTBEAT, "tls.heartbeat_message.type") \
    X(DTLS_RECORD_VERSION, "dtls.record.version") X(DTLS_HS_TYPE, "dtls.handshake.type") \
    X(DTLS_HS_VERSION, "dtls.handshake.version") X(DTLS_SUPPORTED_VERSION, "dtls.handshake.extensions.supported_version") \
    X(DTLS_CIPHERSUITE, "dtls.handshake.ciphersuite") X(DTLS_SNI, "dtls.handshake.extensions_server_name") \
    X(DTLS_ALPN, "dtls.handshake.extensions_alpn_str") X(DTLS_ALERT, "dtls.alert_message.desc") \
    X(X509_ALG_ID, "x509af.algorithm.id") X(X509_UTCTIME, "x509af.utcTime") X(X509_GENTIME, "x509af.generalizedTime") \
    X(QUIC_HEADER_FORM, "quic.header_form") X(QUIC_LONG_TYPE, "quic.long.packet_type") X(QUIC_VERSION, "quic.version") \
    X(QUIC_FRAME_TYPE, "quic.frame_type") X(QUIC_CC_ERROR, "quic.cc.error_code") X(GQUIC_VERSION, "gquic.version") \
    X(BTLE_AA, "btle.access_address") X(BTLE_ADV_PDU, "btle.advertising_header.pdu_type") \
    X(BTLE_ADV_ADDR, "btle.advertising_address") X(BTLE_CTRL_OPCODE, "btle.control_opcode") \
    X(BTLE_CRC_BAD, "btle.crc.incorrect") X(BT_DEVICE_NAME, "btcommon.eir_ad.entry.device_name") \
    X(BTSMP_OPCODE, "btsmp.opcode") X(BTSMP_IO, "btsmp.io_capability") X(BTSMP_SC, "btsmp.sc_flag") \
    X(BTSMP_MITM, "btsmp.mitm_flag") X(BTSMP_KEYSIZE, "btsmp.max_enc_key_size") X(BTSMP_REASON, "btsmp.reason") \
    X(BTATT_OPCODE, "btatt.opcode") X(BTATT_ERROR, "btatt.error_code") X(BTATT_HANDLE, "btatt.handle") \
    X(BTHCI_EVT_CODE, "bthci_evt.code") X(BTHCI_EVT_STATUS, "bthci_evt.status") X(BTHCI_EVT_REASON, "bthci_evt.reason") \
    X(BTHCI_ENC_ENABLE, "bthci_evt.encryption_enable") X(BTHCI_CMD_OPCODE, "bthci_cmd.opcode") \
    X(BTHCI_CHANDLE, "bthci_acl.chandle") \
    X(WLAN_TYPE_SUBTYPE, "wlan.fc.type_subtype") X(WLAN_BSSID, "wlan.bssid") X(WLAN_WEP_IV, "wlan.wep.iv") \
    X(WLAN_REASON, "wlan.fixed.reason_code") \
    X(SSH_PROTOCOL, "ssh.protocol") X(SSH_KEX, "ssh.kex_algorithms") \
    X(SSH_ENC_C2S, "ssh.encryption_algorithms_client_to_server") X(SSH_MAC_C2S, "ssh.mac_algorithms_client_to_server") \
    X(SSH_HOSTKEY_ALGS, "ssh.server_host_key_algorithms") \
    X(SMB1, "smb") X(SMB2_CMD, "smb2.cmd") X(SMB2_NT_STATUS, "smb2.nt_status") X(SMB2_DIALECT, "smb2.dialect") \
    X(SMB2_SIGN_REQUIRED, "smb2.sec_mode.sign_required") \
    X(KRB_ETYPE, "kerberos.etype") X(KRB_ERROR, "kerberos.error_code") \
    X(LDAP_SIMPLE, "ldap.simple") X(RDP_REQ_PROTOCOLS, "rdp.negReq.requestedProtocols") \
    X(FTP_COMMAND, "ftp.request.command") X(TELNET_DATA, "telnet.data") X(POP_COMMAND, "pop.request.command") \
    X(IMAP_REQUEST, "imap.request") X(SMTP_COMMAND, "smtp.req.command") X(SNMP_COMMUNITY, "snmp.community") \
    X(MQTT_USERNAME, "mqtt.username") X(MQTT_PASSWD, "mqtt.passwd") X(TFTP_OPCODE, "tftp.opcode") \
    X(NTP_MODE, "ntp.flags.mode") X(NTP_REQCODE, "ntp.priv.reqcode") X(SIP_STATUS, "sip.Status-Code") \
    X(LLMNR, "llmnr") X(NBNS, "nbns")

enum Fld : int {
#define X(e, n) e,
    ASSIST_FIELDS(X)
#undef X
    FLD_COUNT
};

const char *const FIELD_NAMES[FLD_COUNT] = {
#define X(e, n) n,
    ASSIST_FIELDS(X)
#undef X
};

int g_hf_ids[FLD_COUNT];

// ------------------------------------------------------------------ registration handles
int proto_assist = -1;
int hf_count = -1, hf_finding = -1, hf_id = -1, hf_severity = -1, hf_category = -1;
int hf_protocol = -1, hf_detail = -1, hf_filter = -1;
int ett_assist = -1, ett_finding = -1;
int assist_tap = -1;
dissector_handle_t assist_handle;

enum Category { CAT_SECURITY, CAT_PERFORMANCE, CAT_PROTOCOL, CAT_ANOMALY, CAT_INVENTORY, CAT_COUNT };
const char *const CATEGORY_NAMES[CAT_COUNT] = {"security", "performance", "protocol", "anomaly", "inventory"};
expert_field g_ei[CAT_COUNT][5];

// Preferences
bool pref_enabled = true;
int pref_min_severity = SEV_INFO;
unsigned pref_max_per_id = 2000;
unsigned pref_rtt_ms = 500;
unsigned pref_scan_ports = 40;

const value_string severity_vals[] = {
    {SEV_INFO, "Info"}, {SEV_NOTE, "Note"}, {SEV_WARN, "Warning"}, {SEV_ERROR, "Error"}, {0, nullptr}};

const enum_val_t severity_enum[] = {
    {"info", "Info", SEV_INFO}, {"note", "Note", SEV_NOTE}, {"warning", "Warning", SEV_WARN},
    {"error", "Error", SEV_ERROR}, {nullptr, nullptr, 0}};

// ------------------------------------------------------------------ state
struct Finding {
    uint8_t sev;
    uint8_t cat;
    std::string proto, id, title, detail, filter;
};

struct IdEntry {
    uint64_t count = 0;
    uint32_t first = 0, last = 0, stored = 0;
    uint8_t sev = 0;
    uint8_t cat = 0;
    std::string proto, title, filter;
    std::vector<std::string> examples;
};

using Counter = std::unordered_map<std::string, uint64_t>;

enum Inventory {
    INV_TLS_VER, INV_SNI, INV_ALPN, INV_JA3, INV_JA4, INV_QUIC_VER, INV_HTTP_HOST, INV_HTTP_UA, INV_DNS_Q,
    INV_SSH_SW, INV_SMB_DIALECT, INV_BLE_DEV, INV_COUNT
};
const char *const INVENTORY_KEYS[INV_COUNT] = {"tls_versions", "tls_sni", "alpn", "ja3", "ja4", "quic_versions",
    "http_hosts", "http_user_agents", "dns_names", "ssh_banners", "smb_dialects", "ble_advertisers"};
const char *const INVENTORY_LABELS[INV_COUNT] = {"TLS/DTLS versions negotiated", "TLS server names (SNI)", "ALPN",
    "JA3 client fingerprints", "JA4 client fingerprints", "QUIC versions", "HTTP hosts (cleartext)",
    "HTTP user agents", "DNS names queried", "SSH software banners", "SMB2/3 dialects", "BLE advertisers"};

struct State {
    std::unordered_map<uint32_t, std::vector<Finding>> frames;
    std::unordered_map<std::string, IdEntry> by_id;
    std::array<uint64_t, 5> sev_count{};
    uint64_t packets = 0, untreed = 0;
    double first_ts = 0, last_ts = 0;
    bool have_ts = false;
    Counter protos;
    std::array<Counter, INV_COUNT> inv;
    size_t keys = 0;
    // heuristics
    std::unordered_map<std::string, std::unordered_set<uint32_t>> syn_ports;
    std::unordered_set<std::string> scan_flagged, flagged;
    Counter nx_by_client, http_denied, smb_fail, krb_fail, sip_fail, deauth;
    std::unordered_map<std::string, std::string> arp_map;
    std::unordered_set<std::string> dhcp_servers, ra_sources, ble_encrypted;
    bool dhcp_flagged = false;
    uint64_t crc_bad = 0;
    // dashboard data (bounded)
    std::map<int64_t, uint32_t> sec_packets;
    std::map<int64_t, std::array<uint32_t, 5>> sec_findings;
    Counter host_findings;
    std::unordered_map<std::string, uint8_t> host_worst;
    std::array<uint64_t, CAT_COUNT> cat_count{};
};

std::mutex g_mutex;
State *g_state = nullptr;
uint64_t g_generation = 1;

State &state() {
    if (!g_state) g_state = new State();
    return *g_state;
}

// ------------------------------------------------------------------ field access
std::string fi_string(const field_info *fi) {
    if (!fi || !fi->value) return {};
    enum ftenum ft = fi->hfinfo->type;
    if (ft == FT_NONE || ft == FT_PROTOCOL) return {};
    if (FT_IS_STRING(ft)) {
        const char *s = fvalue_get_string(fi->value);
        return s ? std::string(s) : std::string();
    }
    char *repr = fvalue_to_string_repr(nullptr, fi->value, FTREPR_DISPLAY, fi->hfinfo->display);
    std::string out = repr ? repr : "";
    wmem_free(nullptr, repr);
    return out;
}

std::optional<uint64_t> fi_uint(const field_info *fi) {
    if (!fi || !fi->value) return std::nullopt;
    enum ftenum ft = fi->hfinfo->type;
    if (FT_IS_UINT32(ft)) return fvalue_get_uinteger(fi->value);
    if (FT_IS_UINT64(ft) || ft == FT_BOOLEAN) return fvalue_get_uinteger64(fi->value);
    if (FT_IS_INT32(ft)) {
        int32_t v = fvalue_get_sinteger(fi->value);
        return v < 0 ? std::nullopt : std::optional<uint64_t>(static_cast<uint64_t>(v));
    }
    if (FT_IS_INT64(ft)) {
        int64_t v = fvalue_get_sinteger64(fi->value);
        return v < 0 ? std::nullopt : std::optional<uint64_t>(static_cast<uint64_t>(v));
    }
    return std::nullopt;
}

std::optional<double> fi_double(const field_info *fi) {
    if (!fi || !fi->value) return std::nullopt;
    enum ftenum ft = fi->hfinfo->type;
    if (ft == FT_RELATIVE_TIME || ft == FT_ABSOLUTE_TIME) {
        const nstime_t *t = fvalue_get_time(fi->value);
        if (!t) return std::nullopt;
        return static_cast<double>(t->secs) + static_cast<double>(t->nsecs) / 1e9;
    }
    if (FT_IS_FLOATING(ft)) return fvalue_get_floating(fi->value);
    if (auto u = fi_uint(fi)) return static_cast<double>(*u);
    return std::nullopt;
}

std::string fi_label(const field_info *fi) {
    if (!fi) return {};
    char buf[ITEM_LABEL_LENGTH];
    buf[0] = '\0';
    size_t off = 0;
    proto_item_fill_label(fi, buf, &off);
    return buf;
}

class Pkt {
public:
    Pkt(proto_tree *tree, packet_info *pinfo) : tree_(tree), pinfo_(pinfo) {}

    GPtrArray *arr(Fld f) const {
        int id = g_hf_ids[f];
        if (id < 0 || !tree_) return nullptr;
        return proto_get_finfo_ptr_array(tree_, id);
    }
    size_t count(Fld f) const {
        GPtrArray *a = arr(f);
        return a ? a->len : 0;
    }
    bool has(Fld f) const { return count(f) > 0; }
    const field_info *fi(Fld f, size_t i = 0) const {
        GPtrArray *a = arr(f);
        if (!a || i >= a->len) return nullptr;
        return static_cast<const field_info *>(g_ptr_array_index(a, i));
    }
    std::optional<uint64_t> u(Fld f, size_t i = 0) const { return fi_uint(fi(f, i)); }
    std::optional<double> d(Fld f) const { return fi_double(fi(f)); }
    std::optional<std::string> s(Fld f, size_t i = 0) const {
        const field_info *x = fi(f, i);
        if (!x) return std::nullopt;
        return fi_string(x);
    }
    std::string label(Fld f, size_t i = 0) const { return fi_label(fi(f, i)); }
    // Boolean flag field: present and non-zero.
    bool flag(Fld f) const {
        auto v = u(f);
        return v && *v != 0;
    }
    // Present and explicitly zero/false.
    bool flag_false(Fld f) const {
        auto v = u(f);
        return v && *v == 0;
    }
    packet_info *pinfo() const { return pinfo_; }

private:
    proto_tree *tree_;
    packet_info *pinfo_;
};

// ------------------------------------------------------------------ analyzer
class Analyzer {
public:
    Analyzer(State &st, const Pkt &p) : S(st), P(p) {
        frame_ = p.pinfo()->num;
        time_ = static_cast<double>(p.pinfo()->abs_ts.secs) + static_cast<double>(p.pinfo()->abs_ts.nsecs) / 1e9;
    }

    void run() {
        ++S.packets;
        if (!S.have_ts || time_ < S.first_ts) S.first_ts = time_;
        if (!S.have_ts || time_ > S.last_ts) S.last_ts = time_;
        S.have_ts = true;
        {
            const int64_t sec = static_cast<int64_t>(std::floor(time_));
            auto it = S.sec_packets.find(sec);
            if (it != S.sec_packets.end()) ++it->second;
            else if (S.sec_packets.size() < MAX_TIMELINE_SECONDS) S.sec_packets.emplace(sec, 1);
        }
        if (auto stack = P.s(FRAME_PROTOCOLS)) {
            std::unordered_set<std::string> seen;
            size_t start = 0;
            while (start <= stack->size()) {
                size_t end = stack->find(':', start);
                if (end == std::string::npos) end = stack->size();
                std::string tok = stack->substr(start, end - start);
                if (!tok.empty() && seen.insert(tok).second && (S.protos.count(tok) || S.protos.size() < 512)) {
                    ++S.protos[tok];
                }
                start = end + 1;
            }
        }
        network();
        tcp();
        dns();
        http();
        quic();
        tls_family(false);
        tls_family(true);
        bluetooth();
        wlan();
        remote();
        cleartext();
    }

private:
    State &S;
    const Pkt &P;
    uint32_t frame_ = 0;
    double time_ = 0;
    bool quic_ = false;

    // Register a finding for the current frame.
    void add(int sev, Category cat, const char *proto, const std::string &id, const std::string &title,
             const std::string &detail = {}, const std::string &filter = {}) {
        auto it = S.by_id.find(id);
        if (it == S.by_id.end()) {
            if (S.by_id.size() >= 4096) return; // bounded number of finding types
            IdEntry e;
            e.first = frame_;
            e.sev = static_cast<uint8_t>(sev);
            e.cat = static_cast<uint8_t>(cat);
            e.proto = proto;
            e.title = title;
            e.filter = filter;
            it = S.by_id.emplace(id, std::move(e)).first;
        }
        IdEntry &e = it->second;
        auto fit = S.frames.find(frame_);
        if (fit != S.frames.end()) {
            for (const auto &f : fit->second) if (f.id == id) return; // one per id per frame
        }
        ++e.count;
        ++S.cat_count[cat];
        {
            const int64_t sec = static_cast<int64_t>(std::floor(time_));
            auto it = S.sec_findings.find(sec);
            if (it == S.sec_findings.end() && S.sec_findings.size() < MAX_TIMELINE_SECONDS)
                it = S.sec_findings.emplace(sec, std::array<uint32_t, 5>{}).first;
            if (it != S.sec_findings.end()) ++it->second[static_cast<size_t>(sev)];
            char *a = address_to_str(nullptr, &P.pinfo()->src);
            if (a && *a) {
                const std::string host = clean(a, 64);
                if (bump(S.host_findings, host)) {
                    uint8_t &worst = S.host_worst[host];
                    if (sev > worst) worst = static_cast<uint8_t>(sev);
                }
            }
            wmem_free(nullptr, a);
        }
        e.last = frame_;
        if (sev > e.sev) e.sev = static_cast<uint8_t>(sev);
        ++S.sev_count[sev];
        if (e.stored >= pref_max_per_id) return;
        auto &list = S.frames[frame_];
        if (list.size() >= MAX_FRAME_FINDINGS) return;
        ++e.stored;
        std::string d = detail.empty() ? std::string() : clean(detail, 240);
        if (!d.empty() && e.examples.size() < MAX_EXAMPLES) e.examples.push_back(fmt("#%u %s", frame_, d.c_str()));
        list.push_back(Finding{static_cast<uint8_t>(sev), static_cast<uint8_t>(cat), proto, id, title, d, filter});
    }

    uint64_t bump(Counter &c, const std::string &key_raw, uint64_t by = 1) {
        std::string key = clean(key_raw, 200);
        auto it = c.find(key);
        if (it == c.end()) {
            if (S.keys >= MAX_TRACKED_KEYS) return 0;
            ++S.keys;
            it = c.emplace(key, 0).first;
        }
        it->second += by;
        return it->second;
    }

    bool once(const std::string &key) {
        if (S.flagged.count(key)) return false;
        if (S.flagged.size() >= MAX_TRACKED_KEYS) return false;
        S.flagged.insert(key);
        return true;
    }

    std::string src() const {
        if (auto v = P.s(IP_SRC)) return *v;
        if (auto v = P.s(IPV6_SRC)) return *v;
        char *a = address_to_str(nullptr, &P.pinfo()->src);
        std::string out = a ? a : "";
        wmem_free(nullptr, a);
        return out;
    }
    std::string dst() const {
        if (auto v = P.s(IP_DST)) return *v;
        if (auto v = P.s(IPV6_DST)) return *v;
        char *a = address_to_str(nullptr, &P.pinfo()->dst);
        std::string out = a ? a : "";
        wmem_free(nullptr, a);
        return out;
    }
    static std::string addr_field(const std::string &a) {
        if (a.find(':') != std::string::npos) return "ipv6.addr";
        return "ip.addr";
    }
    unsigned rtt_ms() const { return pref_rtt_ms ? pref_rtt_ms : 500; }

    // ------------------------------------------------------------ IP / ICMP / ARP / DHCP
    void network() {
        if (P.has(IP_SRC)) {
            uint64_t off = P.u(IP_FRAG_OFFSET).value_or(0);
            if (P.flag(IP_MF) || off > 0) {
                add(SEV_NOTE, CAT_PROTOCOL, "IP", "ip.fragmented", "IP fragmentation", fmt("offset %llu", (unsigned long long)off),
                    "ip.flags.mf == 1 || ip.frag_offset > 0");
                if (off > 0 && off < 64) {
                    add(SEV_WARN, CAT_SECURITY, "IP", "ip.tiny_fragment_offset",
                        "Tiny/overlapping IP fragment offset (evasion technique)", fmt("offset %llu bytes", (unsigned long long)off),
                        "ip.frag_offset > 0 && ip.frag_offset < 64");
                }
            }
            if (auto ttl = P.u(IP_TTL)) {
                if (*ttl <= 1 && !P.has(IGMP)) {
                    add(SEV_INFO, CAT_ANOMALY, "IP", "ip.ttl_expiring", "IP TTL 0/1 (traceroute or routing loop)",
                        fmt("TTL %llu", (unsigned long long)*ttl), "ip.ttl <= 1");
                }
            }
        }

        if (auto it = P.u(ICMP_TYPE)) {
            if (*it == 5) {
                add(SEV_WARN, CAT_SECURITY, "ICMP", "icmp.redirect", "ICMP redirect (possible traffic hijack)",
                    src() + " -> " + dst(), "icmp.type == 5");
            } else if (*it == 3) {
                add(SEV_NOTE, CAT_PROTOCOL, "ICMP", "icmp.unreachable", "ICMP destination unreachable",
                    fmt("code %llu", (unsigned long long)P.u(ICMP_CODE).value_or(0)), "icmp.type == 3");
            } else if ((*it == 0 || *it == 8) && P.u(FRAME_LEN).value_or(0) > 1100) {
                add(SEV_WARN, CAT_SECURITY, "ICMP", "icmp.large_echo", "Large ICMP echo payload (possible tunneling)",
                    fmt("%llu bytes", (unsigned long long)P.u(FRAME_LEN).value_or(0)), "icmp.type in {0 8} && frame.len > 1100");
            } else if (*it == 11) {
                add(SEV_INFO, CAT_PROTOCOL, "ICMP", "icmp.time_exceeded", "ICMP time exceeded", {}, "icmp.type == 11");
            }
        }

        if (auto t6 = P.u(ICMPV6_TYPE)) {
            if (*t6 == 134) {
                std::string s = src();
                if (!S.ra_sources.count(s) && S.ra_sources.size() < 4096) {
                    S.ra_sources.insert(s);
                    if (S.ra_sources.size() > 1) {
                        add(SEV_WARN, CAT_SECURITY, "ICMPv6", "icmpv6.multiple_ra",
                            "Router advertisements from multiple sources (possible rogue RA)", s, "icmpv6.type == 134");
                    }
                }
            } else if (*t6 == 137) {
                add(SEV_WARN, CAT_SECURITY, "ICMPv6", "icmpv6.redirect", "ICMPv6 redirect", src(), "icmpv6.type == 137");
            }
        }

        if (P.has(ARP_OPCODE)) {
            if (P.has(ARP_DUP)) {
                add(SEV_ERROR, CAT_SECURITY, "ARP", "arp.duplicate_ip", "Duplicate IP address claim (possible ARP spoofing)",
                    {}, "arp.duplicate-address-detected");
            }
            auto ip = P.s(ARP_SRC_IP);
            auto mac = P.s(ARP_SRC_MAC);
            if (ip && mac && *ip != "0.0.0.0") {
                auto prev = S.arp_map.find(*ip);
                if (prev != S.arp_map.end()) {
                    if (prev->second != *mac) {
                        add(SEV_ERROR, CAT_SECURITY, "ARP", "arp.mac_changed",
                            "IP-to-MAC binding changed (ARP poisoning indicator)",
                            fmt("%s was %s, now %s", ip->c_str(), prev->second.c_str(), mac->c_str()),
                            "arp.src.proto_ipv4 == " + *ip);
                        prev->second = *mac;
                    }
                } else if (S.arp_map.size() < 65536) {
                    S.arp_map.emplace(*ip, *mac);
                }
            }
        }

        if (auto msg = P.u(DHCP_MSG)) {
            if (*msg == 2) {
                std::string server = P.s(DHCP_SERVER_ID).value_or(src());
                if (S.dhcp_servers.size() < 256) S.dhcp_servers.insert(server);
                if (S.dhcp_servers.size() > 1 && !S.dhcp_flagged) {
                    S.dhcp_flagged = true;
                    add(SEV_ERROR, CAT_SECURITY, "DHCP", "dhcp.multiple_servers",
                        "DHCP offers from multiple servers (possible rogue DHCP)", "server " + server, "dhcp.option.dhcp == 2");
                }
            } else if (*msg == 6) {
                add(SEV_NOTE, CAT_PROTOCOL, "DHCP", "dhcp.nak", "DHCP NAK", {}, "dhcp.option.dhcp == 6");
            }
        }

        if (P.has(LLMNR) || P.has(NBNS)) {
            add(SEV_INFO, CAT_SECURITY, "LLMNR/NBNS", "name.llmnr_nbns",
                "LLMNR/NetBIOS name resolution in use (poisoning/relay exposure)", {}, "llmnr || nbns");
        }
    }

    // ------------------------------------------------------------ TCP
    void tcp() {
        if (!P.has(TCP_SRCPORT)) return;
        auto stream = P.u(TCP_STREAM);
        auto flags = P.u(TCP_FLAGS);
        bool syn = false, ack = false;
        if (flags) {
            uint64_t f = *flags & 0xff;
            bool fin = f & 0x01, fsyn = f & 0x02, rst = f & 0x04, psh = f & 0x08, fack = f & 0x10, urg = f & 0x20;
            syn = fsyn;
            ack = fack;
            if (f == 0) {
                add(SEV_WARN, CAT_SECURITY, "TCP", "tcp.null_scan", "TCP NULL flags (scan)", {}, "tcp.flags == 0x000");
            } else if (fin && psh && urg && !fsyn && !fack && !rst) {
                add(SEV_WARN, CAT_SECURITY, "TCP", "tcp.xmas_scan", "TCP XMAS flags FIN/PSH/URG (scan)", {},
                    "tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1 && tcp.flags.ack == 0");
            } else if (fsyn && fin) {
                add(SEV_WARN, CAT_ANOMALY, "TCP", "tcp.syn_fin", "TCP SYN+FIN (invalid, scan/evasion)", {},
                    "tcp.flags.syn == 1 && tcp.flags.fin == 1");
            } else if (fin && !fack && !rst && !psh && !urg && !fsyn) {
                add(SEV_WARN, CAT_SECURITY, "TCP", "tcp.fin_scan", "TCP FIN without ACK (FIN scan)", {}, "tcp.flags == 0x001");
            }
            if (rst) {
                add(SEV_NOTE, CAT_PROTOCOL, "TCP", "tcp.reset", "TCP connection reset",
                    stream ? fmt("tcp.stream == %llu", (unsigned long long)*stream) : std::string(), "tcp.flags.reset == 1");
            }
        }

        if (syn && !ack) {
            std::string s = src(), d = dst();
            auto dport = P.u(TCP_DSTPORT);
            std::string key = s + ">" + d;
            auto it = S.syn_ports.find(key);
            if (it == S.syn_ports.end() && S.keys < MAX_TRACKED_KEYS && S.syn_ports.size() < 50000) {
                ++S.keys;
                it = S.syn_ports.emplace(key, std::unordered_set<uint32_t>()).first;
            }
            unsigned threshold = pref_scan_ports ? pref_scan_ports : 40;
            // Stop tracking a pair once it has been reported: memory stays bounded.
            if (it != S.syn_ports.end() && dport && it->second.size() < threshold) {
                it->second.insert(static_cast<uint32_t>(*dport));
                size_t n = it->second.size();
                if (n >= threshold && !S.scan_flagged.count(key)) {
                    S.scan_flagged.insert(key);
                    add(SEV_ERROR, CAT_SECURITY, "TCP", "tcp.port_scan", "Port scan: many SYNs to distinct ports",
                        fmt("%s probed %zu ports on %s", s.c_str(), n, d.c_str()),
                        fmt("%s == %s && tcp.flags.syn == 1 && tcp.flags.ack == 0", addr_field(s).c_str(), s.c_str()));
                }
            }
        }

        if (P.has(TCP_RETRANS))
            add(SEV_NOTE, CAT_PERFORMANCE, "TCP", "tcp.retransmission", "TCP retransmission", {}, "tcp.analysis.retransmission");
        if (P.has(TCP_LOST))
            add(SEV_WARN, CAT_PERFORMANCE, "TCP", "tcp.lost_segment", "TCP previous segment not captured / lost", {},
                "tcp.analysis.lost_segment");
        if (P.has(TCP_ZERO_WIN))
            add(SEV_WARN, CAT_PERFORMANCE, "TCP", "tcp.zero_window", "TCP zero window (receiver stalled)", {},
                "tcp.analysis.zero_window");
        if (P.has(TCP_OOO))
            add(SEV_NOTE, CAT_PERFORMANCE, "TCP", "tcp.out_of_order", "TCP out-of-order segment", {}, "tcp.analysis.out_of_order");
        if (auto rtt = P.d(TCP_ACK_RTT)) {
            if (*rtt * 1000.0 > rtt_ms() && stream && once(fmt("rtt%llu", (unsigned long long)*stream))) {
                add(SEV_WARN, CAT_PERFORMANCE, "TCP", "tcp.high_rtt", "High TCP ACK round-trip time",
                    fmt("%.0f ms in stream %llu", *rtt * 1000.0, (unsigned long long)*stream),
                    fmt("tcp.analysis.ack_rtt > %.3f", rtt_ms() / 1000.0));
            }
        }
    }

    // ------------------------------------------------------------ DNS
    void dns() {
        auto qname = P.s(DNS_QRY_NAME);
        if (!qname && !P.has(DNS_RESPONSE)) return;
        bool resp = P.flag(DNS_RESPONSE);
        auto qtype = P.u(DNS_QRY_TYPE);
        const std::string name = qname.value_or("");

        if (qname && !resp) {
            bump(S.inv[INV_DNS_Q], lower(name));
            size_t longest = 0, start = 0;
            std::string longest_label;
            while (start <= name.size()) {
                size_t end = name.find('.', start);
                if (end == std::string::npos) end = name.size();
                if (end - start > longest) {
                    longest = end - start;
                    longest_label = name.substr(start, end - start);
                }
                start = end + 1;
            }
            double ent = entropy(longest_label);
            if (name.size() > 120 || longest > 52 || (longest >= 24 && ent > 3.8)) {
                add(SEV_WARN, CAT_SECURITY, "DNS", "dns.tunneling_suspect",
                    "Long/high-entropy DNS name (possible tunneling or exfiltration)",
                    fmt("%s (len %zu, label entropy %.2f)", clean(name, 120).c_str(), name.size(), ent), "len(dns.qry.name) > 60");
            }
            if (qtype && *qtype == 255) {
                add(SEV_NOTE, CAT_SECURITY, "DNS", "dns.any_query", "DNS ANY query (amplification/recon)", name, "dns.qry.type == 255");
            } else if (qtype && (*qtype == 251 || *qtype == 252)) {
                add(SEV_WARN, CAT_SECURITY, "DNS", "dns.zone_transfer", "DNS zone transfer (AXFR/IXFR) requested", name,
                    "dns.qry.type in {251 252}");
            }
        }

        if (resp) {
            uint64_t rcode = P.u(DNS_RCODE).value_or(0);
            if (rcode == 3) {
                std::string client = dst();
                if (bump(S.nx_by_client, client) == 50) {
                    add(SEV_WARN, CAT_SECURITY, "DNS", "dns.nxdomain_burst", "Many NXDOMAIN responses to one client (DGA/malware)",
                        client + " received 50+ NXDOMAIN", "dns.flags.rcode == 3 && " + addr_field(client) + " == " + client);
                }
                add(SEV_INFO, CAT_PROTOCOL, "DNS", "dns.nxdomain", "DNS NXDOMAIN", name, "dns.flags.rcode == 3");
            } else if (rcode != 0) {
                static const char *const names[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"};
                std::string rn = rcode < 6 ? names[rcode] : fmt("rcode %llu", (unsigned long long)rcode);
                add(SEV_NOTE, CAT_PROTOCOL, "DNS", "dns.error_rcode", "DNS error response", rn + " for " + name,
                    "dns.flags.rcode > 0 && dns.flags.rcode != 3");
            }
            if (auto t = P.d(DNS_TIME)) {
                if (*t * 1000.0 > rtt_ms()) {
                    add(SEV_WARN, CAT_PERFORMANCE, "DNS", "dns.slow", "Slow DNS response",
                        fmt("%.0f ms for %s", *t * 1000.0, clean(name, 100).c_str()), fmt("dns.time > %.3f", rtt_ms() / 1000.0));
                }
            }
            if (P.has(DNS_UNSOLICITED)) {
                add(SEV_WARN, CAT_SECURITY, "DNS", "dns.unsolicited", "DNS response without matching query (spoofing indicator)",
                    name, "dns.unsolicited");
            }
            if (P.flag(DNS_TRUNCATED))
                add(SEV_INFO, CAT_PROTOCOL, "DNS", "dns.truncated", "Truncated DNS response (TC)", name, "dns.flags.truncated == 1");
        }
        if (P.has(DNS_RETRANS))
            add(SEV_NOTE, CAT_PERFORMANCE, "DNS", "dns.retransmission", "DNS query/response retransmitted", name, "dns.retransmission");
    }

    // ------------------------------------------------------------ HTTP
    void http() {
        static const std::vector<const char *> ua_tools = {"sqlmap", "nikto", "nmap", "masscan", "zgrab", "gobuster",
            "dirbuster", "hydra", "wpscan", "acunetix", "nessus", "openvas", "nuclei", "feroxbuster", "ffuf", "wfuzz"};
        static const std::vector<const char *> uri_attacks = {"../", "..%2f", "%2e%2e", "..\\", "union select",
            "union%20select", "' or '1'='1", "%27%20or%20", "<script", "%3cscript", "/etc/passwd", "cmd.exe", "/bin/sh",
            "${jndi:", "%24%7bjndi", "xp_cmdshell", "sleep(", "benchmark(", "/.git/", "/.env", "base64_decode("};

        if (auto method = P.s(HTTP_METHOD)) {
            std::string host = P.s(HTTP_HOST).value_or("");
            std::string uri = P.s(HTTP_URI).value_or("");
            if (!host.empty()) bump(S.inv[INV_HTTP_HOST], lower(host));
            if (auto ua = P.s(HTTP_UA)) {
                bump(S.inv[INV_HTTP_UA], *ua);
                if (const char *tool = contains_any_ci(*ua, ua_tools)) {
                    add(SEV_WARN, CAT_SECURITY, "HTTP", "http.scanner_ua", "HTTP User-Agent of attack/scanning tool",
                        std::string(tool) + " (" + *ua + ")", "http.user_agent contains " + filter_quote(tool));
                }
            }
            if (const char *pat = contains_any_ci(uri, uri_attacks)) {
                add(SEV_ERROR, CAT_SECURITY, "HTTP", "http.attack_pattern",
                    "HTTP request with attack pattern (traversal/SQLi/XSS/RCE)", *method + " " + uri + " [" + pat + "]",
                    "http.request.uri contains " + filter_quote(pat));
            }
            std::string authz = lower(P.s(HTTP_AUTHZ).value_or(""));
            if (P.has(HTTP_AUTHBASIC) || authz.rfind("basic", 0) == 0) {
                add(SEV_ERROR, CAT_SECURITY, "HTTP", "http.basic_auth_cleartext", "HTTP Basic credentials sent in cleartext",
                    host, "http.authorization");
            } else if (P.has(HTTP_AUTHZ)) {
                add(SEV_WARN, CAT_SECURITY, "HTTP", "http.auth_cleartext", "HTTP Authorization header over cleartext HTTP",
                    host, "http.authorization");
            }
            if (P.has(HTTP_COOKIE))
                add(SEV_NOTE, CAT_SECURITY, "HTTP", "http.cookie_cleartext", "Cookies sent over cleartext HTTP", host, "http.cookie");
            std::string lu = lower(uri);
            if (contains(lu, "passw") || contains(lu, "token=") || contains(lu, "api_key=") || contains(lu, "apikey=")) {
                add(SEV_ERROR, CAT_SECURITY, "HTTP", "http.secret_in_uri", "Credential-like parameter in cleartext URL", host,
                    "http.request.uri matches \"(?i)(passw|token=|api_?key=)\"");
            }
        }

        if (auto code = P.u(HTTP_CODE)) {
            if (*code >= 500) {
                add(SEV_WARN, CAT_PROTOCOL, "HTTP", "http.server_error", "HTTP 5xx server error",
                    fmt("%llu", (unsigned long long)*code), "http.response.code >= 500");
            } else if (*code == 401 || *code == 403) {
                std::string client = dst();
                if (bump(S.http_denied, client) == 20) {
                    add(SEV_WARN, CAT_SECURITY, "HTTP", "http.auth_failures", "Repeated HTTP 401/403 (brute force/enumeration)",
                        client + " received 20+ denials", "http.response.code in {401 403}");
                }
            }
            if (auto t = P.d(HTTP_TIME)) {
                if (*t * 1000.0 > rtt_ms() * 4.0) {
                    add(SEV_WARN, CAT_PERFORMANCE, "HTTP", "http.slow_response", "Slow HTTP response",
                        fmt("%.0f ms", *t * 1000.0), fmt("http.time > %.3f", rtt_ms() * 4 / 1000.0));
                }
            }
        }
        const uint64_t rst = P.u(HTTP2_RST).value_or(0);
        if (rst != 0 && rst != 8) // 8 = CANCEL
            add(SEV_NOTE, CAT_PROTOCOL, "HTTP2", "http2.rst_stream", "HTTP/2 stream reset with error",
                fmt("error %llu", (unsigned long long)rst), "http2.rst_stream.error != 0");
        const uint64_t ga = P.u(HTTP2_GOAWAY).value_or(0);
        if (ga != 0)
            add(SEV_WARN, CAT_PROTOCOL, "HTTP2", "http2.goaway_error", "HTTP/2 GOAWAY with error",
                fmt("error %llu", (unsigned long long)ga), "http2.goaway.error != 0");
    }

    // ------------------------------------------------------------ TLS / DTLS / X.509
    void tls_family(bool dtls) {
        const char *p = dtls ? "dtls" : "tls";
        const char *PN = dtls ? "DTLS" : "TLS";
        Fld f_rec = dtls ? DTLS_RECORD_VERSION : TLS_RECORD_VERSION;
        Fld f_type = dtls ? DTLS_HS_TYPE : TLS_HS_TYPE;
        Fld f_ver = dtls ? DTLS_HS_VERSION : TLS_HS_VERSION;
        Fld f_sv = dtls ? DTLS_SUPPORTED_VERSION : TLS_SUPPORTED_VERSION;
        Fld f_cs = dtls ? DTLS_CIPHERSUITE : TLS_CIPHERSUITE;
        Fld f_sni = dtls ? DTLS_SNI : TLS_SNI;
        Fld f_alpn = dtls ? DTLS_ALPN : TLS_ALPN;
        Fld f_alert = dtls ? DTLS_ALERT : TLS_ALERT;
        if (!P.has(f_type) && !P.has(f_alert) && !P.has(f_rec)) return;

        bool client_hello = false, server_hello = false, certificate = false;
        for (size_t i = 0; i < P.count(f_type); ++i) {
            auto t = P.u(f_type, i).value_or(0xffff);
            client_hello |= t == 1;
            server_hello |= t == 2;
            certificate |= t == 11;
        }

        // RFC 5246 Appendix E lets a ClientHello carry record version {03,00}
        // for compatibility, so SSL-era record versions only count elsewhere.
        if (!(client_hello && !server_hello)) {
            for (size_t i = 0; i < P.count(f_rec); ++i) {
                auto rv = P.u(f_rec, i);
                if (rv && (*rv == 0x0300 || *rv == 0x0002)) {
                    add(SEV_ERROR, CAT_SECURITY, PN, std::string(p) + ".ssl_protocol", "SSLv2/SSLv3 record layer in use",
                        tls_version_name(static_cast<unsigned>(*rv)),
                        std::string(p) + ".record.version <= 0x0300 && !(" + p + ".handshake.type == 1)");
                    break;
                }
            }
        }

        if (client_hello) {
            if (auto sni = P.s(f_sni)) {
                bump(S.inv[INV_SNI], lower(*sni));
            } else if (!dtls && !quic_) {
                add(SEV_INFO, CAT_INVENTORY, PN, "tls.no_sni", "ClientHello without SNI", {},
                    "tls.handshake.type == 1 && !tls.handshake.extensions_server_name");
            }
            if (auto alpn = P.s(f_alpn)) bump(S.inv[INV_ALPN], *alpn);
            if (!dtls) {
                if (auto ja3 = P.s(TLS_JA3)) bump(S.inv[INV_JA3], *ja3);
                if (auto ja4 = P.s(TLS_JA4)) bump(S.inv[INV_JA4], *ja4);
            }
            // In a frame holding both hellos, the ServerHello suite is the last one.
            size_t n = P.count(f_cs) - (server_hello && P.count(f_cs) > 0 ? 1 : 0);
            std::vector<std::string> bad;
            for (size_t i = 0; i < n; ++i) {
                std::string why;
                if (cipher_weakness(P.label(f_cs, i), why) >= SEV_ERROR
                    && std::find(bad.begin(), bad.end(), why) == bad.end())
                    bad.push_back(why);
            }
            if (!bad.empty()) {
                std::sort(bad.begin(), bad.end());
                std::string joined;
                for (const auto &b : bad) joined += (joined.empty() ? "" : ", ") + b;
                add(SEV_NOTE, CAT_SECURITY, PN, std::string(p) + ".client_offers_weak", "Client offers insecure cipher suites",
                    joined, std::string(p) + ".handshake.type == 1");
            }
        }

        if (server_hello) {
            std::optional<uint64_t> ver;
            if (size_t n = P.count(f_sv)) ver = P.u(f_sv, n - 1);
            if (!ver) {
                size_t n = P.count(f_ver);
                if (n) ver = P.u(f_ver, n - 1);
            }
            if (ver) {
                const char *vn = tls_version_name(static_cast<unsigned>(*ver));
                std::string vname = vn ? vn : hex(*ver, 4);
                bump(S.inv[INV_TLS_VER], vname);
                if (*ver == 0x0300 || *ver == 0x0002) {
                    add(SEV_ERROR, CAT_SECURITY, PN, std::string(p) + ".ssl_negotiated", "SSL 2.0/3.0 negotiated (POODLE, broken)",
                        vname, std::string(p) + ".handshake.type == 2 && " + p + ".handshake.version <= 0x0300");
                } else if (*ver == 0x0301 || *ver == 0x0302 || *ver == 0xfeff) {
                    add(SEV_WARN, CAT_SECURITY, PN, std::string(p) + ".deprecated_version",
                        "Deprecated protocol version negotiated (RFC 8996)", vname,
                        std::string(p) + ".handshake.type == 2 && " + p + ".handshake.version in {0x0301 0x0302 0xfeff}");
                }
            }
            if (size_t n = P.count(f_cs)) {
                std::string name = P.label(f_cs, n - 1);
                std::string why;
                int sev = cipher_weakness(name, why);
                if (sev) {
                    add(sev, CAT_SECURITY, PN, std::string(p) + ".weak_cipher." + slug(why),
                        "Weak cipher suite negotiated: " + why, name,
                        fmt("%s.handshake.type == 2 && %s.handshake.ciphersuite == %s", p, p,
                            hex(P.u(f_cs, n - 1).value_or(0), 4).c_str()));
                }
            }
        }

        if (certificate) {
            static const std::unordered_map<std::string, const char *> weak = {
                {"1.2.840.113549.1.1.2", "md2WithRSAEncryption"}, {"1.2.840.113549.1.1.4", "md5WithRSAEncryption"},
                {"1.2.840.113549.1.1.5", "sha1WithRSAEncryption"}, {"1.2.840.10040.4.3", "dsa-with-sha1"},
                {"1.2.840.10045.4.1", "ecdsa-with-SHA1"}, {"1.3.14.3.2.29", "sha1WithRSASignature"}};
            for (size_t i = 0; i < P.count(X509_ALG_ID); ++i) {
                std::string oid = P.s(X509_ALG_ID, i).value_or("");
                // Display form may be "sha1WithRSAEncryption (1.2.840...)"; match either the OID or the name.
                for (const auto &w : weak) {
                    if (contains(oid, w.first.c_str()) || lower(oid) == lower(w.second)) {
                        add(SEV_WARN, CAT_SECURITY, PN, "x509.weak_signature", "Certificate uses weak signature algorithm",
                            w.second, "x509af.algorithm.id == " + w.first);
                        goto sig_done;
                    }
                }
            }
        sig_done:
            size_t nutc = P.count(X509_UTCTIME), ngen = P.count(X509_GENTIME);
            // Validity pairs (notBefore, notAfter) can only be paired reliably with one time type in the frame.
            Fld tf = nutc ? X509_UTCTIME : X509_GENTIME;
            size_t nt = nutc ? nutc : ngen;
            if ((nutc == 0 || ngen == 0) && nt >= 2) {
                for (size_t i = 0; i + 1 < nt; i += 2) {
                    int64_t nb = 0, na = 0;
                    bool okb = parse_x509_time(P.s(tf, i).value_or(""), nb);
                    bool oka = parse_x509_time(P.s(tf, i + 1).value_or(""), na);
                    if (oka && time_ > static_cast<double>(na)) {
                        add(SEV_ERROR, CAT_SECURITY, PN, "x509.expired", "Expired certificate presented",
                            "notAfter " + iso_utc(static_cast<double>(na)), std::string(p) + ".handshake.type == 11");
                        break;
                    }
                    if (okb && time_ < static_cast<double>(nb)) {
                        add(SEV_WARN, CAT_SECURITY, PN, "x509.not_yet_valid", "Certificate not yet valid",
                            "notBefore " + iso_utc(static_cast<double>(nb)), std::string(p) + ".handshake.type == 11");
                        break;
                    }
                }
            }
        }

        if (auto ad = P.u(f_alert)) {
            unsigned a = static_cast<unsigned>(*ad);
            const char *an = tls_alert_name(a);
            std::string name = an ? an : fmt("%u", a);
            if (a == 0) {
                // close_notify: normal shutdown
            } else if (a == 90) {
                add(SEV_INFO, CAT_PROTOCOL, PN, std::string(p) + ".alert.user_canceled", "TLS alert: user_canceled", {},
                    fmt("%s.alert_message.desc == 90", p));
            } else {
                bool cert = a >= 42 && a <= 48;
                add(cert ? SEV_ERROR : SEV_WARN, cert ? CAT_SECURITY : CAT_PROTOCOL, PN, std::string(p) + ".alert." + name,
                    "TLS alert: " + name, src() + " -> " + dst(), fmt("%s.alert_message.desc == %u", p, a));
            }
        }

        if (!dtls && P.has(TLS_HEARTBEAT)) {
            add(SEV_WARN, CAT_SECURITY, PN, "tls.heartbeat", "TLS heartbeat in use (Heartbleed exposure check)", {},
                "tls.heartbeat_message");
        }
    }

    // ------------------------------------------------------------ QUIC
    void quic() {
        if (P.has(GQUIC_VERSION)) {
            add(SEV_WARN, CAT_SECURITY, "gQUIC", "gquic.legacy", "Legacy Google QUIC (pre-IETF) in use",
                P.s(GQUIC_VERSION).value_or(""), "gquic");
        }
        if (!P.has(QUIC_HEADER_FORM) && !P.has(QUIC_VERSION)) return;
        quic_ = true;
        auto vers = P.u(QUIC_VERSION);
        if (vers) {
            uint32_t v = static_cast<uint32_t>(*vers);
            std::string vname = quic_version_name(v);
            bump(S.inv[INV_QUIC_VER], vname);
            std::string vf = "quic.version == " + hex(v, 8);
            if (v == 0) {
                add(SEV_NOTE, CAT_PROTOCOL, "QUIC", "quic.version_negotiation", "QUIC version negotiation (version mismatch)",
                    {}, "quic.version == 0");
            } else if (vname.rfind("draft", 0) == 0) {
                add(SEV_WARN, CAT_PROTOCOL, "QUIC", "quic.draft_version", "Pre-standard QUIC draft version", vname, vf);
            } else if (vname.rfind("Google", 0) == 0) {
                add(SEV_WARN, CAT_SECURITY, "QUIC", "quic.google_version", "Google proprietary QUIC version", vname, vf);
            } else if (vname.rfind("unknown", 0) == 0) {
                add(SEV_NOTE, CAT_ANOMALY, "QUIC", "quic.unknown_version", "Unknown QUIC version", vname, vf);
            }
        }
        auto lt = P.u(QUIC_LONG_TYPE);
        if (lt && vers && *vers != 0) {
            if (*lt == 3)
                add(SEV_INFO, CAT_PROTOCOL, "QUIC", "quic.retry", "QUIC Retry (address validation)", {}, "quic.long.packet_type == 3");
            else if (*lt == 1)
                add(SEV_NOTE, CAT_SECURITY, "QUIC", "quic.zero_rtt", "QUIC 0-RTT data (replayable)", {}, "quic.long.packet_type == 1");
        }
        uint64_t dport = P.u(UDP_DSTPORT).value_or(0), sport = P.u(UDP_SRCPORT).value_or(0);
        auto std_port = [](uint64_t x) { return x == 443 || x == 8443; };
        if (lt && *lt == 0 && !std_port(dport) && !std_port(sport) && once(fmt("quicport%llu", (unsigned long long)dport))) {
            add(SEV_INFO, CAT_INVENTORY, "QUIC", "quic.nonstandard_port", "QUIC on non-standard port",
                fmt("UDP %llu", (unsigned long long)dport), "quic && !(udp.port in {443 8443})");
        }
        for (size_t i = 0; i < P.count(QUIC_FRAME_TYPE); ++i) {
            auto t = P.u(QUIC_FRAME_TYPE, i);
            if (t && (*t == 0x1c || *t == 0x1d)) {
                auto ec = P.u(QUIC_CC_ERROR);
                if (ec && *ec != 0) {
                    add(SEV_WARN, CAT_PROTOCOL, "QUIC", "quic.connection_close_error", "QUIC CONNECTION_CLOSE with error",
                        fmt("error %s (%s)", hex(*ec).c_str(), *t == 0x1d ? "application" : "transport"), "quic.cc.error_code != 0");
                }
                break;
            }
        }
    }

    // ------------------------------------------------------------ Bluetooth
    std::string ble_link() const {
        if (auto aa = P.u(BTLE_AA)) return fmt("aa:%llx", (unsigned long long)*aa);
        if (auto ch = P.u(BTHCI_CHANDLE)) return fmt("hci:%llu", (unsigned long long)*ch);
        return "link";
    }

    void bluetooth() {
        if (P.has(BTLE_CRC_BAD) && ++S.crc_bad == 25) {
            add(SEV_WARN, CAT_PERFORMANCE, "BLE", "btle.crc_errors", "Many BLE CRC errors (RF interference/weak signal)",
                "25+ frames", "btle.crc.incorrect");
        }
        auto pdu = P.u(BTLE_ADV_PDU);
        if (pdu) {
            if (auto adv = P.s(BTLE_ADV_ADDR)) {
                auto name = P.s(BT_DEVICE_NAME);
                std::string label = name ? *adv + " (" + clean(*name, 40) + ")" : *adv;
                bool first = S.inv[INV_BLE_DEV].find(clean(label, 200)) == S.inv[INV_BLE_DEV].end();
                bump(S.inv[INV_BLE_DEV], label);
                if (first && name) {
                    add(SEV_INFO, CAT_INVENTORY, "BLE", "btle.device_name_advertised", "BLE device advertises its name", label,
                        "btcommon.eir_ad.entry.device_name");
                }
            }
        }
        const std::string lk = ble_link();
        auto mark_encrypted = [&]() { if (S.ble_encrypted.size() < 65536) S.ble_encrypted.insert(lk); };

        if (auto ll = P.u(BTLE_CTRL_OPCODE)) {
            if (*ll == 0x03 || *ll == 0x05 || *ll == 0x06) {
                mark_encrypted();
            } else if (*ll == 0x0d || *ll == 0x11) {
                add(SEV_NOTE, CAT_PROTOCOL, "BLE", "btle.ll_reject", "BLE link-layer procedure rejected", {},
                    "btle.control_opcode in {0x0d 0x11}");
            }
        }
        auto ev = P.u(BTHCI_EVT_CODE);
        if (ev && *ev == 0x08 && P.flag(BTHCI_ENC_ENABLE)) mark_encrypted();
        if (ev && *ev == 0x05) {
            auto r = P.u(BTHCI_EVT_REASON);
            if (r && (*r == 0x05 || *r == 0x06 || *r == 0x3d)) {
                add(SEV_WARN, CAT_SECURITY, "BT HCI", "bthci.auth_disconnect", "Disconnected due to authentication/key failure",
                    "reason " + hex(*r), "bthci_evt.reason in {0x05 0x06 0x3d}");
            }
        }
        if (auto st = P.u(BTHCI_EVT_STATUS)) {
            if (*st != 0 && !(ev && *ev == 0x05)) {
                add(SEV_NOTE, CAT_PROTOCOL, "BT HCI", "bthci.command_failed", "HCI command/event with non-success status",
                    "status " + hex(*st), "bthci_evt.status != 0");
            }
        }
        if (auto cmd = P.u(BTHCI_CMD_OPCODE); cmd && *cmd == 0x2019) mark_encrypted();

        if (auto smp = P.u(BTSMP_OPCODE)) {
            if (*smp == 0x01 || *smp == 0x02) {
                const char *role = *smp == 0x01 ? "Pairing Request" : "Pairing Response";
                if (P.flag_false(BTSMP_SC)) {
                    add(SEV_ERROR, CAT_SECURITY, "BLE SMP", "btsmp.legacy_pairing",
                        "LE Legacy Pairing (no Secure Connections; keys recoverable by sniffing)", role,
                        "btsmp.opcode in {1 2} && btsmp.sc_flag == 0");
                }
                if (auto io = P.u(BTSMP_IO); io && *io == 3) {
                    add(SEV_WARN, CAT_SECURITY, "BLE SMP", "btsmp.just_works",
                        "NoInputNoOutput IO capability (Just Works, no MITM protection)", role, "btsmp.io_capability == 3");
                }
                if (P.flag_false(BTSMP_MITM)) {
                    add(SEV_NOTE, CAT_SECURITY, "BLE SMP", "btsmp.no_mitm", "MITM protection not requested", role, "btsmp.mitm_flag == 0");
                }
                if (auto ks = P.u(BTSMP_KEYSIZE); ks && *ks < 16) {
                    add(*ks < 7 ? SEV_ERROR : SEV_WARN, CAT_SECURITY, "BLE SMP", "btsmp.short_key",
                        "Reduced encryption key size (KNOB-style weakness)", fmt("%llu bytes", (unsigned long long)*ks),
                        "btsmp.max_enc_key_size < 16");
                }
            } else if (*smp == 0x05) {
                static const char *const reasons[] = {"", "Passkey Entry Failed", "OOB Not Available",
                    "Authentication Requirements", "Confirm Value Failed", "Pairing Not Supported", "Encryption Key Size",
                    "Command Not Supported", "Unspecified Reason", "Repeated Attempts", "Invalid Parameters",
                    "DHKey Check Failed", "Numeric Comparison Failed", "BR/EDR pairing in progress",
                    "Cross-transport Key Derivation not allowed", "Key Rejected"};
                uint64_t r = P.u(BTSMP_REASON).value_or(0);
                add(SEV_WARN, CAT_SECURITY, "BLE SMP", "btsmp.pairing_failed", "BLE pairing failed",
                    (r > 0 && r < 16) ? reasons[r] : fmt("reason %llu", (unsigned long long)r), "btsmp.opcode == 5");
            } else if (*smp == 0x06) {
                if (!S.ble_encrypted.count(lk)) {
                    add(SEV_ERROR, CAT_SECURITY, "BLE SMP", "btsmp.ltk_cleartext",
                        "Long Term Key distributed on a link with no observed encryption", {}, "btsmp.opcode == 6");
                } else {
                    add(SEV_INFO, CAT_SECURITY, "BLE SMP", "btsmp.key_distribution", "SMP key distribution observed", {},
                        "btsmp.opcode == 6");
                }
            } else if (*smp == 0x0b) {
                add(SEV_INFO, CAT_SECURITY, "BLE SMP", "btsmp.security_request", "Peripheral requests security", {},
                    "btsmp.opcode == 0x0b");
            }
        }

        if (auto att = P.u(BTATT_OPCODE)) {
            auto ec = P.u(BTATT_ERROR);
            std::string handle = P.u(BTATT_HANDLE) ? hex(*P.u(BTATT_HANDLE), 4) : std::string("?");
            if (*att == 0x01 && ec) {
                if (*ec == 0x05 || *ec == 0x0f || *ec == 0x0c || *ec == 0x08) {
                    add(SEV_NOTE, CAT_SECURITY, "BLE ATT", "btatt.insufficient_security",
                        "ATT access denied: insufficient authentication/encryption/authorization",
                        "error " + hex(*ec) + " handle " + handle, "btatt.error_code in {0x05 0x08 0x0c 0x0f}");
                } else {
                    add(SEV_INFO, CAT_PROTOCOL, "BLE ATT", "btatt.error", "ATT error response", "error " + hex(*ec),
                        "btatt.opcode == 0x01");
                }
            } else if ((*att == 0x12 || *att == 0x52 || *att == 0x16) && !pdu && !S.ble_encrypted.count(lk)) {
                add(SEV_WARN, CAT_SECURITY, "BLE ATT", "btatt.cleartext_write", "GATT write on a link with no observed encryption",
                    "handle " + handle, "btatt.opcode in {0x12 0x52 0x16}");
            }
        }
    }

    // ------------------------------------------------------------ 802.11
    void wlan() {
        auto ts = P.u(WLAN_TYPE_SUBTYPE);
        if (!ts) return;
        if (P.has(WLAN_WEP_IV))
            add(SEV_ERROR, CAT_SECURITY, "802.11", "wlan.wep", "WEP-encrypted wireless traffic (broken encryption)", {}, "wlan.wep.iv");
        if (*ts == 0x000c || *ts == 0x000a) {
            std::string bssid = P.s(WLAN_BSSID).value_or("?");
            uint64_t n = bump(S.deauth, bssid);
            if (n == 20) {
                add(SEV_ERROR, CAT_SECURITY, "802.11", "wlan.deauth_flood", "802.11 deauthentication/disassociation flood",
                    "BSSID " + bssid, "wlan.fc.type_subtype in {0x000a 0x000c}");
            } else if (n > 0 && n < 20) {
                add(SEV_NOTE, CAT_PROTOCOL, "802.11", "wlan.deauth", "802.11 deauthentication/disassociation",
                    fmt("reason %llu", (unsigned long long)P.u(WLAN_REASON).value_or(0)), "wlan.fc.type_subtype in {0x000a 0x000c}");
            }
        }
    }

    // ------------------------------------------------------------ SSH / SMB / Kerberos / LDAP / RDP
    void remote() {
        if (auto proto = P.s(SSH_PROTOCOL)) {
            bump(S.inv[INV_SSH_SW], *proto);
            if (proto->rfind("SSH-1.", 0) == 0 && proto->rfind("SSH-1.99", 0) != 0) {
                add(SEV_ERROR, CAT_SECURITY, "SSH", "ssh.v1", "SSH protocol version 1 (broken)", *proto,
                    "ssh.protocol contains \"SSH-1.\"");
            }
        }
        std::string algs = P.s(SSH_KEX).value_or("") + "," + P.s(SSH_ENC_C2S).value_or("") + "," +
                            P.s(SSH_MAC_C2S).value_or("") + "," + P.s(SSH_HOSTKEY_ALGS).value_or("");
        if (algs.size() > 3) {
            static const char *const weak[] = {"diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1", "arcfour",
                "3des-cbc", "blowfish-cbc", "cast128-cbc", "hmac-md5", "ssh-dss", "des-cbc"};
            std::string found;
            for (const char *w : weak) if (contains(algs, w)) found += (found.empty() ? "" : ", ") + std::string(w);
            if (!found.empty())
                add(SEV_NOTE, CAT_SECURITY, "SSH", "ssh.weak_algorithms_offered", "SSH peer offers weak algorithms", found,
                    "ssh.kex_algorithms");
        }

        if (P.has(SMB1))
            add(SEV_ERROR, CAT_SECURITY, "SMB", "smb.v1", "SMBv1 in use (EternalBlue-class exposure)", {}, "smb");
        if (auto dialect = P.u(SMB2_DIALECT); dialect && *dialect != 0x02ff) {
            bump(S.inv[INV_SMB_DIALECT], hex(*dialect, 4));
            if (*dialect < 0x0300)
                add(SEV_NOTE, CAT_SECURITY, "SMB2", "smb2.old_dialect", "SMB 2.x dialect negotiated (no encryption support)",
                    hex(*dialect, 4), "smb2.dialect < 0x0300");
        }
        if (P.flag_false(SMB2_SIGN_REQUIRED) && P.u(SMB2_CMD).value_or(1) == 0) {
            add(SEV_WARN, CAT_SECURITY, "SMB2", "smb2.signing_not_required", "SMB signing not required (relay attack exposure)",
                src(), "smb2.cmd == 0 && smb2.sec_mode.sign_required == 0");
        }
        if (auto nts = P.u(SMB2_NT_STATUS)) {
            if (*nts == 0xc000006dULL || *nts == 0xc000006aULL || *nts == 0xc0000234ULL) {
                std::string client = dst();
                add(SEV_NOTE, CAT_SECURITY, "SMB2", "smb2.logon_failure", "SMB logon failure", hex(*nts, 8),
                    "smb2.nt_status in {0xc000006d 0xc000006a 0xc0000234}");
                if (bump(S.smb_fail, client) == 10)
                    add(SEV_ERROR, CAT_SECURITY, "SMB2", "smb2.bruteforce",
                        "Repeated SMB logon failures (password spraying/brute force)", client, "smb2.nt_status == 0xc000006d");
            }
        }
        for (size_t i = 0; i < P.count(KRB_ETYPE); ++i) {
            auto et = P.u(KRB_ETYPE, i);
            if (et && (*et == 23 || *et == 24 || *et == 1 || *et == 3)) {
                add(SEV_WARN, CAT_SECURITY, "Kerberos", "kerberos.weak_etype",
                    "Kerberos RC4/DES encryption type (Kerberoasting/downgrade)", fmt("etype %llu", (unsigned long long)*et),
                    "kerberos.etype in {1 3 23 24}");
                break;
            }
        }
        if (auto kerr = P.u(KRB_ERROR); kerr && (*kerr == 24 || *kerr == 18)) {
            std::string client = dst();
            if (bump(S.krb_fail, client) == 10)
                add(SEV_ERROR, CAT_SECURITY, "Kerberos", "kerberos.bruteforce", "Repeated Kerberos pre-authentication failures",
                    client, "kerberos.error_code == 24");
        }
        if (P.has(LDAP_SIMPLE) && !P.has(TLS_RECORD_VERSION))
            add(SEV_ERROR, CAT_SECURITY, "LDAP", "ldap.simple_bind_cleartext", "LDAP simple bind in cleartext", {}, "ldap.simple");
        if (auto rdp = P.u(RDP_REQ_PROTOCOLS); rdp && *rdp == 0)
            add(SEV_WARN, CAT_SECURITY, "RDP", "rdp.standard_security", "RDP client requests Standard RDP Security (no TLS/NLA)",
                {}, "rdp.negReq.requestedProtocols == 0");
    }

    // ------------------------------------------------------------ cleartext application protocols
    void cleartext() {
        bool tls = P.has(TLS_RECORD_VERSION);
        if (auto ftp = P.s(FTP_COMMAND)) {
            std::string c = upper(*ftp);
            if (c == "PASS")
                add(SEV_ERROR, CAT_SECURITY, "FTP", "ftp.cleartext_password", "FTP password sent in cleartext", {},
                    "ftp.request.command == \"PASS\"");
            else if (c == "USER")
                add(SEV_WARN, CAT_SECURITY, "FTP", "ftp.cleartext_login", "FTP login over cleartext", {},
                    "ftp.request.command == \"USER\"");
        }
        if (P.has(TELNET_DATA) && once(fmt("telnet%llu", (unsigned long long)P.u(TCP_STREAM).value_or(~0ULL)))) {
            add(SEV_WARN, CAT_SECURITY, "Telnet", "telnet.session", "Telnet session (cleartext remote shell)",
                src() + " -> " + dst(), "telnet");
        }
        if (auto pop = P.s(POP_COMMAND); pop && !tls && (upper(*pop) == "PASS" || upper(*pop) == "APOP"))
            add(SEV_ERROR, CAT_SECURITY, "POP3", "pop.cleartext_password", "POP3 password in cleartext", {},
                "pop.request.command == \"PASS\"");
        if (auto imap = P.s(IMAP_REQUEST); imap && !tls && contains(upper(*imap), "LOGIN"))
            add(SEV_ERROR, CAT_SECURITY, "IMAP", "imap.cleartext_login", "IMAP LOGIN in cleartext", {},
                "imap.request contains \"LOGIN\"");
        if (auto smtp = P.s(SMTP_COMMAND); smtp && !tls && upper(*smtp) == "AUTH")
            add(SEV_WARN, CAT_SECURITY, "SMTP", "smtp.cleartext_auth", "SMTP AUTH without TLS", {}, "smtp.req.command == \"AUTH\"");
        if (auto community = P.s(SNMP_COMMUNITY)) {
            std::string lc = lower(*community);
            if (lc == "public" || lc == "private" || lc == "community" || lc == "admin")
                add(SEV_WARN, CAT_SECURITY, "SNMP", "snmp.default_community", "SNMP default community string", {},
                    "snmp.community in {\"public\" \"private\"}");
            else
                add(SEV_NOTE, CAT_SECURITY, "SNMP", "snmp.v1v2_cleartext", "SNMPv1/v2c community sent in cleartext", {},
                    "snmp.community");
        }
        if ((P.has(MQTT_PASSWD) || P.has(MQTT_USERNAME)) && !tls)
            add(SEV_ERROR, CAT_SECURITY, "MQTT", "mqtt.cleartext_credentials", "MQTT credentials in cleartext", {},
                "mqtt.passwd || mqtt.username");
        if (P.has(TFTP_OPCODE))
            add(SEV_INFO, CAT_SECURITY, "TFTP", "tftp.in_use", "TFTP transfer (unauthenticated, cleartext)", {}, "tftp");
        auto mode = P.u(NTP_MODE);
        if ((mode && *mode == 7) || P.has(NTP_REQCODE)) {
            auto rc = P.u(NTP_REQCODE);
            if (rc && (*rc == 42 || *rc == 20))
                add(SEV_ERROR, CAT_SECURITY, "NTP", "ntp.monlist", "NTP monlist request (DDoS amplification)", {},
                    "ntp.priv.reqcode in {20 42}");
            else
                add(SEV_NOTE, CAT_SECURITY, "NTP", "ntp.mode7", "NTP mode 7 private request", {}, "ntp.flags.mode == 7");
        }
        if (auto sc = P.u(SIP_STATUS); sc && (*sc == 401 || *sc == 403 || *sc == 407)) {
            std::string client = dst();
            if (bump(S.sip_fail, client) == 20)
                add(SEV_WARN, CAT_SECURITY, "SIP", "sip.auth_failures", "Repeated SIP authentication failures (toll-fraud scanning)",
                    client, "sip.Status-Code in {401 403 407}");
        }
    }
};

// ------------------------------------------------------------------ reports
std::vector<std::pair<std::string, const IdEntry *>> sorted_findings(const State &S) {
    std::vector<std::pair<std::string, const IdEntry *>> out;
    out.reserve(S.by_id.size());
    for (const auto &kv : S.by_id) out.emplace_back(kv.first, &kv.second);
    std::sort(out.begin(), out.end(), [](const auto &a, const auto &b) {
        if (a.second->sev != b.second->sev) return a.second->sev > b.second->sev;
        if (a.second->count != b.second->count) return a.second->count > b.second->count;
        return a.first < b.first;
    });
    return out;
}

std::vector<std::pair<std::string, uint64_t>> top(const Counter &c, size_t n) {
    std::vector<std::pair<std::string, uint64_t>> v(c.begin(), c.end());
    std::sort(v.begin(), v.end(), [](const auto &a, const auto &b) {
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });
    if (v.size() > n) v.resize(n);
    return v;
}

std::string missing_fields() {
    std::string out;
    for (int i = 0; i < FLD_COUNT; ++i)
        if (g_hf_ids[i] < 0) out += (out.empty() ? "" : ", ") + std::string(FIELD_NAMES[i]);
    return out;
}

std::string build_report(const State &S) {
    std::string r;
    auto line = [&](const std::string &s) { r += s + "\n"; };
    line(fmt("Wireshark Assist %s -- capture findings report", ENGINE_VERSION));
    line(std::string(78, '='));
    double dur = S.have_ts ? S.last_ts - S.first_ts : 0;
    line(fmt("Frames analyzed: %llu   Duration: %.3f s   Start: %s", (unsigned long long)S.packets, dur,
             S.have_ts ? iso_utc(S.first_ts).c_str() : "n/a"));
    line(fmt("Findings: %llu error, %llu warning, %llu note, %llu info   Distinct types: %zu",
             (unsigned long long)S.sev_count[4], (unsigned long long)S.sev_count[3], (unsigned long long)S.sev_count[2],
             (unsigned long long)S.sev_count[1], S.by_id.size()));
    if (S.packets == 0) line("\nNo frames have been analyzed yet. Open or reload a capture.");

    auto protos = top(S.protos, 25);
    if (!protos.empty()) {
        line("");
        line(fmt("Protocols (frames containing each, top %zu of %zu):", protos.size(), S.protos.size()));
        std::string row;
        for (size_t i = 0; i < protos.size(); ++i) {
            row += fmt("%s=%llu  ", protos[i].first.c_str(), (unsigned long long)protos[i].second);
            if (i % 6 == 5 || i + 1 == protos.size()) {
                line("  " + row);
                row.clear();
            }
        }
    }
    line("");
    line("Findings (most severe first)");
    line(std::string(78, '-'));
    auto list = sorted_findings(S);
    if (list.empty()) line("  None.");
    static const char *const tags[] = {"", "INFO ", "NOTE ", "WARN ", "ERROR"};
    for (const auto &it : list) {
        const IdEntry &e = *it.second;
        line(fmt("[%s] %-9s %s", tags[e.sev], e.proto.c_str(), e.title.c_str()));
        line(fmt("         id=%s  count=%llu  first=#%u  last=#%u  category=%s", it.first.c_str(), (unsigned long long)e.count,
                 e.first, e.last, CATEGORY_NAMES[e.cat]));
        if (!e.filter.empty()) line("         filter: " + e.filter);
        for (const auto &ex : e.examples) line("         e.g. " + ex);
        if (e.count > e.stored)
            line(fmt("         (%llu occurrences not annotated; raise 'Max stored findings per ID')",
                     (unsigned long long)(e.count - e.stored)));
    }
    bool header = false;
    for (int i = 0; i < INV_COUNT; ++i) {
        auto items = top(S.inv[i], 15);
        if (items.empty()) continue;
        if (!header) {
            line("");
            line("Inventory");
            line(std::string(78, '-'));
            header = true;
        }
        line(fmt("%s (%zu distinct):", INVENTORY_LABELS[i], S.inv[i].size()));
        for (const auto &x : items) line(fmt("  %6llu  %s", (unsigned long long)x.second, clean(x.first, 100).c_str()));
    }
    line("");
    line("Filters: ws_assist.severity >= 3 | ws_assist.category == \"security\" | ws_assist.id == \"<id>\"");
    if (S.untreed) line(fmt("Frames skipped without a protocol tree: %llu", (unsigned long long)S.untreed));
    std::string missing = missing_fields();
    if (!missing.empty()) line("Fields unavailable in this Wireshark build (related checks disabled): " + missing);
    return r;
}

void write_finding(JsonWriter &w, const Finding &f) {
    w.begin_object();
    w.key("id").str(f.id).key("severity").str(severity_name(f.sev)).key("severity_level").num(f.sev);
    w.key("category").str(CATEGORY_NAMES[f.cat]).key("protocol").str(f.proto).key("title").str(f.title);
    if (!f.detail.empty()) w.key("detail").str(f.detail);
    if (!f.filter.empty()) w.key("filter").str(f.filter);
    w.end_object();
}

std::string build_summary_json(const State &S, uint32_t max_findings) {
    JsonWriter w;
    w.begin_object();
    w.key("engine").str(std::string("Wireshark Assist ") + ENGINE_VERSION);
    w.key("generation").num(static_cast<double>(g_generation));
    w.key("capture").begin_object();
    w.key("frames_analyzed").num(static_cast<double>(S.packets));
    w.key("duration_seconds").num(S.have_ts ? std::floor((S.last_ts - S.first_ts) * 1000.0) / 1000.0 : 0);
    if (S.have_ts) w.key("start_utc").str(iso_utc(S.first_ts));
    else w.key("start_utc").null();
    w.end_object();
    w.key("severity_totals").begin_object();
    w.key("error").num(static_cast<double>(S.sev_count[4])).key("warning").num(static_cast<double>(S.sev_count[3]));
    w.key("note").num(static_cast<double>(S.sev_count[2])).key("info").num(static_cast<double>(S.sev_count[1]));
    w.end_object();
    w.key("protocols").begin_object();
    for (const auto &p : top(S.protos, 40)) w.key(p.first).num(static_cast<double>(p.second));
    w.end_object();
    w.key("findings").begin_array();
    uint32_t n = 0;
    for (const auto &it : sorted_findings(S)) {
        if (max_findings && n++ >= max_findings) break;
        const IdEntry &e = *it.second;
        w.begin_object();
        w.key("id").str(it.first).key("severity").str(severity_name(e.sev)).key("severity_level").num(e.sev);
        w.key("category").str(CATEGORY_NAMES[e.cat]).key("protocol").str(e.proto).key("title").str(e.title);
        w.key("count").num(static_cast<double>(e.count)).key("first_frame").num(e.first).key("last_frame").num(e.last);
        if (!e.filter.empty()) w.key("filter").str(e.filter);
        w.key("examples").begin_array();
        for (const auto &ex : e.examples) w.str(ex);
        w.end_array();
        w.end_object();
    }
    w.end_array();
    w.key("inventory").begin_object();
    for (int i = 0; i < INV_COUNT; ++i) {
        auto items = top(S.inv[i], 10);
        if (items.empty()) continue;
        w.key(INVENTORY_KEYS[i]).begin_array();
        for (const auto &x : items) {
            w.begin_object().key("value").str(clean(x.first, 120)).key("count").num(static_cast<double>(x.second)).end_object();
        }
        w.end_array();
    }
    w.end_object();
    // Dashboard data: categories, timeline and hosts.
    w.key("categories").begin_object();
    for (int c = 0; c < CAT_COUNT; ++c) w.key(CATEGORY_NAMES[c]).num(static_cast<double>(S.cat_count[c]));
    w.end_object();
    if (S.have_ts) {
        const int64_t start = static_cast<int64_t>(std::floor(S.first_ts));
        const int64_t span = static_cast<int64_t>(std::floor(S.last_ts)) - start + 1;
        const int64_t bucket = std::max<int64_t>(1, (span + TIMELINE_BUCKETS - 1) / TIMELINE_BUCKETS);
        const size_t nb = static_cast<size_t>((span + bucket - 1) / bucket);
        std::vector<double> packets(nb, 0.0);
        std::array<std::vector<double>, 5> sev(
            {std::vector<double>(nb, 0.0), std::vector<double>(nb, 0.0), std::vector<double>(nb, 0.0),
             std::vector<double>(nb, 0.0), std::vector<double>(nb, 0.0)});
        auto index = [&](int64_t sec) {
            int64_t i = (sec - start) / bucket;
            return static_cast<size_t>(std::clamp<int64_t>(i, 0, static_cast<int64_t>(nb) - 1));
        };
        for (const auto &kv : S.sec_packets) packets[index(kv.first)] += kv.second;
        for (const auto &kv : S.sec_findings)
            for (size_t k = 1; k < 5; ++k) sev[k][index(kv.first)] += kv.second[k];
        w.key("timeline").begin_object();
        w.key("start_epoch").num(static_cast<double>(start)).key("bucket_seconds").num(static_cast<double>(bucket));
        auto arr = [&](const char *name, const std::vector<double> &v) {
            w.key(name).begin_array();
            for (double x : v) w.num(x);
            w.end_array();
        };
        arr("packets", packets);
        arr("error", sev[SEV_ERROR]);
        arr("warning", sev[SEV_WARN]);
        arr("note", sev[SEV_NOTE]);
        arr("info", sev[SEV_INFO]);
        w.end_object();
    }
    w.key("top_hosts").begin_array();
    for (const auto &h : top(S.host_findings, 10)) {
        auto wi = S.host_worst.find(h.first);
        w.begin_object().key("host").str(h.first).key("findings").num(static_cast<double>(h.second));
        w.key("worst_severity").str(severity_name(wi == S.host_worst.end() ? 0 : wi->second)).end_object();
    }
    w.end_array();
    w.key("missing_fields").str(missing_fields());
    w.end_object();
    return w.str();
}

// ------------------------------------------------------------------ C API for the UI plugin
char *dup_string(const std::string &s) {
    char *out = static_cast<char *>(std::malloc(s.size() + 1));
    if (!out) return nullptr;
    std::memcpy(out, s.c_str(), s.size() + 1);
    return out;
}

uint64_t api_generation(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_generation;
}

char *api_summary_json(uint32_t max_findings) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return dup_string(build_summary_json(state(), max_findings));
}

char *api_frame_findings_json(uint32_t frame) {
    std::lock_guard<std::mutex> lock(g_mutex);
    JsonWriter w;
    w.begin_array();
    auto it = state().frames.find(frame);
    if (it != state().frames.end())
        for (const auto &f : it->second) write_finding(w, f);
    w.end_array();
    return dup_string(w.str());
}

char *api_report_text(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return dup_string(build_report(state()));
}

void api_free_string(char *s) { std::free(s); }

const assist_engine_api_t g_api = {ASSIST_API_ABI, "1.0.0", api_generation, api_summary_json,
                                   api_frame_findings_json, api_report_text, api_free_string};

// ------------------------------------------------------------------ dissection
void render(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const std::vector<Finding> &list) {
    std::vector<const Finding *> shown;
    uint8_t worst = 0;
    for (const auto &f : list) {
        if (f.sev >= pref_min_severity) {
            shown.push_back(&f);
            worst = std::max(worst, f.sev);
        }
    }
    if (shown.empty()) return;
    std::stable_sort(shown.begin(), shown.end(), [](const Finding *a, const Finding *b) { return a->sev > b->sev; });
    proto_item *root = proto_tree_add_protocol_format(tree, proto_assist, tvb, 0, 0, "Wireshark Assist: %zu finding%s (worst: %s)",
                                                      shown.size(), shown.size() == 1 ? "" : "s", severity_name(worst));
    proto_tree *rt = proto_item_add_subtree(root, ett_assist);
    proto_item_set_generated(proto_tree_add_uint(rt, hf_count, tvb, 0, 0, static_cast<uint32_t>(shown.size())));
    for (const Finding *f : shown) {
        std::string label = fmt("[%s] %s: %s", severity_name(f->sev), f->proto.c_str(), f->title.c_str());
        std::string text = f->detail.empty() ? label : label + " -- " + f->detail;
        proto_item *it = proto_tree_add_string_format(rt, hf_finding, tvb, 0, 0, f->title.c_str(), "%s", text.c_str());
        proto_item_set_generated(it);
        proto_tree *ft = proto_item_add_subtree(it, ett_finding);
        proto_item_set_generated(proto_tree_add_uint(ft, hf_severity, tvb, 0, 0, f->sev));
        proto_item_set_generated(proto_tree_add_string(ft, hf_id, tvb, 0, 0, f->id.c_str()));
        proto_item_set_generated(proto_tree_add_string(ft, hf_category, tvb, 0, 0, CATEGORY_NAMES[f->cat]));
        proto_item_set_generated(proto_tree_add_string(ft, hf_protocol, tvb, 0, 0, f->proto.c_str()));
        if (!f->detail.empty()) proto_item_set_generated(proto_tree_add_string(ft, hf_detail, tvb, 0, 0, f->detail.c_str()));
        if (!f->filter.empty()) proto_item_set_generated(proto_tree_add_string(ft, hf_filter, tvb, 0, 0, f->filter.c_str()));
        expert_add_info_format(pinfo, it, &g_ei[f->cat][f->sev], "%s", text.c_str());
    }
}

int dissect_assist(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *) {
    if (!pref_enabled) return 0;
    const bool first_pass = !PINFO_FD_VISITED(pinfo);
    std::vector<Finding> copy;
    uint8_t worst = 0;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        State &S = state();
        if (first_pass) {
            if (tree) {
                Pkt pkt(tree, pinfo);
                Analyzer(S, pkt).run();
            } else {
                ++S.untreed;
            }
        }
        auto it = S.frames.find(pinfo->num);
        if (it != S.frames.end()) {
            for (const auto &f : it->second) worst = std::max(worst, f.sev);
            if (tree) copy = it->second;
        }
    }

    if (have_tap_listener(assist_tap)) {
        auto *td = wmem_new0(pinfo->pool, assist_tap_data_t);
        td->abi = ASSIST_API_ABI;
        td->frame = pinfo->num;
        td->worst_severity = worst;
        td->first_pass = first_pass;
        td->api = &g_api;
        tap_queue_packet(assist_tap, pinfo, td);
    }
    if (tree && !copy.empty()) render(tvb, pinfo, tree, copy);
    return static_cast<int>(tvb_captured_length(tvb));
}

void init_routine(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    delete g_state;
    g_state = new State();
    ++g_generation;
    for (int i = 0; i < FLD_COUNT; ++i) g_hf_ids[i] = proto_registrar_get_id_byname(FIELD_NAMES[i]);
    GArray *wanted = g_array_sized_new(false, false, static_cast<unsigned>(sizeof(int)), FLD_COUNT);
    for (int i = 0; i < FLD_COUNT; ++i) {
        if (g_hf_ids[i] >= 0) g_array_append_val(wanted, g_hf_ids[i]);
    }
    set_postdissector_wanted_hfids(assist_handle, wanted);
}

void cleanup_routine(void) {
    set_postdissector_wanted_hfids(assist_handle, nullptr);
}

// ------------------------------------------------------------------ tshark -z ws_assist,report|json
struct CliTap {
    bool json;
};

tap_packet_status cli_packet(void *, packet_info *, epan_dissect_t *, const void *, tap_flags_t) {
    return TAP_PACKET_DONT_REDRAW;
}

void cli_draw(void *tapdata) {
    auto *t = static_cast<CliTap *>(tapdata);
    std::lock_guard<std::mutex> lock(g_mutex);
    if (t->json) std::printf("%s\n", build_summary_json(state(), 0).c_str());
    else std::printf("\n%s", build_report(state()).c_str());
    std::fflush(stdout);
}

void cli_finish(void *tapdata) { delete static_cast<CliTap *>(tapdata); }

bool cli_init(const char *opt_arg, void *) {
    // opt_arg is "ws_assist,report" or "ws_assist,json"
    const char *rest = std::strchr(opt_arg, ',');
    std::string mode = rest ? rest + 1 : "report";
    if (mode != "report" && mode != "json") {
        std::fprintf(stderr, "tshark: invalid -z ws_assist mode \"%s\" (use report or json)\n", mode.c_str());
        return false;
    }
    auto *t = new CliTap{mode == "json"};
    GString *err = register_tap_listener(ASSIST_TAP_NAME, t, nullptr, 0, nullptr, cli_packet, cli_draw, cli_finish);
    if (err) {
        std::fprintf(stderr, "tshark: couldn't register ws_assist tap: %s\n", err->str);
        g_string_free(err, true);
        delete t;
        return false;
    }
    return true;
}

stat_tap_ui g_cli_ui = {REGISTER_PACKET_ANALYZE_GROUP_UNSORTED, "Wireshark Assist findings", "ws_assist", cli_init, 0, nullptr};

} // namespace

void proto_register_wireshark_assist_engine(void) {
    static hf_register_info hf[] = {
        {&hf_count, {"Findings", "ws_assist.count", FT_UINT16, BASE_DEC, nullptr, 0x0, "Number of findings in this frame", HFILL}},
        {&hf_finding, {"Finding", "ws_assist.finding", FT_STRING, BASE_NONE, nullptr, 0x0, nullptr, HFILL}},
        {&hf_id, {"Finding ID", "ws_assist.id", FT_STRING, BASE_NONE, nullptr, 0x0, nullptr, HFILL}},
        {&hf_severity, {"Severity", "ws_assist.severity", FT_UINT8, BASE_DEC, VALS(severity_vals), 0x0, nullptr, HFILL}},
        {&hf_category, {"Category", "ws_assist.category", FT_STRING, BASE_NONE, nullptr, 0x0, nullptr, HFILL}},
        {&hf_protocol, {"Protocol", "ws_assist.protocol", FT_STRING, BASE_NONE, nullptr, 0x0, nullptr, HFILL}},
        {&hf_detail, {"Detail", "ws_assist.detail", FT_STRING, BASE_NONE, nullptr, 0x0, nullptr, HFILL}},
        {&hf_filter, {"Related filter", "ws_assist.filter", FT_STRING, BASE_NONE, nullptr, 0x0, nullptr, HFILL}},
    };
    static int *ett[] = {&ett_assist, &ett_finding};

    static const int groups[CAT_COUNT] = {PI_SECURITY, PI_SEQUENCE, PI_PROTOCOL, PI_PROTOCOL, PI_COMMENTS_GROUP};
    static const int sevs[5] = {0, PI_CHAT, PI_NOTE, PI_WARN, PI_ERROR};
    static ei_register_info ei[CAT_COUNT * 4];
    static std::string names[CAT_COUNT * 4], summaries[CAT_COUNT * 4];
    for (int c = 0; c < CAT_COUNT; ++c) {
        for (int s = SEV_INFO; s <= SEV_ERROR; ++s) {
            int i = c * 4 + (s - 1);
            names[i] = fmt("ws_assist.%s.%s", CATEGORY_NAMES[c], lower(severity_name(s)).c_str());
            summaries[i] = fmt("Wireshark Assist %s %s", CATEGORY_NAMES[c], lower(severity_name(s)).c_str());
            ei_register_info e = {&g_ei[c][s], {names[i].c_str(), groups[c], sevs[s], summaries[i].c_str(), EXPFILL}};
            ei[i] = e;
        }
    }

    proto_assist = proto_register_protocol("Wireshark Assist", "WS_ASSIST", "ws_assist");
    proto_register_field_array(proto_assist, hf, G_N_ELEMENTS(hf));
    proto_register_subtree_array(ett, G_N_ELEMENTS(ett));
    expert_module_t *em = expert_register_protocol(proto_assist);
    expert_register_field_array(em, ei, G_N_ELEMENTS(ei));

    module_t *m = prefs_register_protocol(proto_assist, nullptr);
    prefs_register_bool_preference(m, "enabled", "Enable analysis", "Analyze every frame for protocol and security findings",
                                   &pref_enabled);
    prefs_register_enum_preference(m, "min_severity", "Minimum severity shown in packet details",
                                   "Findings below this severity are not added to the packet tree", &pref_min_severity,
                                   severity_enum, false);
    prefs_register_uint_preference(m, "max_per_id", "Max annotated findings per ID",
                                   "Per-finding-type cap on per-packet annotations (counts keep increasing)", 10, &pref_max_per_id);
    prefs_register_uint_preference(m, "rtt_ms", "High latency threshold (ms)",
                                   "TCP ACK RTT and DNS response times above this are reported (HTTP uses 4x)", 10, &pref_rtt_ms);
    prefs_register_uint_preference(m, "scan_ports", "Port scan threshold",
                                   "Distinct destination ports probed by one source toward one host", 10, &pref_scan_ports);

    assist_handle = register_dissector("ws_assist", dissect_assist, proto_assist);
    register_init_routine(init_routine);
    register_cleanup_routine(cleanup_routine);
    assist_tap = register_tap(ASSIST_TAP_NAME);
    for (int &id : g_hf_ids) id = -1;
}

void proto_reg_handoff_wireshark_assist_engine(void) {
    register_postdissector(assist_handle);
    register_stat_tap_ui(&g_cli_ui, nullptr);
}
