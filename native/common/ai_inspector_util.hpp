// SPDX-License-Identifier: GPL-2.0-or-later
//
// AI Inspector - dependency-free helpers shared by the analysis engine and
// unit tests. Nothing in this header touches Wireshark or Qt APIs.
#pragma once

#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

namespace aiinspector {

enum Severity : uint8_t { SEV_INFO = 1, SEV_NOTE = 2, SEV_WARN = 3, SEV_ERROR = 4 };

inline const char *severity_name(int sev) {
    switch (sev) {
    case SEV_INFO: return "Info";
    case SEV_NOTE: return "Note";
    case SEV_WARN: return "Warning";
    case SEV_ERROR: return "Error";
    default: return "Unknown";
    }
}

// Make untrusted text safe for single-line display and bounded in size.
// Control bytes become '?', invalid UTF-8 sequences become '?'.
inline std::string clean(const std::string &in, size_t maxlen = 160) {
    std::string out;
    out.reserve(in.size() < maxlen ? in.size() : maxlen);
    size_t i = 0, n = in.size();
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(in[i]);
        size_t len = c < 0x80 ? 1 : (c >= 0xC2 && c <= 0xDF) ? 2 : (c >= 0xE0 && c <= 0xEF) ? 3
                   : (c >= 0xF0 && c <= 0xF4) ? 4 : 0;
        bool ok = len > 0 && i + len <= n;
        for (size_t k = 1; ok && k < len; ++k) {
            unsigned char b = static_cast<unsigned char>(in[i + k]);
            if (b < 0x80 || b > 0xBF) ok = false;
        }
        if (!ok) {
            out += '?';
            ++i;
        } else if (len == 1) {
            out += (c < 0x20 || c == 0x7F) ? '?' : static_cast<char>(c);
            ++i;
        } else {
            out.append(in, i, len);
            i += len;
        }
        if (out.size() >= maxlen) {
            if (i < n) {
                // Trim to a UTF-8 boundary before appending the ellipsis.
                size_t cut = maxlen > 3 ? maxlen - 3 : 0;
                while (cut > 0 && (static_cast<unsigned char>(out[cut]) & 0xC0) == 0x80) --cut;
                out.resize(cut);
                out += "...";
            }
            break;
        }
    }
    return out;
}

inline std::string lower(std::string s) {
    for (auto &ch : s) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    return s;
}

inline std::string upper(std::string s) {
    for (auto &ch : s) if (ch >= 'a' && ch <= 'z') ch = static_cast<char>(ch - 'a' + 'A');
    return s;
}

inline bool contains(const std::string &hay, const char *needle) {
    return hay.find(needle) != std::string::npos;
}

// Returns the first pattern found (case-insensitive), or nullptr.
inline const char *contains_any_ci(const std::string &s, const std::vector<const char *> &patterns) {
    std::string l = lower(s);
    for (const char *p : patterns) if (l.find(p) != std::string::npos) return p;
    return nullptr;
}

// Quote a string literal for a Wireshark display filter.
inline std::string filter_quote(const std::string &s) {
    std::string out = "\"";
    for (char ch : s) {
        unsigned char c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c == 0x7F) continue;
        if (ch == '"' || ch == '\\') out += '\\';
        out += ch;
    }
    return out + "\"";
}

inline std::string hex(uint64_t v, int width = 2) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%0*llx", width, static_cast<unsigned long long>(v));
    return buf;
}

inline std::string fmt(const char *f, ...) __attribute__((format(printf, 1, 2)));
inline std::string fmt(const char *f, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, f);
    std::vsnprintf(buf, sizeof buf, f, ap);
    va_end(ap);
    return buf;
}

// Shannon entropy in bits per byte.
inline double entropy(const std::string &s) {
    if (s.empty()) return 0.0;
    size_t freq[256] = {0};
    for (unsigned char c : s) ++freq[c];
    double e = 0.0, len = static_cast<double>(s.size());
    for (size_t f : freq) {
        if (!f) continue;
        double p = static_cast<double>(f) / len;
        e -= p * std::log2(p);
    }
    return e;
}

// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant).
inline int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

// Parse X.509 UTCTime/GeneralizedTime in the forms Wireshark displays
// ("YY-MM-DD HH:MM:SS (UTC)", "YYYY-MM-DD HH:MM:SS (UTC)") or raw DER text
// ("YYMMDDHHMMSSZ", "YYYYMMDDHHMMSSZ"). Returns false when unparseable.
inline bool parse_x509_time(const std::string &s, int64_t &epoch) {
    auto digits = [&](size_t pos, size_t count, int &out) {
        if (pos + count > s.size()) return false;
        int v = 0;
        for (size_t i = 0; i < count; ++i) {
            char c = s[pos + i];
            if (c < '0' || c > '9') return false;
            v = v * 10 + (c - '0');
        }
        out = v;
        return true;
    };
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0;
    bool two_digit_year = false;
    if (s.size() >= 19 && s[4] == '-' && digits(0, 4, y) && digits(5, 2, mo) && s[7] == '-' && digits(8, 2, d)
        && (s[10] == ' ' || s[10] == 'T') && digits(11, 2, h) && s[13] == ':' && digits(14, 2, mi) && s[16] == ':'
        && digits(17, 2, se)) {
    } else if (s.size() >= 17 && s[2] == '-' && digits(0, 2, y) && digits(3, 2, mo) && s[5] == '-' && digits(6, 2, d)
               && (s[8] == ' ' || s[8] == 'T') && digits(9, 2, h) && s[11] == ':' && digits(12, 2, mi) && s[14] == ':'
               && digits(15, 2, se)) {
        two_digit_year = true;
    } else if (s.size() >= 15 && s[14] == 'Z' && digits(0, 4, y) && digits(4, 2, mo) && digits(6, 2, d)
               && digits(8, 2, h) && digits(10, 2, mi) && digits(12, 2, se)) {
    } else if (s.size() >= 13 && s[12] == 'Z' && digits(0, 2, y) && digits(2, 2, mo) && digits(4, 2, d)
               && digits(6, 2, h) && digits(8, 2, mi) && digits(10, 2, se)) {
        two_digit_year = true;
    } else {
        return false;
    }
    if (two_digit_year) y = y >= 50 ? 1900 + y : 2000 + y; // RFC 5280 4.1.2.5.1
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) return false;
    epoch = days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d)) * 86400 + h * 3600 + mi * 60 + se;
    return true;
}

inline std::string iso_utc(double epoch) {
    int64_t t = static_cast<int64_t>(std::floor(epoch));
    int64_t days = t >= 0 ? t / 86400 : (t - 86399) / 86400;
    int64_t secs = t - days * 86400;
    // civil_from_days
    int64_t z = days + 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t y = static_cast<int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned d = doy - (153 * mp + 2) / 5 + 1;
    const unsigned m = mp < 10 ? mp + 3 : mp - 9;
    y += m <= 2;
    return fmt("%04lld-%02u-%02u %02lld:%02lld:%02lld UTC", static_cast<long long>(y), m, d,
               static_cast<long long>(secs / 3600), static_cast<long long>((secs / 60) % 60),
               static_cast<long long>(secs % 60));
}

// Classify a TLS cipher suite by its IANA name. Returns 0 when not weak.
inline int cipher_weakness(const std::string &name, std::string &why) {
    const std::string n = upper(name);
    if (contains(n, "_NULL_") || contains(n, "WITH_NULL")) { why = "NULL encryption"; return SEV_ERROR; }
    if (contains(n, "EXPORT")) { why = "EXPORT-grade"; return SEV_ERROR; }
    if (contains(n, "_ANON_")) { why = "anonymous key exchange"; return SEV_ERROR; }
    if (contains(n, "RC4")) { why = "RC4"; return SEV_ERROR; }
    if ((contains(n, "_DES_") || contains(n, "DES40") || contains(n, "DES_CBC_")) && !contains(n, "3DES")) {
        why = "single DES";
        return SEV_ERROR;
    }
    if (contains(n, "3DES") || contains(n, "IDEA")) { why = "64-bit block cipher (SWEET32)"; return SEV_WARN; }
    if (contains(n, "_MD5")) { why = "MD5 MAC"; return SEV_WARN; }
    if (contains(n, "TLS_RSA_WITH")) { why = "static RSA key exchange (no forward secrecy)"; return SEV_NOTE; }
    if (contains(n, "_CBC_")) { why = "CBC mode"; return SEV_INFO; }
    return 0;
}

inline std::string slug(const std::string &s) {
    std::string out;
    bool dash = false;
    for (char ch : lower(s)) {
        bool alnum = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
        if (alnum) {
            out += ch;
            dash = false;
        } else if (!dash && !out.empty()) {
            out += '_';
            dash = true;
        }
    }
    while (!out.empty() && out.back() == '_') out.pop_back();
    return out;
}

inline std::string quic_version_name(uint32_t v) {
    if (v == 0) return "Version Negotiation";
    if (v == 0x00000001) return "QUIC v1";
    if (v == 0x6b3343cf) return "QUIC v2";
    if (v >= 0xff000000 && v <= 0xff0000ff) return fmt("draft-%u", v - 0xff000000);
    if ((v & 0x0f0f0f0f) == 0x0a0a0a0a) return "GREASE " + hex(v, 8);
    if ((v >> 24) == 0x51) return "Google QUIC " + hex(v, 8);
    if ((v >> 24) == 0x54) return "Google T-QUIC " + hex(v, 8);
    if ((v >> 8) == 0xfaceb0) return "mvfst " + hex(v, 8);
    return "unknown " + hex(v, 8);
}

inline const char *tls_version_name(unsigned v) {
    switch (v) {
    case 0x0002: return "SSL 2.0";
    case 0x0300: return "SSL 3.0";
    case 0x0301: return "TLS 1.0";
    case 0x0302: return "TLS 1.1";
    case 0x0303: return "TLS 1.2";
    case 0x0304: return "TLS 1.3";
    case 0xfeff: return "DTLS 1.0";
    case 0xfefd: return "DTLS 1.2";
    case 0xfefc: return "DTLS 1.3";
    default: return nullptr;
    }
}

inline const char *tls_alert_name(unsigned a) {
    static const std::map<unsigned, const char *> names = {
        {10, "unexpected_message"}, {20, "bad_record_mac"}, {21, "decryption_failed"}, {22, "record_overflow"},
        {40, "handshake_failure"}, {41, "no_certificate"}, {42, "bad_certificate"}, {43, "unsupported_certificate"},
        {44, "certificate_revoked"}, {45, "certificate_expired"}, {46, "certificate_unknown"},
        {47, "illegal_parameter"}, {48, "unknown_ca"}, {49, "access_denied"}, {70, "protocol_version"},
        {71, "insufficient_security"}, {80, "internal_error"}, {86, "inappropriate_fallback"},
        {90, "user_canceled"}, {109, "missing_extension"}, {110, "unsupported_extension"},
        {112, "unrecognized_name"}, {116, "certificate_required"}, {120, "no_application_protocol"}};
    auto it = names.find(a);
    return it == names.end() ? nullptr : it->second;
}

// ---------------------------------------------------------------- JSON writer
inline void json_escape_into(std::string &out, const std::string &s) {
    out += '"';
    const std::string safe = clean(s, s.size() + 4); // valid UTF-8, no control bytes
    for (char ch : safe) {
        switch (ch) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        default: out += ch;
        }
    }
    out += '"';
}

inline std::string json_str(const std::string &s) {
    std::string out;
    json_escape_into(out, s);
    return out;
}

// Streaming JSON builder that tracks commas.
class JsonWriter {
public:
    JsonWriter &begin_object() { value_prefix(); out_ += '{'; first_.push_back(true); return *this; }
    JsonWriter &end_object() { out_ += '}'; first_.pop_back(); return *this; }
    JsonWriter &begin_array() { value_prefix(); out_ += '['; first_.push_back(true); return *this; }
    JsonWriter &end_array() { out_ += ']'; first_.pop_back(); return *this; }
    JsonWriter &key(const std::string &k) {
        comma();
        json_escape_into(out_, k);
        out_ += ':';
        after_key_ = true;
        return *this;
    }
    JsonWriter &str(const std::string &v) { value_prefix(); json_escape_into(out_, v); return *this; }
    JsonWriter &num(double v) {
        value_prefix();
        if (!std::isfinite(v)) out_ += "null";
        else if (std::floor(v) == v && std::fabs(v) < 9007199254740992.0) out_ += fmt("%lld", static_cast<long long>(v));
        else out_ += fmt("%.6g", v);
        return *this;
    }
    JsonWriter &boolean(bool v) { value_prefix(); out_ += v ? "true" : "false"; return *this; }
    JsonWriter &null() { value_prefix(); out_ += "null"; return *this; }
    const std::string &str() const { return out_; }

private:
    void comma() {
        if (!first_.empty()) {
            if (!first_.back()) out_ += ',';
            first_.back() = false;
        }
    }
    void value_prefix() {
        if (after_key_) { after_key_ = false; return; }
        comma();
    }
    std::string out_;
    std::vector<bool> first_;
    bool after_key_ = false;
};

} // namespace aiinspector
