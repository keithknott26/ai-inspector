// SPDX-License-Identifier: GPL-2.0-or-later
// Unit tests for the dependency-free engine helpers (ai_inspector_util.hpp).
#include "ai_inspector_util.hpp"

#include <cstdio>
#include <cstring>

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { ++failures; std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

using namespace aiinspector;

int main() {
    // clean(): control bytes, invalid UTF-8, truncation on a code point boundary
    CHECK(clean("a\x01" "b\x7f") == "a?b?");
    CHECK(clean("ok \xff\xfe") == "ok ??");
    CHECK(clean("\xc3\xa9t\xc3\xa9") == "\xc3\xa9t\xc3\xa9");
    CHECK(clean(std::string(300, 'x'), 10) == "xxxxxxx...");
    std::string multi;
    for (int i = 0; i < 20; ++i) multi += "\xe2\x82\xac"; // euro signs
    std::string cut = clean(multi, 10);
    CHECK(cut.size() <= 10 && cut.substr(cut.size() - 3) == "...");
    CHECK(clean(cut, 100) == cut); // still valid UTF-8

    CHECK(filter_quote("a\"b\\c\n") == "\"a\\\"b\\\\c\"");
    CHECK(hex(5) == "0x05" && hex(0x6b3343cf, 8) == "0x6b3343cf");
    CHECK(std::fabs(entropy("abcd") - 2.0) < 1e-9 && entropy("aaaa") == 0.0 && entropy("") == 0.0);
    CHECK(slug("64-bit block cipher (SWEET32)") == "64_bit_block_cipher_sweet32");

    int64_t t = 0;
    CHECK(parse_x509_time("24-01-01 00:00:00 (UTC)", t) && t == 1704067200);
    CHECK(parse_x509_time("2024-01-01 00:00:00 (UTC)", t) && t == 1704067200);
    CHECK(parse_x509_time("500101000000Z", t) && t == -631152000);
    CHECK(parse_x509_time("491231235959Z", t) && t == 2524607999);
    CHECK(parse_x509_time("20380119031408Z", t) && t == 2147483648LL);
    CHECK(!parse_x509_time("2024-13-01 00:00:00", t));
    CHECK(!parse_x509_time("garbage", t));
    CHECK(!parse_x509_time("", t));
    CHECK(iso_utc(1704067200) == "2024-01-01 00:00:00 UTC");
    CHECK(iso_utc(-1) == "1969-12-31 23:59:59 UTC");
    CHECK(iso_utc(951782400) == "2000-02-29 00:00:00 UTC");

    std::string why;
    CHECK(cipher_weakness("Cipher Suite: TLS_RSA_WITH_RC4_128_SHA (0x0005)", why) == SEV_ERROR && why == "RC4");
    CHECK(cipher_weakness("TLS_RSA_WITH_NULL_SHA", why) == SEV_ERROR);
    CHECK(cipher_weakness("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", why) == SEV_ERROR);
    CHECK(cipher_weakness("TLS_DH_anon_WITH_AES_128_CBC_SHA", why) == SEV_ERROR);
    CHECK(cipher_weakness("TLS_RSA_WITH_DES_CBC_SHA", why) == SEV_ERROR && why == "single DES");
    CHECK(cipher_weakness("TLS_RSA_WITH_3DES_EDE_CBC_SHA", why) == SEV_WARN);
    CHECK(cipher_weakness("TLS_RSA_WITH_AES_128_GCM_SHA256", why) == SEV_NOTE);
    CHECK(cipher_weakness("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", why) == SEV_INFO);
    CHECK(cipher_weakness("TLS_AES_128_GCM_SHA256", why) == 0);
    CHECK(cipher_weakness("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", why) == 0);

    CHECK(quic_version_name(1) == "QUIC v1" && quic_version_name(0x6b3343cf) == "QUIC v2");
    CHECK(quic_version_name(0xff00001d) == "draft-29");
    CHECK(quic_version_name(0x1a2a3a4a).rfind("GREASE", 0) == 0);
    CHECK(quic_version_name(0x51303433).rfind("Google QUIC", 0) == 0);
    CHECK(quic_version_name(0xfaceb002).rfind("mvfst", 0) == 0);
    CHECK(quic_version_name(0x12345678).rfind("unknown", 0) == 0);
    CHECK(std::strcmp(tls_version_name(0x0304), "TLS 1.3") == 0 && tls_version_name(0x9999) == nullptr);
    CHECK(std::strcmp(tls_alert_name(48), "unknown_ca") == 0 && tls_alert_name(250) == nullptr);

    JsonWriter w;
    w.begin_object().key("s").str("q\"\\\n\xff").key("n").num(-1.5).key("i").num(42).key("a").begin_array();
    w.boolean(true).null().begin_object().end_object().end_array().key("e").begin_array().end_array().end_object();
    CHECK(w.str() == "{\"s\":\"q\\\"\\\\??\",\"n\":-1.5,\"i\":42,\"a\":[true,null,{}],\"e\":[]}");

    std::printf("unit_util: %s (%d failures)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
