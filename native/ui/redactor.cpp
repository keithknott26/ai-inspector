// SPDX-License-Identifier: GPL-2.0-or-later
#include "redactor.h"

#include <QHostAddress>
#include <QRegularExpression>
#include <QStringList>

#include <algorithm>
#include <functional>

namespace aiinspector {

void Redactor::reset() {
    map_.clear();
    reverse_.clear();
    ip_ = ip6_ = mac_ = 0;
}

QString Redactor::token(const QString &kind, const QString &value, const QString &suffix) {
    const QString key = kind + QLatin1Char('|') + value.toLower();
    auto it = map_.constFind(key);
    if (it != map_.constEnd()) return it.value();
    int n = kind == QLatin1String("mac") ? ++mac_ : kind == QLatin1String("ip6") ? ++ip6_ : ++ip_;
    const QString t = QStringLiteral("%1-%2%3").arg(kind.toUpper()).arg(n).arg(suffix);
    map_.insert(key, t);
    reverse_.insert(QStringLiteral("%1-%2").arg(kind.toUpper()).arg(n), value);
    return t;
}

static bool isPrivateV4(quint32 a) {
    const quint8 o1 = static_cast<quint8>(a >> 24), o2 = static_cast<quint8>(a >> 16);
    return o1 == 10 || o1 == 127 || (o1 == 172 && o2 >= 16 && o2 <= 31) || (o1 == 192 && o2 == 168)
        || (o1 == 169 && o2 == 254) || (o1 == 100 && o2 >= 64 && o2 <= 127);
}

static QString replaceAll(const QString &in, const QRegularExpression &re, const std::function<QString(const QRegularExpressionMatch &)> &fn) {
    QString out;
    out.reserve(in.size());
    qsizetype last = 0;
    auto it = re.globalMatch(in);
    while (it.hasNext()) {
        const auto m = it.next();
        out += in.mid(last, m.capturedStart() - last);
        const QString rep = fn(m);
        out += rep.isNull() ? m.captured() : rep;
        last = m.capturedEnd();
    }
    out += in.mid(last);
    return out;
}

QString Redactor::apply(const QString &text) {
    static const QRegularExpression macRe(
        QStringLiteral("(?<![0-9A-Fa-f:.-])[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f:.-])"));
    static const QRegularExpression v6Re(QStringLiteral("(?<![0-9A-Za-z:.])[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*(?:%[0-9A-Za-z]+)?(?![0-9A-Za-z:])"));
    static const QRegularExpression v4Re(QStringLiteral("(?<![0-9.])(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})(?![0-9]|\\.\\d)"));

    // Resolved OUI names such as "Apple_12:34:56" still identify a device.
    static const QRegularExpression ouiRe(QStringLiteral("\\b[A-Za-z][A-Za-z0-9-]{1,15}_[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\\b"));
    QString s = replaceAll(text, macRe, [this](const QRegularExpressionMatch &m) { return token(QStringLiteral("mac"), m.captured()); });
    s = replaceAll(s, ouiRe, [this](const QRegularExpressionMatch &m) { return token(QStringLiteral("mac"), m.captured()); });
    s = replaceAll(s, v6Re, [this](const QRegularExpressionMatch &m) -> QString {
        QString cand = m.captured();
        while (cand.endsWith(QLatin1Char('.'))) cand.chop(1);
        if (cand.count(QLatin1Char(':')) < 2) return QString();
        QHostAddress addr;
        if (!addr.setAddress(cand.section(QLatin1Char('%'), 0, 0)) || addr.protocol() != QAbstractSocket::IPv6Protocol)
            return QString();
        const QString rest = m.captured().mid(cand.size());
        return token(QStringLiteral("ip6"), addr.toString()) + rest;
    });
    s = replaceAll(s, v4Re, [this](const QRegularExpressionMatch &m) -> QString {
        quint32 v = 0;
        for (int i = 1; i <= 4; ++i) {
            const int o = m.captured(i).toInt();
            if (o > 255) return QString();
            v = (v << 8) | static_cast<quint32>(o);
        }
        return token(QStringLiteral("ip"), m.captured(), isPrivateV4(v) ? QStringLiteral("(private)") : QString());
    });
    return s;
}

QString Redactor::restore(const QString &text) const {
    if (reverse_.isEmpty()) return text;
    static const QRegularExpression re(QStringLiteral("\\b(IP6|IP|MAC)-(\\d+)(?:\\s*\\(private\\))?"));
    QString out;
    qsizetype last = 0;
    auto it = re.globalMatch(text);
    while (it.hasNext()) {
        const auto m = it.next();
        const auto found = reverse_.constFind(m.captured(1) + QLatin1Char('-') + m.captured(2));
        if (found == reverse_.constEnd()) continue;
        out += text.mid(last, m.capturedStart() - last);
        out += found.value();
        last = m.capturedEnd();
    }
    out += text.mid(last);
    return out;
}

bool isSensitiveField(const QString &abbrev) {
    static const QStringList needles = {
        QStringLiteral("passw"), QStringLiteral("authbasic"), QStringLiteral("authorization"), QStringLiteral("cookie"),
        QStringLiteral("community"), QStringLiteral("secret"), QStringLiteral("token"), QStringLiteral("credential"),
        QStringLiteral("private_key"), QStringLiteral("api_key"), QStringLiteral("ntresponse"), QStringLiteral("ftp.request.arg"),
        QStringLiteral("telnet.data"), QStringLiteral("ldap.simple"), QStringLiteral("pop.request.parameter"),
        QStringLiteral("imap.request"), QStringLiteral("btsmp.long_term_key"), QStringLiteral("btsmp.ltk"),
        QStringLiteral("psk"), QStringLiteral("wlan.rsn.ie.pmkid"), QStringLiteral("smtp.auth")};
    const QString a = abbrev.toLower();
    for (const auto &n : needles)
        if (a.contains(n)) return true;
    return false;
}

QString scrubSecrets(const QString &text, const QStringList &secretValues) {
    QString s = text;
    QStringList values = secretValues;
    // Longest first so a value that contains another is removed whole.
    std::sort(values.begin(), values.end(), [](const QString &a, const QString &b) { return a.size() > b.size(); });
    for (QString v : values) {
        v = v.trimmed();
        if (v.size() < 3) continue;
        s.replace(v, QStringLiteral("[redacted]"), Qt::CaseSensitive);
    }
    static const QRegularExpression param(QStringLiteral(
        "(?i)\\b((?:pass(?:word|wd)?|pwd|secret|token|access_token|api_?key|apikey|auth|session(?:id)?|sid|key)=)[^&\\s\"']+"));
    s.replace(param, QStringLiteral("\\1[redacted]"));
    static const QRegularExpression authz(QStringLiteral("(?i)\\b(authorization:\\s*(?:basic|bearer|digest|ntlm|negotiate)?\\s*)[^\\s\"\\\\]+"));
    s.replace(authz, QStringLiteral("\\1[redacted]"));
    return s;
}

} // namespace aiinspector
