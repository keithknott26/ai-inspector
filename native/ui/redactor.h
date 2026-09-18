// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <QHash>
#include <QString>
#include <QStringList>

namespace aiinspector {

// Replaces IPv4, IPv6 and MAC addresses with stable placeholders
// (IP-1(private), IP6-2, MAC-3). One instance keeps a consistent mapping,
// so follow-up questions in the same conversation reuse the same tokens.
class Redactor {
public:
    QString apply(const QString &text);
    int mappedCount() const { return static_cast<int>(map_.size()); }
    // Replaces placeholders (IP-3, IP-3(private), IP6-1, MAC-2) with the real
    // values again. Used only for local display; never for outgoing requests.
    QString restore(const QString &text) const;
    void reset();

private:
    QString token(const QString &kind, const QString &value, const QString &suffix = QString());
    QHash<QString, QString> map_;
    QHash<QString, QString> reverse_; // "IP-3" -> "10.0.0.5"
    int ip_ = 0, ip6_ = 0, mac_ = 0;
};

// True for field abbreviations that commonly carry secrets; their values are
// replaced before any packet detail leaves the machine.
bool isSensitiveField(const QString &abbrev);

// Removes credential-like material regardless of the address-redaction
// setting: known secret values collected from the packet, URL/query
// parameters such as password=..., and Authorization header values.
// JSON objects/arrays are scrubbed by string value to preserve their encoding.
QString scrubSecrets(const QString &text, const QStringList &secretValues = QStringList());

} // namespace aiinspector
