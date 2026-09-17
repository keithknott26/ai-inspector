// SPDX-License-Identifier: GPL-2.0-or-later
#include "chat_view.h"

#include <QDateTime>
#include <QEvent>
#include <QHostAddress>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QScrollBar>
#include <QTextDocument>
#include <QUrl>
#include <QUrlQuery>

namespace aiinspector {

namespace {
QString hexColor(const QColor &c) { return c.name(QColor::HexRgb); }

const QRegularExpression &chartBlockRe() {
    static const QRegularExpression re(QStringLiteral("```chart[ \\t]*\\n([\\s\\S]*?)```"));
    return re;
}
} // namespace

ChatView::ChatView(QWidget *parent) : QTextBrowser(parent) {
    setOpenLinks(false);
    setOpenExternalLinks(false);
    setReadOnly(true);
    setFrameShape(QFrame::NoFrame);
    document()->setDocumentMargin(10);
    renderTimer_.setSingleShot(true);
    renderTimer_.setInterval(90);
    connect(&renderTimer_, &QTimer::timeout, this, &ChatView::render);
    connect(this, &QTextBrowser::anchorClicked, this, [this](const QUrl &url) {
        if (url.scheme() == QLatin1String("wsfilter")) {
            const QString f = QString::fromUtf8(QByteArray::fromHex(url.path().toLatin1()));
            QString reason;
            if (validator_ && !validator_(f, &reason)) emit filterRejected(f, reason);
            else if (validator_ || looksLikeFilter(f)) emit applyFilterRequested(f);
        } else if (url.scheme() == QLatin1String("wsframe")) {
            bool ok = false;
            const uint n = QUrlQuery(url).queryItemValue(QStringLiteral("n")).toUInt(&ok);
            if (ok && n > 0) emit goToFrameRequested(n);
        }
        // Any other link (http, file, ...) is deliberately ignored.
    });
}

QVariant ChatView::loadResource(int type, const QUrl &name) {
    if (type == QTextDocument::ImageResource && name.scheme() == QLatin1String("wschart")) {
        auto it = charts_.constFind(name.toString());
        if (it != charts_.constEnd()) return it.value();
    }
    return QVariant(); // never fetch external or local resources
}

void ChatView::changeEvent(QEvent *event) {
    if (event->type() == QEvent::PaletteChange) {
        charts_.clear();
        render();
    }
    QTextBrowser::changeEvent(event);
}

void ChatView::addUser(const QString &text) {
    messages_.push_back({Message::User, text, false});
    render();
}

void ChatView::beginAssistant() {
    messages_.push_back({Message::Assistant, QString(), true});
    render();
}

void ChatView::appendAssistant(const QString &delta) {
    if (messages_.isEmpty() || messages_.last().role != Message::Assistant || !messages_.last().streaming) beginAssistant();
    messages_.last().text += delta;
    scheduleRender();
}

void ChatView::finishAssistant(const QString &fullText) {
    if (messages_.isEmpty() || messages_.last().role != Message::Assistant || !messages_.last().streaming)
        messages_.push_back({Message::Assistant, QString(), true});
    // The transform (restoring local addresses) is applied once, with the
    // mapping that was valid for this answer.
    messages_.last().text = transform_ ? transform_(fullText) : fullText;
    messages_.last().streaming = false;
    renderTimer_.stop();
    render();
}

void ChatView::addError(const QString &text) {
    if (!messages_.isEmpty() && messages_.last().streaming) {
        messages_.last().streaming = false;
        if (messages_.last().text.trimmed().isEmpty()) messages_.removeLast();
    }
    messages_.push_back({Message::Error, text, false});
    renderTimer_.stop();
    render();
}

void ChatView::clearConversation() {
    messages_.clear();
    charts_.clear();
    render();
}

QString ChatView::plainTranscript() const {
    QStringList out;
    for (const auto &m : messages_) {
        const QString who = m.role == Message::User ? QStringLiteral("You") : m.role == Message::Error ? QStringLiteral("Error")
                                                                                                        : QStringLiteral("Assistant");
        out << QStringLiteral("== %1 ==\n%2\n").arg(who, m.text);
    }
    return out.join(QLatin1Char('\n'));
}

bool ChatView::looksLikeFilter(const QString &s) {
    if (s.size() < 3 || s.size() > 300) return false;
    static const QRegularExpression field(QStringLiteral("^[!( ]*[a-z][a-z0-9_-]*(\\.[A-Za-z0-9_-]+)*"));
    static const QRegularExpression dotted(QStringLiteral("\\b[a-z][a-z0-9_-]*\\.[a-z0-9_.-]+\\b"));
    static const QRegularExpression allowed(QStringLiteral("^[A-Za-z0-9_.:=!<>&|()\"' {}\\[\\]/~,+*%^$-]+$"));
    if (!allowed.match(s).hasMatch() || !field.match(s).hasMatch()) return false;
    // Must reference a dotted field or be a bare, known-style protocol name.
    if (dotted.match(s).hasMatch()) return true;
    static const QRegularExpression bare(QStringLiteral("^[a-z][a-z0-9_]{1,15}$"));
    static const QStringList protos = {QStringLiteral("tcp"), QStringLiteral("udp"), QStringLiteral("dns"), QStringLiteral("http"),
        QStringLiteral("tls"), QStringLiteral("quic"), QStringLiteral("arp"), QStringLiteral("icmp"), QStringLiteral("dhcp"),
        QStringLiteral("smb"), QStringLiteral("smb2"), QStringLiteral("ssh"), QStringLiteral("telnet"), QStringLiteral("ftp"),
        QStringLiteral("btle"), QStringLiteral("btatt"), QStringLiteral("btsmp"), QStringLiteral("ai_inspector"), QStringLiteral("http2"),
        QStringLiteral("kerberos"), QStringLiteral("ntp"), QStringLiteral("snmp"), QStringLiteral("mqtt"), QStringLiteral("sip")};
    return bare.match(s).hasMatch() && protos.contains(s);
}

QString ChatView::toDisplayFilter(const QString &raw, const FilterValidator &validator) {
    const QString c = raw.trimmed();
    if (c.isEmpty() || c.size() > 300) return {};
    auto valid = [&](const QString &f) { return validator ? validator(f, nullptr) : looksLikeFilter(f); };
    // Addresses become address filters.
    QHostAddress addr;
    if (addr.setAddress(c))
        return (addr.protocol() == QAbstractSocket::IPv6Protocol ? QStringLiteral("ipv6.addr == ") : QStringLiteral("ip.addr == ")) + addr.toString();
    static const QRegularExpression mac(QStringLiteral("^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$"));
    if (mac.match(c).hasMatch()) return QStringLiteral("eth.addr == ") + QString(c).replace(QLatin1Char('-'), QLatin1Char(':'));
    // A real filter (or field existence test) is used as-is.
    if (validator ? validator(c, nullptr) : looksLikeFilter(c)) {
        // Without the compiler, don't mistake host names for fields.
        static const QRegularExpression hostish(QStringLiteral("^[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,24}$"));
        if (validator || !hostish.match(c).hasMatch() || c.startsWith(QStringLiteral("ai_inspector")))
            return c;
    }
    // Host names match HTTP Host, TLS SNI and DNS query names.
    static const QRegularExpression host(QStringLiteral("^(?=.{3,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"));
    if (host.match(c).hasMatch()) {
        const QString q = QStringLiteral("\"%1\"").arg(c.toLower());
        const QString f = QStringLiteral("http.host == %1 || tls.handshake.extensions_server_name == %1 || dns.qry.name == %1").arg(q);
        if (!validator || valid(f)) return f;
    }
    return {};
}

QStringList ChatView::extractFilters(const QString &markdown) {
    QStringList out;
    QString text = markdown;
    text.remove(chartBlockRe());
    static const QRegularExpression code(QStringLiteral("(?<!`)`([^`\\n]+)`(?!`)"));
    auto it = code.globalMatch(text);
    while (it.hasNext()) {
        const QString f = it.next().captured(1).trimmed();
        static const QRegularExpression addrOrHost(QStringLiteral("^[A-Za-z0-9:.%\\-]{3,253}$"));
        if ((looksLikeFilter(f) || addrOrHost.match(f).hasMatch()) && !out.contains(f)) out << f;
        if (out.size() >= 12) break;
    }
    return out;
}

void ChatView::scheduleRender() {
    if (!renderTimer_.isActive()) renderTimer_.start();
}

// Rendering pipeline for one answer:
//   1. ```chart blocks -> validated ChartSpec -> QImage resource (wschart://...)
//   2. "frame N" mentions -> wsframe: links
//   3. Markdown -> HTML with raw HTML disabled (MarkdownNoHTML)
// Links use private schemes handled in the anchorClicked handler; loadResource()
// refuses everything else, so model output can never load remote content.
QString ChatView::markdownToHtml(QString md, int messageIndex, QStringList *filters) {
    const Theme t = Theme::fromPalette(palette());
    // 1) Charts: replace ```chart blocks with image references rendered natively.
    int chartNo = 0;
    QString rebuilt;
    qsizetype last = 0;
    auto cit = chartBlockRe().globalMatch(md);
    while (cit.hasNext()) {
        const auto m = cit.next();
        rebuilt += md.mid(last, m.capturedStart() - last);
        last = m.capturedEnd();
        ChartSpec spec;
        QString err;
        const QJsonDocument doc = QJsonDocument::fromJson(m.captured(1).toUtf8());
        if (chartNo < 3 && doc.isObject() && parseChartSpec(doc.object(), spec, &err)) {
            const QString key = QStringLiteral("wschart://m%1/c%2/%3").arg(messageIndex).arg(chartNo).arg(t.dark ? 1 : 0);
            if (!charts_.contains(key)) {
                const int w = std::clamp(viewport()->width() - 60, 320, 760);
                const int h = spec.type == ChartSpec::HBar ? std::clamp(70 + static_cast<int>(spec.labels.size()) * 26, 160, 520)
                                                           : (spec.type == ChartSpec::Donut ? 220 : 260);
                charts_.insert(key, renderChart(spec, QSize(w, h), t, std::max<qreal>(2.0, devicePixelRatioF())));
            }
            const QImage &img = charts_[key];
            rebuilt += QStringLiteral("\n\n![chart](%1)\n\n").arg(key);
            Q_UNUSED(img);
            ++chartNo;
        } else {
            rebuilt += QStringLiteral("\n\n_(chart omitted: %1)_\n\n").arg(err.isEmpty() ? QStringLiteral("invalid data") : err);
        }
    }
    rebuilt += md.mid(last);
    // Unterminated chart block while streaming: hide the raw JSON until it completes.
    const qsizetype open = rebuilt.lastIndexOf(QStringLiteral("```chart"));
    if (open >= 0) rebuilt = rebuilt.left(open) + QStringLiteral("\n\n_Preparing chart..._\n");

    if (filters) *filters = extractFilters(rebuilt);

    // 2) Frame references -> links. Done in Markdown so they survive rendering.
    static const QRegularExpression frameRe(QStringLiteral("(?<![\\w/#\\[`])(?:[Ff]rames?|[Pp]ackets?)\\s+#?(\\d{1,9})\\b"));
    QString linked;
    last = 0;
    auto fit = frameRe.globalMatch(rebuilt);
    while (fit.hasNext()) {
        const auto m = fit.next();
        linked += rebuilt.mid(last, m.capturedStart() - last);
        linked += QStringLiteral("[%1](wsframe:go?n=%2)").arg(m.captured(0), m.captured(1));
        last = m.capturedEnd();
    }
    linked += rebuilt.mid(last);

    QTextDocument doc;
    doc.setMarkdown(linked, QTextDocument::MarkdownFeatures(QTextDocument::MarkdownDialectGitHub | QTextDocument::MarkdownNoHTML));
    QString html = doc.toHtml();
    const qsizetype b = html.indexOf(QStringLiteral("<body"));
    const qsizetype bs = b >= 0 ? html.indexOf(QLatin1Char('>'), b) : -1;
    const qsizetype be = html.lastIndexOf(QStringLiteral("</body>"));
    if (bs >= 0 && be > bs) html = html.mid(bs + 1, be - bs - 1);
    // Restyle inline code (filters) for readability.
    html.replace(QStringLiteral("font-family:'monospace'"),
                 QStringLiteral("font-family:'Menlo','Consolas','monospace'; background-color:%1; color:%2")
                     .arg(hexColor(t.grid), hexColor(t.text)));
    return html;
}

QString ChatView::renderMessage(int index, const Message &m, const Theme &t) {
    QString body;
    QString header;
    QColor bg = t.card, border = t.cardBorder, accent = t.accent;
    if (m.role == Message::User) {
        header = QStringLiteral("You");
        accent = t.subtext;
        bg = t.dark ? t.window.lighter(135) : QColor(0xee, 0xf3, 0xff);
        body = m.text.toHtmlEscaped().replace(QLatin1Char('\n'), QStringLiteral("<br>"));
    } else if (m.role == Message::Error) {
        header = QStringLiteral("Problem");
        accent = t.error;
        bg = t.dark ? QColor(0x3a, 0x22, 0x24) : QColor(0xfd, 0xec, 0xec);
        body = m.text.toHtmlEscaped().replace(QLatin1Char('\n'), QStringLiteral("<br>"));
    } else {
        header = m.streaming ? QStringLiteral("AI Inspector  •  writing...") : QStringLiteral("AI Inspector");
        QStringList filters;
        body = m.text.isEmpty() ? QStringLiteral("<span style='color:%1'>Thinking...</span>").arg(hexColor(t.subtext))
                                : markdownToHtml(m.streaming && transform_ ? transform_(m.text) : m.text, index,
                                                 m.streaming ? nullptr : &filters);
        QStringList usable;
        for (const auto &cand : filters) {
            const QString f = toDisplayFilter(cand, validator_);
            if (!f.isEmpty() && !usable.contains(f)) usable << f;
        }
        filters = usable;
        if (!filters.isEmpty()) {
            QString chips;
            for (const auto &f : filters) {
                const QUrl url(QStringLiteral("wsfilter:") + QString::fromLatin1(f.toUtf8().toHex()));
                chips += QStringLiteral("<a href=\"%1\" style=\"text-decoration:none; color:%2\">&#9656;&nbsp;<code>%3</code></a><br>")
                             .arg(url.toString(QUrl::FullyEncoded).toHtmlEscaped(), hexColor(t.accent), f.toHtmlEscaped());
            }
            body += QStringLiteral("<p style='margin-top:10px; color:%1'><b>Suggested filters</b> (click to apply)</p><p>%2</p>")
                        .arg(hexColor(t.subtext), chips);
        }
        body += QStringLiteral("<p style='color:%1; font-size:small'>AI output can be wrong. Verify against the packets.</p>")
                    .arg(hexColor(t.subtext));
    }
    return QStringLiteral(
               "<table width='100%' cellspacing='0' cellpadding='0' style='margin-bottom:10px'><tr>"
               "<td width='4' style='background-color:%1'></td>"
               "<td style='background-color:%2; border:1px solid %3; padding:10px 12px'>"
               "<p style='margin:0 0 6px 0; color:%4; font-weight:600'>%5</p>%6</td></tr></table>")
        .arg(hexColor(accent), hexColor(bg), hexColor(border), hexColor(accent), header, body);
}

void ChatView::render() {
    const QScrollBar *sb = verticalScrollBar();
    const bool atBottom = sb->value() >= sb->maximum() - 24;
    const Theme t = Theme::fromPalette(palette());
    QString html = QStringLiteral("<html><body style='color:%1'>").arg(hexColor(t.text));
    if (messages_.isEmpty()) {
        html += QStringLiteral(
                    "<div align='center' style='margin-top:40px'><p style='font-size:large; font-weight:600'>Ask about this capture</p>"
                    "<p style='color:%1'>Run a triage, explain the selected packet, or type a question.<br>"
                    "Answers include clickable filters, frame links and charts.</p></div>")
                    .arg(hexColor(t.subtext));
    }
    for (int i = 0; i < messages_.size(); ++i) html += renderMessage(i, messages_[i], t);
    html += QStringLiteral("</body></html>");
    const int keep = sb->value();
    setHtml(html);
    verticalScrollBar()->setValue(atBottom ? verticalScrollBar()->maximum() : keep);
}

} // namespace aiinspector
