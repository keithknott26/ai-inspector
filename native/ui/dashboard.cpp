// SPDX-License-Identifier: GPL-2.0-or-later
#include "dashboard.h"

#include <QDateTime>
#include <QGridLayout>
#include <QJsonArray>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QResizeEvent>
#include <QScrollArea>
#include <QStackedLayout>
#include <QVBoxLayout>

#include <cmath>

namespace aiinspector {

namespace {
qint64 num(const QJsonValue &v) { return v.toVariant().toLongLong(); }

QString humanDuration(double s) {
    if (s < 1) return QStringLiteral("%1 ms").arg(qRound(s * 1000));
    if (s < 120) return QStringLiteral("%1 s").arg(QString::number(s, 'f', s < 10 ? 1 : 0));
    if (s < 7200) return QStringLiteral("%1 min").arg(QString::number(s / 60, 'f', 1));
    return QStringLiteral("%1 h").arg(QString::number(s / 3600, 'f', 1));
}

} // namespace

// ---------------------------------------------------------------- KPI card
KpiCard::KpiCard(const QString &caption, int level, QWidget *parent) : QWidget(parent), caption_(caption), value_(QStringLiteral("0")), level_(level) {
    setAttribute(Qt::WA_Hover);
    if (level_ > 0) setCursor(Qt::PointingHandCursor);
}

void KpiCard::setValue(const QString &value, const QString &detail) {
    value_ = value;
    detail_ = detail;
    setToolTip(detail.isEmpty() ? caption_ : caption_ + QStringLiteral(": ") + detail);
    update();
}

QSize KpiCard::sizeHint() const { return QSize(130, 74); }
QSize KpiCard::minimumSizeHint() const { return QSize(96, 68); }

void KpiCard::mousePressEvent(QMouseEvent *e) {
    if (e->button() == Qt::LeftButton) emit clicked();
}

void KpiCard::paintEvent(QPaintEvent *) {
    const Theme t = Theme::fromPalette(palette());
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const QRectF r = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
    QPainterPath card;
    card.addRoundedRect(r, 10, 10);
    QColor bg = t.card;
    if (underMouse() && level_ > 0) bg = t.dark ? bg.lighter(115) : bg.darker(103);
    p.fillPath(card, bg);
    p.setPen(QPen(t.cardBorder, 1));
    p.drawPath(card);
    const QColor accent = level_ > 0 ? t.severity(level_) : t.accent;
    p.save();
    p.setClipPath(card);
    p.fillRect(QRectF(r.left(), r.top(), 4, r.height()), accent);
    p.restore();

    QFont capF = font();
    capF.setPointSizeF(font().pointSizeF() * 0.85);
    p.setFont(capF);
    p.setPen(t.subtext);
    p.drawText(r.adjusted(14, 9, -8, 0), Qt::AlignLeft | Qt::AlignTop, caption_.toUpper());
    QFont valF = font();
    valF.setBold(true);
    valF.setPointSizeF(font().pointSizeF() * 1.75);
    p.setFont(valF);
    const bool zero = value_ == QLatin1String("0");
    p.setPen(level_ > 0 && !zero ? accent : t.text);
    p.drawText(r.adjusted(14, 0, -8, -8), Qt::AlignLeft | Qt::AlignBottom,
               QFontMetricsF(valF).elidedText(value_, Qt::ElideRight, r.width() - 22));
}

// ---------------------------------------------------------------- dashboard
Dashboard::Dashboard(QWidget *parent) : QWidget(parent) {
    setObjectName(QStringLiteral("dashboard"));
    stack_ = new QStackedLayout(this);

    empty_ = new QLabel(this);
    empty_->setObjectName(QStringLiteral("dashboardEmpty"));
    empty_->setAlignment(Qt::AlignCenter);
    empty_->setWordWrap(true);
    empty_->setTextFormat(Qt::RichText);
    empty_->setText(QStringLiteral("<p style='font-size:15pt; font-weight:600'>No capture analyzed yet</p>"
                                   "<p>Open a capture file (or reload it) to see findings, trends and charts.</p>"));
    stack_->addWidget(empty_);

    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    content_ = new QWidget(scroll);
    auto *v = new QVBoxLayout(content_);
    v->setContentsMargins(4, 4, 4, 4);
    v->setSpacing(10);
    kpiGrid_ = new QGridLayout;
    kpiGrid_->setSpacing(8);
    v->addLayout(kpiGrid_);
    chartGrid_ = new QGridLayout;
    chartGrid_->setSpacing(10);
    v->addLayout(chartGrid_);
    v->addStretch(1);
    scroll->setWidget(content_);
    stack_->addWidget(scroll);

    const QList<QPair<QString, int>> kpis = {{QStringLiteral("Frames"), 0}, {QStringLiteral("Duration"), 0},
        {QStringLiteral("Errors"), 4}, {QStringLiteral("Warnings"), 3}, {QStringLiteral("Notes"), 2}, {QStringLiteral("Finding types"), 0}};
    for (const auto &k : kpis) {
        auto *card = new KpiCard(k.first, k.second, content_);
        card->setObjectName(QStringLiteral("kpi_") + k.first.toLower().replace(QLatin1Char(' '), QLatin1Char('_')));
        if (k.second > 0) connect(card, &KpiCard::clicked, this, [this, lvl = k.second] { emit severityClicked(lvl); });
        kpis_ << card;
    }
    const QStringList names = {QStringLiteral("chartSeverity"), QStringLiteral("chartTimeline"), QStringLiteral("chartCategories"),
                               QStringLiteral("chartTraffic"), QStringLiteral("chartHosts"), QStringLiteral("chartProtocols"),
                               QStringLiteral("chartTls")};
    for (const auto &n : names) {
        auto *c = new ChartWidget(content_);
        c->setObjectName(n);
        charts_ << c;
    }
    connect(chart(QStringLiteral("chartSeverity")), &ChartWidget::itemClicked, this, [this](int i) {
        const auto &keys = chart(QStringLiteral("chartSeverity"))->spec().sliceKeys;
        if (i >= 0 && i < keys.size()) emit severityClicked(keys[i].toInt());
    });
    connect(chart(QStringLiteral("chartCategories")), &ChartWidget::itemClicked, this, [this](int i) {
        const auto &labels = chart(QStringLiteral("chartCategories"))->spec().labels;
        if (i >= 0 && i < labels.size()) emit categoryClicked(labels[i].toLower());
    });
    connect(chart(QStringLiteral("chartHosts")), &ChartWidget::itemClicked, this, [this](int i) {
        const auto &labels = chart(QStringLiteral("chartHosts"))->spec().labels;
        if (i >= 0 && i < labels.size()) emit hostClicked(labels[i]);
    });
    connect(chart(QStringLiteral("chartProtocols")), &ChartWidget::itemClicked, this, [this](int i) {
        const auto &labels = chart(QStringLiteral("chartProtocols"))->spec().labels;
        if (i >= 0 && i < labels.size()) emit protocolClicked(labels[i]);
    });
    relayout();
}

ChartWidget *Dashboard::chart(const QString &name) const {
    for (auto *c : charts_)
        if (c->objectName() == name) return c;
    return nullptr;
}

int Dashboard::chartCount() const {
    int n = 0;
    for (auto *c : charts_)
        if (c->isVisible() || !c->isHidden()) n += c->spec().labels.isEmpty() ? 0 : 1;
    return n;
}

void Dashboard::resizeEvent(QResizeEvent *e) {
    QWidget::resizeEvent(e);
    relayout();
}

void Dashboard::relayout() {
    const int w = width();
    const int kpiCols = w >= 780 ? 6 : (w >= 420 ? 3 : 2);
    const int chartCols = w >= 820 ? 2 : 1;
    if (kpiCols * 10 + chartCols == columns_) return;
    columns_ = kpiCols * 10 + chartCols;
    for (auto *k : kpis_) kpiGrid_->removeWidget(k);
    for (int i = 0; i < kpis_.size(); ++i) kpiGrid_->addWidget(kpis_[i], i / kpiCols, i % kpiCols);
    for (auto *c : charts_) chartGrid_->removeWidget(c);
    int slot = 0;
    for (auto *c : charts_) {
        if (c->isHidden()) continue;
        // The timeline and traffic charts span both columns.
        const bool wide = chartCols == 2 && (c->objectName() == QLatin1String("chartTimeline") || c->objectName() == QLatin1String("chartTraffic"));
        if (wide && slot % 2) ++slot;
        chartGrid_->addWidget(c, slot / chartCols, slot % chartCols, 1, wide ? 2 : 1);
        slot += wide ? 2 : 1;
    }
    for (int c = 0; c < 2; ++c) chartGrid_->setColumnStretch(c, c < chartCols ? 1 : 0);
}

void Dashboard::setSummary(const QJsonObject &root) {
    const QJsonObject cap = root.value(QStringLiteral("capture")).toObject();
    const qint64 frames = num(cap.value(QStringLiteral("frames_analyzed")));
    stack_->setCurrentIndex(frames > 0 ? 1 : 0);
    if (frames == 0) return;

    const QJsonObject sev = root.value(QStringLiteral("severity_totals")).toObject();
    const QJsonArray findings = root.value(QStringLiteral("findings")).toArray();
    kpis_[0]->setValue(formatNumber(static_cast<double>(frames)));
    kpis_[1]->setValue(humanDuration(cap.value(QStringLiteral("duration_seconds")).toDouble()),
                       cap.value(QStringLiteral("start_utc")).toString());
    kpis_[2]->setValue(formatNumber(static_cast<double>(num(sev.value(QStringLiteral("error"))))));
    kpis_[3]->setValue(formatNumber(static_cast<double>(num(sev.value(QStringLiteral("warning"))))));
    kpis_[4]->setValue(formatNumber(static_cast<double>(num(sev.value(QStringLiteral("note"))))));
    kpis_[5]->setValue(QString::number(findings.size()));

    // Severity donut
    ChartSpec s;
    s.type = ChartSpec::Donut;
    s.title = QStringLiteral("Findings by severity");
    s.unit = QStringLiteral("findings");
    ChartSeries ss;
    const QList<QPair<QString, int>> levels = {{QStringLiteral("Error"), 4}, {QStringLiteral("Warning"), 3},
                                               {QStringLiteral("Note"), 2}, {QStringLiteral("Info"), 1}};
    for (const auto &l : levels) {
        s.labels << l.first;
        s.sliceKeys << QString::number(l.second);
        ss.values << static_cast<double>(num(sev.value(l.first.toLower())));
    }
    s.series << ss;
    chart(QStringLiteral("chartSeverity"))->setSpec(s);

    // Categories
    ChartSpec c;
    c.type = ChartSpec::HBar;
    c.title = QStringLiteral("Findings by category");
    ChartSeries cs;
    const QJsonObject cats = root.value(QStringLiteral("categories")).toObject();
    QList<QPair<double, QString>> catList;
    for (auto it = cats.begin(); it != cats.end(); ++it) catList << qMakePair(it.value().toDouble(), it.key());
    std::sort(catList.begin(), catList.end(), [](const auto &a, const auto &b) { return a.first > b.first; });
    for (const auto &cv : catList) {
        if (cv.first <= 0) continue;
        QString name = cv.second;
        name[0] = name[0].toUpper();
        c.labels << name;
        cs.values << cv.first;
    }
    cs.name = QStringLiteral("findings");
    c.series << cs;
    chart(QStringLiteral("chartCategories"))->setSpec(c);
    chart(QStringLiteral("chartCategories"))->setVisible(!c.labels.isEmpty());

    // Timeline
    const QJsonObject tl = root.value(QStringLiteral("timeline")).toObject();
    const qint64 start = num(tl.value(QStringLiteral("start_epoch")));
    const qint64 bucket = std::max<qint64>(1, num(tl.value(QStringLiteral("bucket_seconds"))));
    const QJsonArray packets = tl.value(QStringLiteral("packets")).toArray();
    QStringList timeLabels;
    for (int i = 0; i < packets.size(); ++i) {
        const QDateTime dt = QDateTime::fromSecsSinceEpoch(start + i * bucket);
        timeLabels << dt.toString(bucket >= 3600 * 24 ? QStringLiteral("MM-dd") : QStringLiteral("HH:mm:ss"));
    }
    ChartSpec tsp;
    tsp.type = ChartSpec::StackedColumn;
    tsp.title = QStringLiteral("Findings over time");
    tsp.subtitle = QStringLiteral("%1 per bar").arg(humanDuration(static_cast<double>(bucket)));
    tsp.labels = timeLabels;
    const Theme th = Theme::fromPalette(palette());
    for (const auto &l : levels) {
        ChartSeries sr;
        sr.name = l.first;
        sr.color = th.severity(l.second);
        for (const auto &v : tl.value(l.first.toLower()).toArray()) sr.values << v.toDouble();
        sr.values.resize(timeLabels.size());
        tsp.series << sr;
    }
    chart(QStringLiteral("chartTimeline"))->setSpec(tsp);
    chart(QStringLiteral("chartTimeline"))->setVisible(timeLabels.size() > 1);

    ChartSpec tr;
    tr.type = ChartSpec::Line;
    tr.title = QStringLiteral("Traffic");
    tr.subtitle = QStringLiteral("frames per %1").arg(humanDuration(static_cast<double>(bucket)));
    tr.unit = QStringLiteral("frames");
    tr.labels = timeLabels;
    ChartSeries ps;
    ps.name = QStringLiteral("frames");
    for (const auto &v : packets) ps.values << v.toDouble();
    tr.series << ps;
    chart(QStringLiteral("chartTraffic"))->setSpec(tr);
    chart(QStringLiteral("chartTraffic"))->setVisible(timeLabels.size() > 1);

    // Hosts
    ChartSpec h;
    h.type = ChartSpec::HBar;
    h.title = QStringLiteral("Hosts with the most findings");
    h.subtitle = QStringLiteral("click a host to filter");
    ChartSeries hs;
    hs.name = QStringLiteral("findings");
    for (const auto &v : root.value(QStringLiteral("top_hosts")).toArray()) {
        const QJsonObject o = v.toObject();
        h.labels << o.value(QStringLiteral("host")).toString();
        hs.values << o.value(QStringLiteral("findings")).toDouble();
    }
    h.series << hs;
    chart(QStringLiteral("chartHosts"))->setSpec(h);
    chart(QStringLiteral("chartHosts"))->setVisible(!h.labels.isEmpty());

    // Protocols
    ChartSpec pr;
    pr.type = ChartSpec::HBar;
    pr.title = QStringLiteral("Top protocols");
    pr.subtitle = QStringLiteral("frames containing each protocol");
    ChartSeries prs;
    prs.name = QStringLiteral("frames");
    QList<QPair<double, QString>> protoList;
    const QJsonObject protos = root.value(QStringLiteral("protocols")).toObject();
    static const QStringList boring = {QStringLiteral("frame"), QStringLiteral("eth"), QStringLiteral("ethertype"),
                                       QStringLiteral("ip"), QStringLiteral("ipv6"), QStringLiteral("data"), QStringLiteral("raw")};
    for (auto it = protos.begin(); it != protos.end(); ++it)
        if (!boring.contains(it.key())) protoList << qMakePair(it.value().toDouble(), it.key());
    std::sort(protoList.begin(), protoList.end(), [](const auto &a, const auto &b) { return a.first > b.first; });
    for (int i = 0; i < protoList.size() && i < 10; ++i) {
        pr.labels << protoList[i].second;
        prs.values << protoList[i].first;
    }
    pr.series << prs;
    chart(QStringLiteral("chartProtocols"))->setSpec(pr);
    chart(QStringLiteral("chartProtocols"))->setVisible(!pr.labels.isEmpty());

    // TLS / QUIC versions inventory
    ChartSpec tls;
    tls.type = ChartSpec::HBar;
    tls.title = QStringLiteral("Encryption versions");
    tls.subtitle = QStringLiteral("negotiated TLS/DTLS and QUIC versions");
    ChartSeries tlss;
    const QJsonObject inv = root.value(QStringLiteral("inventory")).toObject();
    for (const auto &key : {QStringLiteral("tls_versions"), QStringLiteral("quic_versions")})
        for (const auto &v : inv.value(key).toArray()) {
            tls.labels << v.toObject().value(QStringLiteral("value")).toString();
            tlss.values << v.toObject().value(QStringLiteral("count")).toDouble();
        }
    tlss.name = QStringLiteral("count");
    tls.series << tlss;
    chart(QStringLiteral("chartTls"))->setSpec(tls);
    chart(QStringLiteral("chartTls"))->setVisible(!tls.labels.isEmpty());

    columns_ = 0;
    relayout();
}

} // namespace aiinspector
