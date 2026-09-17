// SPDX-License-Identifier: GPL-2.0-or-later
#include "charts.h"

#include <QEvent>
#include <QFontMetricsF>
#include <QJsonArray>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QRegularExpression>
#include <QToolTip>

#include <algorithm>
#include <cmath>

namespace aiinspector {

namespace {
constexpr int MAX_LABELS = 60;
constexpr int MAX_SERIES = 5;

QColor mix(const QColor &a, const QColor &b, qreal t) {
    return QColor::fromRgbF(static_cast<float>(a.redF() * (1 - t) + b.redF() * t),
                            static_cast<float>(a.greenF() * (1 - t) + b.greenF() * t),
                            static_cast<float>(a.blueF() * (1 - t) + b.blueF() * t));
}

double niceCeil(double v) {
    if (v <= 0) return 1;
    const double exp = std::floor(std::log10(v));
    const double base = std::pow(10.0, exp);
    for (double m : {1.0, 2.0, 2.5, 5.0, 10.0})
        if (v <= m * base) return m * base;
    return 10 * base;
}

QColor seriesColor(const ChartSpec &spec, const Theme &t, int i) {
    if (i < spec.series.size() && spec.series[i].color.isValid()) return spec.series[i].color;
    return t.series.isEmpty() ? t.accent : t.series[i % t.series.size()];
}

QString elide(const QFontMetricsF &fm, const QString &s, qreal width) {
    return fm.elidedText(s, Qt::ElideRight, std::max<qreal>(8, width));
}
} // namespace

Theme Theme::fromPalette(const QPalette &pal) {
    Theme t;
    t.window = pal.color(QPalette::Window);
    t.dark = t.window.lightness() < 128;
    t.text = pal.color(QPalette::WindowText);
    t.subtext = mix(t.text, t.window, 0.45);
    t.card = t.dark ? mix(t.window, QColor(255, 255, 255), 0.05) : mix(t.window, QColor(255, 255, 255), 0.75);
    t.cardBorder = mix(t.text, t.window, t.dark ? 0.82 : 0.88);
    t.grid = mix(t.text, t.window, t.dark ? 0.85 : 0.90);
    t.accent = t.dark ? QColor(0x5b, 0x9c, 0xff) : QColor(0x25, 0x63, 0xeb);
    t.accentText = QColor(255, 255, 255);
    t.error = t.dark ? QColor(0xf0, 0x6a, 0x6a) : QColor(0xd1, 0x3b, 0x3b);
    t.warning = t.dark ? QColor(0xf2, 0xb3, 0x4d) : QColor(0xe0, 0x8e, 0x0b);
    t.note = t.dark ? QColor(0x5b, 0x9c, 0xff) : QColor(0x25, 0x63, 0xeb);
    t.info = t.dark ? QColor(0x9a, 0xa4, 0xb5) : QColor(0x72, 0x7c, 0x8e);
    t.series = t.dark
        ? QVector<QColor>{QColor(0x5b, 0x9c, 0xff), QColor(0x4f, 0xd1, 0xa5), QColor(0xf2, 0xb3, 0x4d),
                          QColor(0xc0, 0x84, 0xfc), QColor(0xf0, 0x6a, 0x6a), QColor(0x38, 0xbd, 0xf8)}
        : QVector<QColor>{QColor(0x25, 0x63, 0xeb), QColor(0x0f, 0x9d, 0x76), QColor(0xe0, 0x8e, 0x0b),
                          QColor(0x93, 0x33, 0xea), QColor(0xd1, 0x3b, 0x3b), QColor(0x08, 0x91, 0xb2)};
    return t;
}

QColor Theme::severity(int level) const {
    switch (level) {
    case 4: return error;
    case 3: return warning;
    case 2: return note;
    default: return info;
    }
}

bool ChartSpec::isEmpty() const {
    for (const auto &s : series)
        for (double v : s.values)
            if (v != 0) return false;
    return true;
}

double ChartSpec::total() const {
    double t = 0;
    for (const auto &s : series)
        for (double v : s.values) t += v;
    return t;
}

QString formatNumber(double v) {
    const double a = std::fabs(v);
    if (a >= 1e9) return QString::number(v / 1e9, 'f', 1) + QStringLiteral("B");
    if (a >= 1e6) return QString::number(v / 1e6, 'f', 1) + QStringLiteral("M");
    if (a >= 1e4) return QString::number(v / 1e3, 'f', 1) + QStringLiteral("k");
    if (std::floor(v) == v) return QString::number(static_cast<qlonglong>(v));
    QString out = QString::number(v, 'f', a < 10 ? 2 : 1);
    while (out.contains(QLatin1Char('.')) && (out.endsWith(QLatin1Char('0')) || out.endsWith(QLatin1Char('.')))) out.chop(1);
    return out;
}

bool parseChartSpec(const QJsonObject &obj, ChartSpec &spec, QString *error) {
    auto fail = [error](const QString &msg) {
        if (error) *error = msg;
        return false;
    };
    const QString type = obj.value(QStringLiteral("type")).toString().toLower();
    if (type == QLatin1String("bar") || type == QLatin1String("column")) spec.type = ChartSpec::Bar;
    else if (type == QLatin1String("hbar") || type == QLatin1String("horizontal_bar")) spec.type = ChartSpec::HBar;
    else if (type == QLatin1String("pie") || type == QLatin1String("donut")) spec.type = ChartSpec::Donut;
    else if (type == QLatin1String("line")) spec.type = ChartSpec::Line;
    else if (type == QLatin1String("stacked") || type == QLatin1String("stacked_bar")) spec.type = ChartSpec::StackedColumn;
    else return fail(QStringLiteral("unsupported chart type"));

    auto cleanText = [](QString s, int max) {
        s.remove(QRegularExpression(QStringLiteral("[\\x00-\\x1F\\x7F]")));
        return s.left(max);
    };
    spec.title = cleanText(obj.value(QStringLiteral("title")).toString(), 90);
    spec.subtitle = cleanText(obj.value(QStringLiteral("subtitle")).toString(), 120);
    spec.unit = cleanText(obj.value(QStringLiteral("unit")).toString(), 20);
    const QJsonArray labels = obj.value(QStringLiteral("labels")).toArray();
    if (labels.isEmpty() || labels.size() > MAX_LABELS) return fail(QStringLiteral("labels must have 1-%1 entries").arg(MAX_LABELS));
    spec.labels.clear();
    for (const auto &l : labels) spec.labels << cleanText(l.isString() ? l.toString() : QString::number(l.toDouble()), 48);

    QJsonArray series = obj.value(QStringLiteral("series")).toArray();
    if (series.isEmpty() && obj.value(QStringLiteral("values")).isArray())
        series.append(QJsonObject{{QStringLiteral("name"), spec.title}, {QStringLiteral("values"), obj.value(QStringLiteral("values"))}});
    if (series.isEmpty() || series.size() > MAX_SERIES) return fail(QStringLiteral("series must have 1-%1 entries").arg(MAX_SERIES));
    spec.series.clear();
    for (const auto &sv : series) {
        const QJsonObject so = sv.toObject();
        ChartSeries s;
        s.name = cleanText(so.value(QStringLiteral("name")).toString(), 40);
        const QJsonArray vals = so.value(QStringLiteral("values")).toArray();
        if (vals.size() != spec.labels.size()) return fail(QStringLiteral("each series needs one value per label"));
        for (const auto &v : vals) {
            if (!v.isDouble() || !std::isfinite(v.toDouble()) || std::fabs(v.toDouble()) > 1e15)
                return fail(QStringLiteral("values must be finite numbers"));
            s.values << v.toDouble();
        }
        spec.series << s;
    }
    if (spec.type == ChartSpec::Donut) {
        spec.series.resize(1);
        for (double v : spec.series[0].values)
            if (v < 0) return fail(QStringLiteral("pie values must be non-negative"));
    }
    return true;
}

// ---------------------------------------------------------------- painting
namespace {

QRectF paintHeader(QPainter &p, const QRectF &r, const ChartSpec &spec, const Theme &t) {
    QRectF area = r;
    QFont f = p.font();
    if (!spec.title.isEmpty()) {
        QFont tf = f;
        tf.setBold(true);
        tf.setPointSizeF(f.pointSizeF() * 1.05);
        p.setFont(tf);
        p.setPen(t.text);
        const QFontMetricsF fm(tf);
        p.drawText(QRectF(area.left(), area.top(), area.width(), fm.height()), Qt::AlignLeft | Qt::AlignVCenter,
                   elide(fm, spec.title, area.width()));
        area.setTop(area.top() + fm.height() + 2);
    }
    if (!spec.subtitle.isEmpty()) {
        QFont sf = f;
        sf.setPointSizeF(f.pointSizeF() * 0.9);
        p.setFont(sf);
        p.setPen(t.subtext);
        const QFontMetricsF fm(sf);
        p.drawText(QRectF(area.left(), area.top(), area.width(), fm.height()), Qt::AlignLeft | Qt::AlignVCenter,
                   elide(fm, spec.subtitle, area.width()));
        area.setTop(area.top() + fm.height() + 2);
    }
    p.setFont(f);
    return area.adjusted(0, 6, 0, 0);
}

qreal paintLegend(QPainter &p, const QRectF &r, const ChartSpec &spec, const Theme &t) {
    if (spec.series.size() < 2) return 0;
    QFont f = p.font();
    QFont lf = f;
    lf.setPointSizeF(f.pointSizeF() * 0.88);
    p.setFont(lf);
    const QFontMetricsF fm(lf);
    qreal x = r.left(), y = r.bottom() - fm.height();
    for (int i = 0; i < spec.series.size(); ++i) {
        const QString name = spec.series[i].name.isEmpty() ? QStringLiteral("Series %1").arg(i + 1) : spec.series[i].name;
        const qreal w = 14 + fm.horizontalAdvance(name) + 14;
        if (x + w > r.right() && x > r.left()) break;
        p.setPen(Qt::NoPen);
        p.setBrush(seriesColor(spec, t, i));
        p.drawRoundedRect(QRectF(x, y + fm.height() / 2 - 4, 8, 8), 2, 2);
        p.setPen(t.subtext);
        p.drawText(QRectF(x + 12, y, w, fm.height()), Qt::AlignLeft | Qt::AlignVCenter, name);
        x += w;
    }
    p.setFont(f);
    return fm.height() + 6;
}

QVector<QRectF> paintDonut(QPainter &p, const QRectF &r, const ChartSpec &spec, const Theme &t) {
    QVector<QRectF> hits(spec.labels.size());
    const auto &vals = spec.series.value(0).values;
    const double total = std::max(1e-9, spec.total());
    const qreal legendW = std::min<qreal>(r.width() * 0.5, 190);
    const qreal d = std::min(r.height(), r.width() - legendW - 12);
    if (d < 40) return hits;
    const QRectF circle(r.left(), r.top() + (r.height() - d) / 2, d, d);
    const qreal thickness = d * 0.22;
    qreal angle = 90.0 * 16;
    p.setPen(Qt::NoPen);
    for (int i = 0; i < vals.size(); ++i) {
        const qreal span = -vals[i] / total * 360.0 * 16;
        if (vals[i] <= 0) continue;
        QPainterPath path;
        path.arcMoveTo(circle, angle / 16);
        path.arcTo(circle, angle / 16, span / 16);
        const QRectF inner = circle.adjusted(thickness, thickness, -thickness, -thickness);
        path.arcTo(inner, (angle + span) / 16, -span / 16);
        path.closeSubpath();
        QColor c = spec.series.value(0).color.isValid() && vals.size() == 1 ? spec.series[0].color
                   : (i < spec.sliceKeys.size() ? t.severity(spec.sliceKeys[i].toInt()) : t.series[i % t.series.size()]);
        p.setBrush(c);
        p.drawPath(path);
        angle += span;
    }
    if (spec.total() <= 0) {
        p.setBrush(t.grid);
        QPainterPath ring;
        ring.addEllipse(circle);
        ring.addEllipse(circle.adjusted(thickness, thickness, -thickness, -thickness));
        p.drawPath(ring);
    }
    // centre total
    QFont f = p.font();
    QFont big = f;
    big.setBold(true);
    big.setPointSizeF(f.pointSizeF() * std::clamp<qreal>(d / 90.0, 1.1, 2.0));
    p.setFont(big);
    p.setPen(t.text);
    const QRectF inner = circle.adjusted(thickness, thickness, -thickness, -thickness);
    const QFontMetricsF bfm(big);
    p.drawText(QRectF(inner.left(), inner.center().y() - bfm.height() * 0.65, inner.width(), bfm.height()),
               Qt::AlignCenter, formatNumber(spec.total()));
    QFont small = f;
    small.setPointSizeF(f.pointSizeF() * 0.85);
    p.setFont(small);
    p.setPen(t.subtext);
    p.drawText(QRectF(inner.left(), inner.center().y() + bfm.height() * 0.3, inner.width(), QFontMetricsF(small).height()),
               Qt::AlignCenter, spec.unit.isEmpty() ? QStringLiteral("total") : spec.unit);
    p.setFont(f);
    // legend
    const QFontMetricsF fm(f);
    const qreal lx = circle.right() + 16;
    qreal ly = r.top() + std::max<qreal>(0, (r.height() - vals.size() * (fm.height() + 6)) / 2);
    for (int i = 0; i < vals.size(); ++i) {
        QColor c = i < spec.sliceKeys.size() ? t.severity(spec.sliceKeys[i].toInt()) : t.series[i % t.series.size()];
        p.setPen(Qt::NoPen);
        p.setBrush(c);
        p.drawRoundedRect(QRectF(lx, ly + fm.height() / 2 - 5, 10, 10), 3, 3);
        p.setPen(t.text);
        const QString pct = QStringLiteral("%1%").arg(qRound(vals[i] / total * 100));
        const qreal numW = fm.horizontalAdvance(QStringLiteral("00000  100%"));
        const QRectF row(lx + 16, ly, r.right() - lx - 16, fm.height());
        p.drawText(row.adjusted(0, 0, -numW, 0), Qt::AlignLeft | Qt::AlignVCenter, elide(fm, spec.labels[i], row.width() - numW));
        p.setPen(t.subtext);
        p.drawText(row, Qt::AlignRight | Qt::AlignVCenter, QStringLiteral("%1  %2").arg(formatNumber(vals[i]), pct));
        hits[i] = QRectF(lx, ly - 3, r.right() - lx, fm.height() + 6);
        ly += fm.height() + 6;
    }
    return hits;
}

QVector<QRectF> paintHBar(QPainter &p, const QRectF &r, const ChartSpec &spec, const Theme &t) {
    QVector<QRectF> hits(spec.labels.size());
    const QFontMetricsF fm(p.font());
    const int n = static_cast<int>(spec.labels.size());
    const qreal rowH = std::clamp<qreal>((r.height()) / std::max(1, n), fm.height() * 1.1, fm.height() * 2.0);
    const int visible = std::min(n, static_cast<int>(r.height() / rowH));
    double maxV = 0;
    for (int i = 0; i < n; ++i) {
        double sum = 0;
        for (const auto &s : spec.series) sum += std::max(0.0, s.values.value(i));
        maxV = std::max(maxV, sum);
    }
    maxV = std::max(maxV, 1e-9);
    qreal labelW = 0;
    for (int i = 0; i < visible; ++i) labelW = std::max(labelW, fm.horizontalAdvance(spec.labels[i]));
    labelW = std::min(labelW + 8, r.width() * 0.42);
    const qreal valueW = fm.horizontalAdvance(QStringLiteral("00.0k")) + 8;
    const qreal barX = r.left() + labelW, barW = std::max<qreal>(10, r.width() - labelW - valueW);
    for (int i = 0; i < visible; ++i) {
        const qreal y = r.top() + i * rowH;
        p.setPen(t.text);
        p.drawText(QRectF(r.left(), y, labelW - 8, rowH), Qt::AlignLeft | Qt::AlignVCenter, elide(fm, spec.labels[i], labelW - 8));
        const qreal barH = std::min<qreal>(rowH * 0.62, 18);
        const QRectF track(barX, y + (rowH - barH) / 2, barW, barH);
        p.setPen(Qt::NoPen);
        p.setBrush(t.grid);
        p.drawRoundedRect(track, barH / 2.5, barH / 2.5);
        qreal x = barX;
        double sum = 0;
        for (int s = 0; s < spec.series.size(); ++s) {
            const double v = std::max(0.0, spec.series[s].values.value(i));
            const qreal w = barW * v / maxV;
            if (w <= 0) continue;
            p.setBrush(seriesColor(spec, t, s));
            p.drawRoundedRect(QRectF(x, track.top(), std::max<qreal>(w, 3), barH), barH / 2.5, barH / 2.5);
            x += w;
            sum += v;
        }
        p.setPen(t.subtext);
        p.drawText(QRectF(barX + barW + 6, y, valueW, rowH), Qt::AlignLeft | Qt::AlignVCenter, formatNumber(sum));
        hits[i] = QRectF(r.left(), y, r.width(), rowH);
    }
    return hits;
}

QVector<QRectF> paintColumns(QPainter &p, const QRectF &r0, const ChartSpec &spec, const Theme &t) {
    QVector<QRectF> hits(spec.labels.size());
    const QFont baseFont = p.font();
    const QFontMetricsF fm(p.font());
    const int n = static_cast<int>(spec.labels.size());
    const bool stacked = spec.type == ChartSpec::StackedColumn;
    const bool line = spec.type == ChartSpec::Line;
    double maxV = 0;
    for (int i = 0; i < n; ++i) {
        double sum = 0;
        for (const auto &s : spec.series) {
            const double v = s.values.value(i);
            sum = stacked ? sum + std::max(0.0, v) : std::max(sum, v);
        }
        maxV = std::max(maxV, sum);
    }
    maxV = niceCeil(maxV);
    qreal axisW = 0;
    for (int g = 0; g <= 4; ++g) axisW = std::max(axisW, fm.horizontalAdvance(formatNumber(maxV * g / 4.0)));
    axisW += 12;
    QRectF r = r0.adjusted(axisW, 4, 0, -(fm.height() + 6));
    if (r.width() < 20 || r.height() < 20) return hits;
    // grid
    QFont small = p.font();
    small.setPointSizeF(small.pointSizeF() * 0.85);
    p.setFont(small);
    for (int g = 0; g <= 4; ++g) {
        const qreal y = r.bottom() - r.height() * g / 4.0;
        p.setPen(QPen(t.grid, 1));
        p.drawLine(QPointF(r.left(), y), QPointF(r.right(), y));
        p.setPen(t.subtext);
        p.drawText(QRectF(r0.left(), y - fm.height() / 2, axisW - 6, fm.height()), Qt::AlignRight | Qt::AlignVCenter,
                   formatNumber(maxV * g / 4.0));
    }
    const qreal slot = r.width() / std::max(1, n);
    // x labels: show a subset so they don't overlap
    const qreal labelW = fm.horizontalAdvance(QStringLiteral("00:00:00")) + 6;
    const int every = std::max(1, static_cast<int>(std::ceil(labelW / std::max<qreal>(1, slot))));
    for (int i = 0; i < n; i += every) {
        p.setPen(t.subtext);
        p.drawText(QRectF(r.left() + i * slot - labelW / 2 + slot / 2, r.bottom() + 3, labelW, fm.height()), Qt::AlignCenter,
                   elide(QFontMetricsF(small), spec.labels[i], labelW));
    }
    p.setFont(baseFont);
    if (line) {
        for (int s = 0; s < spec.series.size(); ++s) {
            QPainterPath path, area;
            for (int i = 0; i < n; ++i) {
                const QPointF pt(r.left() + slot * (i + 0.5), r.bottom() - r.height() * std::max(0.0, spec.series[s].values.value(i)) / maxV);
                if (i == 0) { path.moveTo(pt); area.moveTo(pt.x(), r.bottom()); area.lineTo(pt); }
                else { path.lineTo(pt); area.lineTo(pt); }
                if (i == n - 1) area.lineTo(pt.x(), r.bottom());
            }
            QColor c = seriesColor(spec, t, s);
            QColor fill = c;
            fill.setAlphaF(spec.series.size() == 1 ? 0.18f : 0.08f);
            p.setPen(Qt::NoPen);
            p.setBrush(fill);
            p.drawPath(area);
            p.setPen(QPen(c, 2.0, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            p.setBrush(Qt::NoBrush);
            p.drawPath(path);
        }
    } else {
        const int ns = static_cast<int>(spec.series.size());
        const qreal barSlot = slot * 0.72;
        for (int i = 0; i < n; ++i) {
            qreal base = r.bottom();
            for (int s = 0; s < ns; ++s) {
                const double v = std::max(0.0, spec.series[s].values.value(i));
                const qreal h = r.height() * v / maxV;
                p.setPen(Qt::NoPen);
                p.setBrush(seriesColor(spec, t, s));
                if (stacked) {
                    if (h > 0) p.drawRect(QRectF(r.left() + slot * i + (slot - barSlot) / 2, base - h, barSlot, h));
                    base -= h;
                } else {
                    const qreal w = barSlot / ns;
                    if (h > 0) p.drawRoundedRect(QRectF(r.left() + slot * i + (slot - barSlot) / 2 + s * w, r.bottom() - h, w * 0.92, h), 2, 2);
                }
            }
        }
    }
    for (int i = 0; i < n; ++i) hits[i] = QRectF(r.left() + slot * i, r.top(), slot, r.height());
    return hits;
}

} // namespace

QVector<QRectF> paintChart(QPainter &p, const QRectF &rect, const ChartSpec &spec, const Theme &theme) {
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setRenderHint(QPainter::TextAntialiasing, true);
    QRectF area = paintHeader(p, rect, spec, theme);
    if (spec.labels.isEmpty() || spec.series.isEmpty()) return {};
    if (spec.type != ChartSpec::Donut && spec.type != ChartSpec::HBar) area.setBottom(area.bottom() - paintLegend(p, area, spec, theme));
    else if (spec.type == ChartSpec::HBar) area.setBottom(area.bottom() - paintLegend(p, area, spec, theme));
    if (spec.isEmpty()) {
        p.setPen(theme.subtext);
        p.drawText(area, Qt::AlignCenter, QStringLiteral("No data"));
        return {};
    }
    switch (spec.type) {
    case ChartSpec::Donut: return paintDonut(p, area, spec, theme);
    case ChartSpec::HBar: return paintHBar(p, area, spec, theme);
    default: return paintColumns(p, area, spec, theme);
    }
}

QImage renderChart(const ChartSpec &spec, const QSize &size, const Theme &theme, qreal dpr) {
    QImage img(QSize(qRound(size.width() * dpr), qRound(size.height() * dpr)), QImage::Format_ARGB32_Premultiplied);
    img.setDevicePixelRatio(dpr);
    img.fill(theme.card);
    QPainter p(&img);
    p.setRenderHint(QPainter::Antialiasing);
    QPainterPath border;
    border.addRoundedRect(QRectF(0.5, 0.5, size.width() - 1, size.height() - 1), 10, 10);
    p.setPen(QPen(theme.cardBorder, 1));
    p.drawPath(border);
    paintChart(p, QRectF(14, 12, size.width() - 28, size.height() - 24), spec, theme);
    return img;
}

// ---------------------------------------------------------------- widget
ChartWidget::ChartWidget(QWidget *parent) : QWidget(parent) {
    setMouseTracking(true);
    setAttribute(Qt::WA_Hover);
}

void ChartWidget::setSpec(const ChartSpec &spec) {
    spec_ = spec;
    hover_ = -1;
    updateGeometry();
    update();
}

QSize ChartWidget::sizeHint() const {
    const int rows = spec_.type == ChartSpec::HBar ? std::max<int>(3, static_cast<int>(spec_.labels.size())) : 0;
    const int h = spec_.type == ChartSpec::HBar ? 64 + rows * (fontMetrics().height() + 12) : 250;
    return QSize(360, std::min(h, 400));
}

QSize ChartWidget::minimumSizeHint() const {
    const int line = fontMetrics().height();
    switch (spec_.type) {
    case ChartSpec::HBar:
        return QSize(220, std::min(380, 64 + std::max<int>(2, static_cast<int>(spec_.labels.size())) * (line + 12)));
    case ChartSpec::Donut: return QSize(220, 190);
    default: return QSize(220, 240);
    }
}

void ChartWidget::paintEvent(QPaintEvent *) {
    const Theme t = Theme::fromPalette(palette());
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    QPainterPath card;
    card.addRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), 10, 10);
    p.fillPath(card, t.card);
    p.setPen(QPen(t.cardBorder, 1));
    p.drawPath(card);
    hits_ = paintChart(p, QRectF(rect()).adjusted(14, 12, -14, -12), spec_, t);
    if (hover_ >= 0 && hover_ < hits_.size() && !hits_[hover_].isNull()) {
        QColor hl = t.text;
        hl.setAlphaF(0.06f);
        p.setPen(Qt::NoPen);
        p.setBrush(hl);
        p.drawRoundedRect(hits_[hover_], 4, 4);
    }
}

int ChartWidget::hitTest(const QPointF &pos) const {
    for (int i = 0; i < hits_.size(); ++i)
        if (hits_[i].contains(pos)) return i;
    return -1;
}

void ChartWidget::mouseMoveEvent(QMouseEvent *e) {
    const int h = hitTest(e->position());
    if (h != hover_) {
        hover_ = h;
        update();
    }
    if (h >= 0 && h < spec_.labels.size()) {
        QStringList lines{spec_.labels[h]};
        for (const auto &s : spec_.series)
            lines << QStringLiteral("%1%2%3").arg(s.name.isEmpty() ? QString() : s.name + QStringLiteral(": "),
                                                  formatNumber(s.values.value(h)),
                                                  spec_.unit.isEmpty() ? QString() : QStringLiteral(" ") + spec_.unit);
        QToolTip::showText(e->globalPosition().toPoint(), lines.join(QLatin1Char('\n')), this);
        setCursor(receivers(SIGNAL(itemClicked(int))) > 0 ? Qt::PointingHandCursor : Qt::ArrowCursor);
    } else {
        QToolTip::hideText();
        unsetCursor();
    }
}

void ChartWidget::mousePressEvent(QMouseEvent *e) {
    const int h = hitTest(e->position());
    if (h >= 0 && e->button() == Qt::LeftButton) emit itemClicked(h);
}

void ChartWidget::leaveEvent(QEvent *) {
    hover_ = -1;
    update();
}

void ChartWidget::changeEvent(QEvent *e) {
    if (e->type() == QEvent::PaletteChange) update();
    QWidget::changeEvent(e);
}

} // namespace aiinspector
