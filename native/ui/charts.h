// SPDX-License-Identifier: GPL-2.0-or-later
//
// Lightweight, dependency-free charts (QPainter) for the AI Inspector
// dashboard and for charts the AI assistant includes in its answers.
#pragma once

#include <QColor>
#include <QImage>
#include <QJsonObject>
#include <QPalette>
#include <QRectF>
#include <QString>
#include <QStringList>
#include <QVector>
#include <QWidget>

class QPainter;

namespace aiinspector {

struct Theme {
    QColor window, card, cardBorder, text, subtext, grid, accent, accentText;
    QColor error, warning, note, info;
    QVector<QColor> series;
    bool dark = false;

    static Theme fromPalette(const QPalette &palette);
    QColor severity(int level) const;
};

struct ChartSeries {
    QString name;
    QVector<double> values;
    QColor color; // invalid = theme series color
};

struct ChartSpec {
    enum Type { Bar, HBar, Donut, Line, StackedColumn };
    Type type = Bar;
    QString title;
    QString subtitle;
    QStringList labels;
    QVector<ChartSeries> series;
    QString unit;
    QStringList sliceKeys; // optional identifiers per label (e.g. severity names) for click handling

    bool isEmpty() const;
    double total() const;
};

// Parses a chart requested by the AI (```chart JSON block). Values are
// validated and bounded; returns false with a reason on invalid input.
bool parseChartSpec(const QJsonObject &obj, ChartSpec &spec, QString *error = nullptr);

// Draws a chart into rect. Returns hit regions (one per label index) for tooltips.
QVector<QRectF> paintChart(QPainter &p, const QRectF &rect, const ChartSpec &spec, const Theme &theme);

QImage renderChart(const ChartSpec &spec, const QSize &size, const Theme &theme, qreal devicePixelRatio = 2.0);

QString formatNumber(double v);

class ChartWidget : public QWidget {
    Q_OBJECT
public:
    explicit ChartWidget(QWidget *parent = nullptr);
    void setSpec(const ChartSpec &spec);
    const ChartSpec &spec() const { return spec_; }
    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

signals:
    void itemClicked(int index);

protected:
    void paintEvent(QPaintEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void leaveEvent(QEvent *event) override;
    void changeEvent(QEvent *event) override;

private:
    int hitTest(const QPointF &pos) const;
    ChartSpec spec_;
    QVector<QRectF> hits_;
    int hover_ = -1;
};

} // namespace aiinspector
