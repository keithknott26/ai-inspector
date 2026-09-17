// SPDX-License-Identifier: GPL-2.0-or-later
//
// Overview tab. Built entirely from the engine summary JSON
// (build_summary_json() in the engine): capture, severity_totals, categories,
// timeline, top_hosts, protocols and inventory. To add a chart, create a
// ChartWidget in the constructor, fill a ChartSpec in setSummary() and, if it
// should span both columns, add its objectName to relayout().
#pragma once

#include "charts.h"

#include <QJsonObject>
#include <QWidget>

class QGridLayout;
class QLabel;
class QScrollArea;
class QStackedLayout;

namespace aiinspector {

class KpiCard : public QWidget {
    Q_OBJECT
public:
    KpiCard(const QString &caption, int severityLevel, QWidget *parent = nullptr);
    void setValue(const QString &value, const QString &detail = QString());
    QString value() const { return value_; }

signals:
    void clicked();

protected:
    void paintEvent(QPaintEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

private:
    QString caption_, value_, detail_;
    int level_;
};

// Overview tab: KPI cards and charts built from the engine summary JSON.
class Dashboard : public QWidget {
    Q_OBJECT
public:
    explicit Dashboard(QWidget *parent = nullptr);
    void setSummary(const QJsonObject &summary);
    int chartCount() const;
    ChartWidget *chart(const QString &objectName) const;

signals:
    void severityClicked(int level);      // 1..4
    void categoryClicked(const QString &category);
    void hostClicked(const QString &host);
    void protocolClicked(const QString &protocol);

protected:
    void resizeEvent(QResizeEvent *event) override;

private:
    void relayout();
    QStackedLayout *stack_;
    QLabel *empty_;
    QWidget *content_;
    QGridLayout *kpiGrid_;
    QGridLayout *chartGrid_;
    QList<KpiCard *> kpis_;
    QList<ChartWidget *> charts_;
    int columns_ = 0;
};

} // namespace aiinspector
