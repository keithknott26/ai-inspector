// SPDX-License-Identifier: GPL-2.0-or-later
#include "panel.h"
#include "charts.h"
#include "chat_view.h"
#include "dashboard.h"
#include "settings.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QDockWidget>
#include <QEvent>
#include <QFileDialog>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMessageBox>
#include <QPainter>
#include <QPainterPath>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSplitter>
#include <QStyledItemDelegate>
#include <QTabWidget>
#include <QTextBrowser>
#include <QToolButton>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace aiinspector {

namespace {
constexpr int COL_SEV = 0, COL_PROTO = 1, COL_TITLE = 2, COL_COUNT = 3, COL_FIRST = 4;
constexpr int ROLE_FIRST = Qt::UserRole + 1, ROLE_FILTER = Qt::UserRole + 2, ROLE_LEVEL = Qt::UserRole + 3,
              ROLE_JSON = Qt::UserRole + 4, ROLE_CATEGORY = Qt::UserRole + 5;
constexpr int MAX_PACKET_TREE_CHARS = 24000;
constexpr int TAB_OVERVIEW = 0, TAB_FINDINGS = 1, TAB_ASSISTANT = 2, TAB_REPORT = 3;

QString hex(const QColor &c) { return c.name(QColor::HexRgb); }

class SeverityItem : public QTreeWidgetItem {
public:
    using QTreeWidgetItem::QTreeWidgetItem;
    bool operator<(const QTreeWidgetItem &other) const override {
        const int col = treeWidget() ? treeWidget()->sortColumn() : 0;
        if (col == COL_SEV) {
            const int a = data(COL_SEV, ROLE_LEVEL).toInt(), b = other.data(COL_SEV, ROLE_LEVEL).toInt();
            if (a != b) return a < b;
            return text(COL_COUNT).toULongLong() < other.text(COL_COUNT).toULongLong();
        }
        if (col == COL_COUNT || col == COL_FIRST) return text(col).toULongLong() < other.text(col).toULongLong();
        return QTreeWidgetItem::operator<(other);
    }
};

// Paints the severity column as a coloured pill.
class SeverityDelegate : public QStyledItemDelegate {
public:
    using QStyledItemDelegate::QStyledItemDelegate;
    void paint(QPainter *p, const QStyleOptionViewItem &opt, const QModelIndex &index) const override {
        QStyleOptionViewItem o = opt;
        initStyleOption(&o, index);
        const QString text = o.text;
        o.text.clear();
        // Draw only the row background/selection; the pill replaces the text.
        const QWidget *view = o.widget;
        (view ? view->style() : QApplication::style())->drawControl(QStyle::CE_ItemViewItem, &o, p, view);
        const Theme t = Theme::fromPalette(opt.palette);
        const QColor c = t.severity(index.data(ROLE_LEVEL).toInt());
        p->save();
        p->setRenderHint(QPainter::Antialiasing);
        QFont f = opt.font;
        f.setBold(true);
        f.setPointSizeF(f.pointSizeF() * 0.85);
        p->setFont(f);
        const QFontMetricsF fm(f);
        const qreal w = fm.horizontalAdvance(text) + 16, h = fm.height() + 4;
        const QRectF pill(opt.rect.left() + 6, opt.rect.center().y() - h / 2 + 0.5, w, h);
        QColor bg = c;
        bg.setAlphaF(t.dark ? 0.28f : 0.14f);
        p->setPen(Qt::NoPen);
        p->setBrush(bg);
        p->drawRoundedRect(pill, h / 2, h / 2);
        p->setPen(c);
        p->drawText(pill, Qt::AlignCenter, text);
        p->restore();
    }
    QSize sizeHint(const QStyleOptionViewItem &opt, const QModelIndex &index) const override {
        QSize s = QStyledItemDelegate::sizeHint(opt, index);
        s.setHeight(std::max(s.height(), opt.fontMetrics.height() + 12));
        s.setWidth(std::max(s.width(), 92));
        return s;
    }
};

QString filterForHost(const QString &host) {
    QHostAddress a;
    if (a.setAddress(host)) return (a.protocol() == QAbstractSocket::IPv6Protocol ? QStringLiteral("ipv6.addr == ") : QStringLiteral("ip.addr == ")) + host;
    static const QRegularExpression mac(QStringLiteral("^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$"));
    if (mac.match(host).hasMatch()) return QStringLiteral("eth.addr == ") + host;
    return {};
}
} // namespace

InspectorPanel::InspectorPanel(Host host, QWidget *parent) : QWidget(parent), host_(std::move(host)), client_(new AiClient(this)) {
    setObjectName(QStringLiteral("aiInspectorPanel"));
    setMinimumWidth(380);
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(8);

    // ---- header
    auto *header = new QHBoxLayout;
    auto *titles = new QVBoxLayout;
    titles->setSpacing(0);
    title_ = new QLabel(QStringLiteral("AI Inspector"), this);
    title_->setObjectName(QStringLiteral("title"));
    summaryLabel_ = new QLabel(this);
    summaryLabel_->setObjectName(QStringLiteral("summary"));
    summaryLabel_->setTextFormat(Qt::PlainText);
    summaryLabel_->setWordWrap(true);
    titles->addWidget(title_);
    titles->addWidget(summaryLabel_);
    header->addLayout(titles, 1);
    auto *refreshBtn = new QToolButton(this);
    refreshBtn->setObjectName(QStringLiteral("refresh"));
    refreshBtn->setText(QStringLiteral("↻"));
    refreshBtn->setToolTip(QStringLiteral("Refresh analysis"));
    auto *settingsBtn = new QToolButton(this);
    settingsBtn->setObjectName(QStringLiteral("settings"));
    settingsBtn->setText(QStringLiteral("⚙"));
    settingsBtn->setToolTip(QStringLiteral("AI provider and privacy settings"));
    header->addWidget(refreshBtn, 0, Qt::AlignTop);
    header->addWidget(settingsBtn, 0, Qt::AlignTop);
    layout->addLayout(header);

    tabs_ = new QTabWidget(this);
    tabs_->setObjectName(QStringLiteral("tabs"));
    tabs_->setDocumentMode(true);
    layout->addWidget(tabs_, 1);

    // ---- Overview
    dashboard_ = new Dashboard(tabs_);
    tabs_->addTab(dashboard_, QStringLiteral("Overview"));

    // ---- Findings
    auto *ftab = new QWidget(tabs_);
    auto *fl = new QVBoxLayout(ftab);
    fl->setContentsMargins(0, 8, 0, 0);
    auto *filters = new QHBoxLayout;
    search_ = new QLineEdit(ftab);
    search_->setObjectName(QStringLiteral("findingSearch"));
    search_->setPlaceholderText(QStringLiteral("Search findings, protocols, IDs..."));
    search_->setClearButtonEnabled(true);
    severityFilter_ = new QComboBox(ftab);
    severityFilter_->setObjectName(QStringLiteral("severityFilter"));
    severityFilter_->addItem(QStringLiteral("All severities"), 0);
    severityFilter_->addItem(QStringLiteral("Errors"), 4);
    severityFilter_->addItem(QStringLiteral("Warnings and above"), 3);
    severityFilter_->addItem(QStringLiteral("Notes and above"), 2);
    categoryFilter_ = new QComboBox(ftab);
    categoryFilter_->setObjectName(QStringLiteral("categoryFilter"));
    categoryFilter_->addItem(QStringLiteral("All categories"), QString());
    for (const auto &c : {QStringLiteral("security"), QStringLiteral("performance"), QStringLiteral("protocol"),
                          QStringLiteral("anomaly"), QStringLiteral("inventory")}) {
        QString label = c;
        label[0] = label[0].toUpper();
        categoryFilter_->addItem(label, c);
    }
    filters->addWidget(search_, 1);
    filters->addWidget(severityFilter_);
    filters->addWidget(categoryFilter_);
    fl->addLayout(filters);

    auto *split = new QSplitter(Qt::Vertical, ftab);
    findings_ = new QTreeWidget(split);
    findings_->setObjectName(QStringLiteral("findings"));
    findings_->setHeaderLabels({QStringLiteral("Severity"), QStringLiteral("Protocol"), QStringLiteral("Finding"),
                                QStringLiteral("Count"), QStringLiteral("First")});
    findings_->setRootIsDecorated(false);
    findings_->setSortingEnabled(true);
    findings_->setUniformRowHeights(true);
    findings_->setAlternatingRowColors(true);
    findings_->setItemDelegateForColumn(COL_SEV, new SeverityDelegate(findings_));
    findings_->header()->setSectionResizeMode(COL_TITLE, QHeaderView::Stretch);
    findings_->header()->setStretchLastSection(false);
    detail_ = new QTextBrowser(split);
    detail_->setObjectName(QStringLiteral("findingDetail"));
    detail_->setOpenLinks(false);
    split->addWidget(findings_);
    split->addWidget(detail_);
    split->setStretchFactor(0, 3);
    split->setStretchFactor(1, 2);
    fl->addWidget(split, 1);
    auto *fbuttons = new QHBoxLayout;
    goFirst_ = new QPushButton(QStringLiteral("Go to first packet"), ftab);
    goFirst_->setObjectName(QStringLiteral("goFirst"));
    filterBtn_ = new QPushButton(QStringLiteral("Apply filter"), ftab);
    filterBtn_->setObjectName(QStringLiteral("applyFilter"));
    fbuttons->addWidget(goFirst_);
    fbuttons->addWidget(filterBtn_);
    fbuttons->addStretch();
    fl->addLayout(fbuttons);
    tabs_->addTab(ftab, QStringLiteral("Findings"));

    // ---- Assistant
    auto *atab = new QWidget(tabs_);
    auto *al = new QVBoxLayout(atab);
    al->setContentsMargins(0, 8, 0, 0);
    auto *aTop = new QHBoxLayout;
    modelLabel_ = new QLabel(atab);
    modelLabel_->setObjectName(QStringLiteral("modelLabel"));
    modelLabel_->setTextFormat(Qt::PlainText);
    auto *newChat = new QPushButton(QStringLiteral("New conversation"), atab);
    newChat->setObjectName(QStringLiteral("newConversation"));
    auto *copyBtn = new QPushButton(QStringLiteral("Copy"), atab);
    aTop->addWidget(modelLabel_, 1);
    aTop->addWidget(newChat);
    aTop->addWidget(copyBtn);
    al->addLayout(aTop);
    chat_ = new ChatView(atab);
    chat_->setObjectName(QStringLiteral("transcript"));
    al->addWidget(chat_, 1);
    auto *actions = new QHBoxLayout;
    triageBtn_ = new QPushButton(QStringLiteral("Triage capture"), atab);
    triageBtn_->setObjectName(QStringLiteral("triage"));
    explainBtn_ = new QPushButton(QStringLiteral("Explain selected packet"), atab);
    explainBtn_->setObjectName(QStringLiteral("explain"));
    actions->addWidget(triageBtn_);
    actions->addWidget(explainBtn_);
    actions->addStretch();
    al->addLayout(actions);
    auto *chips = new QHBoxLayout;
    const QList<QPair<QString, QString>> suggestions = {
        {QStringLiteral("Top security risks"), QStringLiteral("What are the most important security risks in this capture? Rank them and include a chart if it helps.")},
        {QStringLiteral("Chart the trends"), QStringLiteral("Show how findings and traffic change over the capture with a chart, and explain any spikes.")},
        {QStringLiteral("Encryption posture"), QStringLiteral("Assess TLS, QUIC and other encryption in this capture: versions, cipher weaknesses and certificates.")}};
    for (const auto &sgt : suggestions) {
        auto *b = new QPushButton(sgt.first, atab);
        b->setObjectName(QStringLiteral("suggestion"));
        b->setToolTip(sgt.second);
        connect(b, &QPushButton::clicked, this, [this, q = sgt.second] {
            question_->setText(q);
            askQuestion();
        });
        chips->addWidget(b);
        suggestionBtns_ << b;
    }
    chips->addStretch();
    al->addLayout(chips);
    auto *askRow = new QHBoxLayout;
    question_ = new QLineEdit(atab);
    question_->setObjectName(QStringLiteral("question"));
    question_->setPlaceholderText(QStringLiteral("Ask about this capture..."));
    question_->setMaxLength(4000);
    question_->setClearButtonEnabled(true);
    askBtn_ = new QPushButton(QStringLiteral("Send"), atab);
    askBtn_->setObjectName(QStringLiteral("ask"));
    cancelBtn_ = new QPushButton(QStringLiteral("Stop"), atab);
    cancelBtn_->setObjectName(QStringLiteral("cancel"));
    askRow->addWidget(question_, 1);
    askRow->addWidget(askBtn_);
    askRow->addWidget(cancelBtn_);
    al->addLayout(askRow);
    auto *statusRow = new QHBoxLayout;
    progress_ = new QProgressBar(atab);
    progress_->setObjectName(QStringLiteral("busyIndicator"));
    progress_->setRange(0, 0);
    progress_->setTextVisible(false);
    progress_->setFixedWidth(90);
    progress_->setFixedHeight(6);
    status_ = new QLabel(atab);
    status_->setObjectName(QStringLiteral("status"));
    status_->setTextFormat(Qt::PlainText);
    status_->setWordWrap(true);
    statusRow->addWidget(progress_, 0, Qt::AlignVCenter);
    statusRow->addWidget(status_, 1);
    al->addLayout(statusRow);
    tabs_->addTab(atab, QStringLiteral("Assistant"));

    // ---- Report
    auto *rtab = new QWidget(tabs_);
    auto *rl = new QVBoxLayout(rtab);
    rl->setContentsMargins(0, 8, 0, 0);
    report_ = new QPlainTextEdit(rtab);
    report_->setObjectName(QStringLiteral("report"));
    report_->setReadOnly(true);
    report_->setLineWrapMode(QPlainTextEdit::NoWrap);
    report_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    rl->addWidget(report_, 1);
    auto *rbuttons = new QHBoxLayout;
    auto *saveBtn = new QPushButton(QStringLiteral("Save..."), rtab);
    auto *copyReport = new QPushButton(QStringLiteral("Copy"), rtab);
    rbuttons->addStretch();
    rbuttons->addWidget(copyReport);
    rbuttons->addWidget(saveBtn);
    rl->addLayout(rbuttons);
    tabs_->addTab(rtab, QStringLiteral("Report"));

    // ---- wiring
    busyTicker_.setInterval(500);
    connect(&busyTicker_, &QTimer::timeout, this, [this] {
        if (client_->busy())
            status_->setText(QStringLiteral("%1  %2s").arg(busyText_).arg(client_->elapsedMs() / 1000));
    });
    connect(refreshBtn, &QToolButton::clicked, this, &InspectorPanel::refresh);
    connect(settingsBtn, &QToolButton::clicked, this, &InspectorPanel::openSettings);
    connect(search_, &QLineEdit::textChanged, this, &InspectorPanel::applyFindingFilters);
    connect(severityFilter_, qOverload<int>(&QComboBox::currentIndexChanged), this, &InspectorPanel::applyFindingFilters);
    connect(categoryFilter_, qOverload<int>(&QComboBox::currentIndexChanged), this, &InspectorPanel::applyFindingFilters);
    connect(findings_, &QTreeWidget::itemSelectionChanged, this, &InspectorPanel::showFindingDetail);
    connect(findings_, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem *, int) { goFirst_->click(); });
    connect(goFirst_, &QPushButton::clicked, this, [this] {
        auto *it = selectedFinding();
        if (!it || !actionAllowed()) return;
        if (host_.goToFrame) host_.goToFrame(it->data(COL_TITLE, ROLE_FIRST).toUInt());
    });
    connect(filterBtn_, &QPushButton::clicked, this, [this] {
        auto *it = selectedFinding();
        if (!it || !actionAllowed()) return;
        if (host_.applyFilter) host_.applyFilter(it->data(COL_TITLE, ROLE_FILTER).toString());
    });
    connect(detail_, &QTextBrowser::anchorClicked, this, [this](const QUrl &url) {
        if (!actionAllowed()) return;
        if (url.scheme() == QLatin1String("wsframe") && host_.goToFrame) host_.goToFrame(url.path().toUInt());
        if (url.scheme() == QLatin1String("wsfilter") && host_.applyFilter)
            host_.applyFilter(QString::fromUtf8(QByteArray::fromHex(url.path().toLatin1())));
    });
    connect(dashboard_, &Dashboard::severityClicked, this, [this](int level) {
        const int idx = severityFilter_->findData(level == 1 ? 0 : level);
        severityFilter_->setCurrentIndex(std::max(0, idx));
        tabs_->setCurrentIndex(TAB_FINDINGS);
    });
    connect(dashboard_, &Dashboard::categoryClicked, this, [this](const QString &cat) {
        categoryFilter_->setCurrentIndex(std::max(0, categoryFilter_->findData(cat)));
        tabs_->setCurrentIndex(TAB_FINDINGS);
    });
    connect(dashboard_, &Dashboard::hostClicked, this, [this](const QString &hostName) {
        const QString f = filterForHost(hostName);
        if (!f.isEmpty() && actionAllowed() && host_.applyFilter) host_.applyFilter(f + QStringLiteral(" && ai_inspector"));
    });
    connect(dashboard_, &Dashboard::protocolClicked, this, [this](const QString &proto) {
        static const QRegularExpression ok(QStringLiteral("^[a-z][a-z0-9_.-]{0,31}$"));
        if (ok.match(proto).hasMatch() && actionAllowed() && host_.applyFilter) host_.applyFilter(proto);
    });
    connect(triageBtn_, &QPushButton::clicked, this, &InspectorPanel::runTriage);
    connect(explainBtn_, &QPushButton::clicked, this, &InspectorPanel::explainSelectedPacket);
    connect(askBtn_, &QPushButton::clicked, this, &InspectorPanel::askQuestion);
    connect(question_, &QLineEdit::returnPressed, this, &InspectorPanel::askQuestion);
    connect(cancelBtn_, &QPushButton::clicked, client_, &AiClient::cancel);
    connect(newChat, &QPushButton::clicked, this, [this] {
        if (client_->busy()) return;
        client_->resetConversation();
        redactor_.reset();
        chat_->clearConversation();
        status_->setText(QStringLiteral("New conversation started."));
    });
    connect(copyBtn, &QPushButton::clicked, this, [this] { QApplication::clipboard()->setText(chat_->plainTranscript()); });
    connect(copyReport, &QPushButton::clicked, this, [this] { QApplication::clipboard()->setText(report_->toPlainText()); });
    connect(saveBtn, &QPushButton::clicked, this, [this] {
        const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("Save report"),
            QStringLiteral("ai-inspector-report-%1.txt").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss"))),
            QStringLiteral("Text files (*.txt)"));
        if (path.isEmpty()) return;
        QSaveFile f(path);
        if (!f.open(QIODevice::WriteOnly) || f.write(report_->toPlainText().toUtf8()) < 0 || !f.commit())
            QMessageBox::warning(this, QStringLiteral("AI Inspector"), QStringLiteral("Could not save: %1").arg(f.errorString()));
    });
    if (host_.validateFilter) chat_->setFilterValidator(host_.validateFilter);
    chat_->setDisplayTransform([this](const QString &text) { return redactor_.restore(text); });
    connect(chat_, &ChatView::filterRejected, this, [this](const QString &f, const QString &why) {
        status_->setText(QStringLiteral("Not a valid display filter: %1 (%2)").arg(f, why));
    });
    connect(chat_, &ChatView::applyFilterRequested, this, [this](const QString &f) {
        if (actionAllowed() && host_.applyFilter) host_.applyFilter(f);
    });
    connect(chat_, &ChatView::goToFrameRequested, this, [this](quint32 frame) {
        if (actionAllowed() && host_.goToFrame) host_.goToFrame(frame);
    });
    connect(client_, &AiClient::delta, this, [this](const QString &text) {
        chat_->appendAssistant(text);
        busyText_ = QStringLiteral("Receiving answer...");
    });
    connect(client_, &AiClient::finished, this, [this](const QString &text) {
        chat_->finishAssistant(text);
        setBusy(false, QStringLiteral("Answer complete in %1 s.").arg(QString::number(client_->elapsedMs() / 1000.0, 'f', 1)));
        emit transcriptChanged();
    });
    connect(client_, &AiClient::failed, this, [this](const QString &err) {
        chat_->addError(err);
        setBusy(false, err);
        emit transcriptChanged();
    });

    applyStyle();
    updateModelLabel();
    setBusy(false);
    refresh();
}

void InspectorPanel::changeEvent(QEvent *event) {
    if (event->type() == QEvent::PaletteChange) applyStyle();
    QWidget::changeEvent(event);
}

void InspectorPanel::applyStyle() {
    const Theme t = Theme::fromPalette(palette());
    const QString css = QStringLiteral(
        "QLabel#title { font-size: 15pt; font-weight: 700; }"
        "QLabel#summary, QLabel#modelLabel, QLabel#status { color: %1; }"
        "QToolButton#refresh, QToolButton#settings { font-size: 14pt; border: 1px solid %2; border-radius: 6px; padding: 2px 8px; }"
        "QToolButton#refresh:hover, QToolButton#settings:hover { background: %3; }"
        "QPushButton { border: 1px solid %2; border-radius: 7px; padding: 5px 12px; background: %3; color: %4; }"
        "QPushButton:hover { border-color: %5; }"
        "QPushButton:disabled { color: %1; }"
        "QPushButton#triage, QPushButton#ask { background: %5; color: %6; border-color: %5; font-weight: 600; }"
        "QPushButton#triage:disabled, QPushButton#ask:disabled { background: %2; border-color: %2; color: %1; }"
        "QPushButton#suggestion { border-radius: 12px; padding: 3px 10px; color: %5; }"
        "QPushButton#cancel:enabled { color: %7; border-color: %7; }"
        "QLineEdit, QComboBox { border: 1px solid %2; border-radius: 7px; padding: 5px 8px; background: %3; color: %4; }"
        "QLineEdit:focus { border-color: %5; }"
        "QTreeWidget, QTextBrowser#findingDetail, QPlainTextEdit#report, QTextBrowser#transcript { border: 1px solid %2; border-radius: 8px; background: %3; }"
        "QProgressBar#busyIndicator { border: none; border-radius: 3px; background: %2; }"
        "QProgressBar#busyIndicator::chunk { background: %5; border-radius: 3px; }")
        .arg(hex(t.subtext), hex(t.cardBorder), hex(t.card), hex(t.text), hex(t.accent), hex(t.accentText), hex(t.error));
    setStyleSheet(css);
}

void InspectorPanel::updateModelLabel() {
    const UiSettings s = UiSettings::load();
    modelLabel_->setText(QStringLiteral("%1  •  %2%3").arg(AiConfig::providerName(s.ai.provider), s.ai.effectiveModel(),
        s.ai.apiKey.isEmpty() && s.ai.provider != Provider::OpenAICompatible ? QStringLiteral("  •  no API key") : QString()));
}

QTreeWidgetItem *InspectorPanel::selectedFinding() const {
    const auto items = findings_->selectedItems();
    return items.isEmpty() ? nullptr : items.first();
}

bool InspectorPanel::generationCurrent() const {
    return !host_.generation || host_.generation() == dataGeneration_;
}

bool InspectorPanel::actionAllowed() {
    if (generationCurrent()) return true;
    refresh();
    status_->setText(QStringLiteral("The capture changed; the view was refreshed. Try the action again."));
    summaryLabel_->setText(QStringLiteral("Capture changed — refreshed."));
    return false;
}

void InspectorPanel::refresh() {
    const bool engine = !host_.engineAvailable || host_.engineAvailable();
    if (!engine) {
        summaryLabel_->setText(QStringLiteral("The analysis engine is not loaded. Install ai_inspector_engine into the epan "
                                              "plugin folder and restart Wireshark."));
        report_->setPlainText(summaryLabel_->text());
        findings_->clear();
        triageBtn_->setEnabled(false);
        return;
    }
    dataGeneration_ = host_.generation ? host_.generation() : 0;
    summary_ = QJsonDocument::fromJson(host_.summaryJson ? host_.summaryJson(0).toUtf8() : QByteArray()).object();
    const QJsonObject cap = summary_.value(QStringLiteral("capture")).toObject();
    const QJsonObject sev = summary_.value(QStringLiteral("severity_totals")).toObject();
    const qint64 frames = cap.value(QStringLiteral("frames_analyzed")).toVariant().toLongLong();
    if (frames == 0) {
        summaryLabel_->setText(QStringLiteral("No capture analyzed yet. Open a capture file (or reload it) to see findings."));
    } else {
        summaryLabel_->setText(QStringLiteral("%1 frames  •  %2 errors  •  %3 warnings  •  %4 notes")
            .arg(frames).arg(sev.value(QStringLiteral("error")).toVariant().toLongLong())
            .arg(sev.value(QStringLiteral("warning")).toVariant().toLongLong())
            .arg(sev.value(QStringLiteral("note")).toVariant().toLongLong()));
    }
    dashboard_->setSummary(summary_);
    populateFindings();
    if (host_.reportText) report_->setPlainText(host_.reportText());
    updateModelLabel();
    setBusy(client_->busy());
}

void InspectorPanel::populateFindings() {
    const QSignalBlocker block(findings_);
    findings_->clear();
    findings_->setSortingEnabled(false);
    const Theme t = Theme::fromPalette(palette());
    for (const auto &v : summary_.value(QStringLiteral("findings")).toArray()) {
        const QJsonObject f = v.toObject();
        auto *it = new SeverityItem(findings_);
        const int level = f.value(QStringLiteral("severity_level")).toInt();
        it->setText(COL_SEV, f.value(QStringLiteral("severity")).toString());
        it->setData(COL_SEV, ROLE_LEVEL, level);
        it->setText(COL_PROTO, f.value(QStringLiteral("protocol")).toString());
        it->setText(COL_TITLE, f.value(QStringLiteral("title")).toString());
        it->setText(COL_COUNT, QString::number(f.value(QStringLiteral("count")).toVariant().toULongLong()));
        it->setText(COL_FIRST, QString::number(f.value(QStringLiteral("first_frame")).toVariant().toUInt()));
        it->setTextAlignment(COL_COUNT, Qt::AlignRight | Qt::AlignVCenter);
        it->setTextAlignment(COL_FIRST, Qt::AlignRight | Qt::AlignVCenter);
        it->setData(COL_TITLE, ROLE_FIRST, f.value(QStringLiteral("first_frame")).toVariant().toUInt());
        it->setData(COL_TITLE, ROLE_FILTER, f.value(QStringLiteral("filter")).toString());
        it->setData(COL_TITLE, ROLE_CATEGORY, f.value(QStringLiteral("category")).toString());
        it->setData(COL_TITLE, ROLE_JSON, QJsonDocument(f).toJson(QJsonDocument::Compact));
        it->setToolTip(COL_TITLE, f.value(QStringLiteral("id")).toString());
        Q_UNUSED(t);
    }
    findings_->setSortingEnabled(true);
    findings_->sortByColumn(COL_SEV, Qt::DescendingOrder);
    findings_->resizeColumnToContents(COL_SEV);
    findings_->resizeColumnToContents(COL_PROTO);
    applyFindingFilters();
    if (findings_->topLevelItemCount() > 0 && !selectedFinding()) findings_->setCurrentItem(findings_->topLevelItem(0));
    showFindingDetail();
}

void InspectorPanel::applyFindingFilters() {
    const QString q = search_->text().trimmed();
    const int minLevel = severityFilter_->currentData().toInt();
    const QString cat = categoryFilter_->currentData().toString();
    for (int i = 0; i < findings_->topLevelItemCount(); ++i) {
        auto *it = findings_->topLevelItem(i);
        bool show = it->data(COL_SEV, ROLE_LEVEL).toInt() >= minLevel;
        if (show && !cat.isEmpty()) show = it->data(COL_TITLE, ROLE_CATEGORY).toString() == cat;
        if (show && !q.isEmpty())
            show = it->text(COL_TITLE).contains(q, Qt::CaseInsensitive) || it->text(COL_PROTO).contains(q, Qt::CaseInsensitive)
                || it->toolTip(COL_TITLE).contains(q, Qt::CaseInsensitive);
        it->setHidden(!show);
    }
}

void InspectorPanel::showFindingDetail() {
    auto *it = selectedFinding();
    goFirst_->setEnabled(it != nullptr);
    filterBtn_->setEnabled(it && !it->data(COL_TITLE, ROLE_FILTER).toString().isEmpty());
    const Theme t = Theme::fromPalette(palette());
    if (!it) {
        detail_->setHtml(QStringLiteral("<p style='color:%1'>Select a finding to see its details.</p>").arg(hex(t.subtext)));
        return;
    }
    const QJsonObject f = QJsonDocument::fromJson(it->data(COL_TITLE, ROLE_JSON).toByteArray()).object();
    const int level = f.value(QStringLiteral("severity_level")).toInt();
    const QString filter = f.value(QStringLiteral("filter")).toString();
    QString examples;
    for (const auto &e : f.value(QStringLiteral("examples")).toArray()) {
        QString ex = e.toString().toHtmlEscaped();
        static const QRegularExpression frameRe(QStringLiteral("^#(\\d+)"));
        const auto m = frameRe.match(e.toString());
        if (m.hasMatch())
            ex = QStringLiteral("<a href='wsframe:%1'>frame %1</a>%2").arg(m.captured(1), e.toString().mid(m.capturedLength()).toHtmlEscaped());
        examples += QStringLiteral("<li>%1</li>").arg(ex);
    }
    const quint32 first = f.value(QStringLiteral("first_frame")).toVariant().toUInt();
    const quint32 lastF = f.value(QStringLiteral("last_frame")).toVariant().toUInt();
    detail_->setHtml(QStringLiteral(
        "<p style='margin:0'><span style='color:%1; font-weight:700'>%2</span> &nbsp;<span style='color:%3'>%4 • %5</span></p>"
        "<p style='font-size:13pt; font-weight:600; margin:4px 0'>%6</p>"
        "<p style='color:%3; margin:0'>%7 occurrence(s) • first <a href='wsframe:%8'>frame %8</a> • last <a href='wsframe:%9'>frame %9</a></p>"
        "%10%11"
        "<p style='color:%3; font-size:small'>ID: %12</p>")
        .arg(hex(t.severity(level)), f.value(QStringLiteral("severity")).toString().toHtmlEscaped(), hex(t.subtext),
             f.value(QStringLiteral("protocol")).toString().toHtmlEscaped(), f.value(QStringLiteral("category")).toString().toHtmlEscaped(),
             f.value(QStringLiteral("title")).toString().toHtmlEscaped())
        .arg(f.value(QStringLiteral("count")).toVariant().toLongLong())
        .arg(first).arg(lastF)
        .arg(filter.isEmpty() ? QString()
                              : QStringLiteral("<p style='margin-top:8px'><b>Display filter</b><br><a href='wsfilter:%1'><code>%2</code></a></p>")
                                    .arg(QString::fromLatin1(filter.toUtf8().toHex()), filter.toHtmlEscaped()),
             examples.isEmpty() ? QString() : QStringLiteral("<p style='margin-bottom:0'><b>Examples</b></p><ul style='margin-top:2px'>%1</ul>").arg(examples),
             f.value(QStringLiteral("id")).toString().toHtmlEscaped()));
}

void InspectorPanel::setBusy(bool busy, const QString &status) {
    const bool engine = !host_.engineAvailable || host_.engineAvailable();
    triageBtn_->setEnabled(!busy && engine);
    explainBtn_->setEnabled(!busy);
    askBtn_->setEnabled(!busy);
    question_->setEnabled(!busy);
    for (auto *b : suggestionBtns_) b->setEnabled(!busy && engine);
    cancelBtn_->setEnabled(busy);
    progress_->setVisible(busy);
    if (busy) busyTicker_.start();
    else busyTicker_.stop();
    if (!status.isNull()) status_->setText(status);
}

QString InspectorPanel::captureContext(quint32 maxFindings) {
    return host_.summaryJson ? host_.summaryJson(maxFindings) : QStringLiteral("{}");
}

void InspectorPanel::send(const QString &shownRequest, const QString &userMessage) {
    updateModelLabel();
    const UiSettings settings = UiSettings::load();
    tabs_->setCurrentIndex(TAB_ASSISTANT);
    const QString invalid = settings.ai.validate();
    if (!invalid.isEmpty()) {
        chat_->addError(invalid);
        status_->setText(invalid);
        if (invalid.startsWith(QStringLiteral("No API key"))) openSettings();
        return;
    }
    QString message = scrubSecrets(userMessage);
    if (settings.redact) message = redactor_.apply(message);
    chat_->addUser(shownRequest);
    chat_->beginAssistant();
    busyText_ = QStringLiteral("Waiting for %1...").arg(settings.ai.effectiveModel());
    setBusy(true, busyText_);
    client_->ask(settings.ai, message);
}

void InspectorPanel::runTriage() {
    if (client_->busy()) return;
    // A triage always starts a fresh conversation: resending earlier triage
    // context would double the request size and slow the answer.
    client_->resetConversation();
    redactor_.reset();
    conversationGeneration_ = host_.generation ? host_.generation() : 0;
    const UiSettings s = UiSettings::load();
    send(QStringLiteral("Triage this capture"),
         QStringLiteral("Capture analysis data (JSON):\n%1\n\nAnalyst request: Triage this capture.")
             .arg(captureContext(static_cast<quint32>(s.effectiveMaxFindings()))));
}

void InspectorPanel::explainSelectedPacket() {
    if (client_->busy()) return;
    tabs_->setCurrentIndex(TAB_ASSISTANT);
    const auto pkt = host_.selectedPacket ? host_.selectedPacket() : std::nullopt;
    if (!pkt || pkt->frame == 0) {
        const QString msg = QStringLiteral("Select a packet in the packet list first.");
        status_->setText(msg);
        chat_->addError(msg);
        return;
    }
    const quint64 gen = host_.generation ? host_.generation() : 0;
    if (gen != conversationGeneration_) {
        client_->resetConversation();
        redactor_.reset();
        conversationGeneration_ = gen;
    }
    const UiSettings s = UiSettings::load();
    QString tree = s.includePacketTree ? pkt->tree : QStringLiteral("(packet tree omitted by privacy setting)");
    if (tree.size() > MAX_PACKET_TREE_CHARS) tree = tree.left(MAX_PACKET_TREE_CHARS) + QStringLiteral("\n... (truncated)");
    const QString q = question_->text().trimmed();
    question_->clear();
    const QString request = q.isEmpty() ? QStringLiteral("Explain packet %1").arg(pkt->frame)
                                        : QStringLiteral("About packet %1: %2").arg(pkt->frame).arg(q);
    // Capture context is only sent when the conversation does not already have it.
    const QString context = client_->conversationTurns() > 0
        ? QString()
        : QStringLiteral("Capture analysis data (JSON):\n%1\n\n").arg(captureContext(static_cast<quint32>(qMin(s.effectiveMaxFindings(), 30))));
    send(request, QStringLiteral("%1Selected packet %2 findings (JSON):\n%3\n\nSelected packet %2 decoded tree:\n%4\n\nAnalyst request: %5")
                      .arg(context).arg(pkt->frame)
                      .arg(pkt->findingsJson.isEmpty() ? QStringLiteral("[]") : pkt->findingsJson, tree, request));
}

void InspectorPanel::askQuestion() {
    if (client_->busy()) return;
    const QString q = question_->text().trimmed();
    if (q.isEmpty()) return;
    question_->clear();
    const quint64 gen = host_.generation ? host_.generation() : 0;
    if (gen != conversationGeneration_) {
        client_->resetConversation();
        redactor_.reset();
        conversationGeneration_ = gen;
    }
    const UiSettings s = UiSettings::load();
    if (client_->conversationTurns() > 0) {
        send(q, QStringLiteral("Follow-up question: %1").arg(q));
    } else {
        send(q, QStringLiteral("Capture analysis data (JSON):\n%1\n\nAnalyst question: %2")
                    .arg(captureContext(static_cast<quint32>(s.effectiveMaxFindings())), q));
    }
}

void InspectorPanel::showReport() {
    refresh();
    tabs_->setCurrentIndex(TAB_REPORT);
}

void InspectorPanel::showOverview() {
    refresh();
    tabs_->setCurrentIndex(TAB_OVERVIEW);
}

void InspectorPanel::openSettings() {
    SettingsDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted) {
        const UiSettings s = UiSettings::load();
        updateModelLabel();
        status_->setText(QStringLiteral("Settings saved. Provider: %1, model: %2, key: %3")
            .arg(AiConfig::providerName(s.ai.provider), s.ai.effectiveModel(),
                 s.ai.apiKey.isEmpty() ? QStringLiteral("not set") : QStringLiteral("configured")));
    }
}

QDockWidget *showDock(QMainWindow *window, Host host) {
    if (!window) return nullptr;
    if (auto *existing = window->findChild<QDockWidget *>(QStringLiteral("aiInspectorDock"), Qt::FindDirectChildrenOnly)) {
        if (auto *panel = existing->findChild<InspectorPanel *>()) panel->refresh();
        existing->show();
        existing->raise();
        return existing;
    }
    auto *dock = new QDockWidget(QStringLiteral("AI Inspector"), window);
    dock->setObjectName(QStringLiteral("aiInspectorDock"));
    dock->setAllowedAreas(Qt::LeftDockWidgetArea | Qt::RightDockWidgetArea | Qt::BottomDockWidgetArea);
    dock->setWidget(new InspectorPanel(std::move(host), dock));
    window->addDockWidget(Qt::RightDockWidgetArea, dock);
    // A useful default width: wide enough for two chart columns on larger screens.
    window->resizeDocks({dock}, {std::max(520, window->width() * 2 / 5)}, Qt::Horizontal);
    dock->show();
    return dock;
}

} // namespace aiinspector
