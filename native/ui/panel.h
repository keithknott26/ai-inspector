// SPDX-License-Identifier: GPL-2.0-or-later
//
// InspectorPanel: the dockable AI Inspector UI.
//
// Tabs: Overview (Dashboard), Findings (filterable table + detail pane),
// Assistant (ChatView + AiClient), Report (plain text report).
//
// The panel never talks to Wireshark directly. Everything it needs is injected
// through the Host struct, implemented by ai_inspector_ui.cpp inside Wireshark
// and by fakes in tests/ui_tests.cpp. Actions that act on packets (go to frame,
// apply filter) are refused when the engine generation changed since the data
// was shown, so stale findings never act on a different capture.
//
// Privacy pipeline for every AI request (see send()):
//   scrubSecrets() -> Redactor::apply() (if enabled) -> AiClient::ask()
// Answers are shown with Redactor::restore() so real addresses appear locally.
//
// The assistant can also pull capture data on demand through EngineTools (see
// engine_tools.h). Tool arguments are un-redacted on the way in and results go
// through the same pipeline on the way out, so the model only ever sees
// placeholders.
#pragma once

#include "ai_client.h"
#include "redactor.h"

#include <QJsonObject>
#include <QString>
#include <QTimer>
#include <QWidget>
#include <functional>
#include <memory>
#include <optional>

class QComboBox;
class QDockWidget;
class QLabel;
class QLineEdit;
class QMainWindow;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QTabWidget;
class QTextBrowser;
class QToolButton;
class QTreeWidget;
class QTreeWidgetItem;

namespace aiinspector {

class ChatView;
class Dashboard;
class EngineTools;

struct SelectedPacket {
    quint32 frame = 0;
    QString tree;          // indented decoded packet tree (sensitive values removed)
    QString findingsJson;  // JSON array from the engine
};

// Everything the panel needs from Wireshark, injectable for tests.
struct Host {
    std::function<bool()> engineAvailable;
    std::function<quint64()> generation;
    std::function<QString(quint32 maxFindings)> summaryJson;
    std::function<QString()> reportText;
    // Findings the engine recorded for one frame, as a JSON array.
    std::function<QString(quint32 frame)> frameFindingsJson;
    std::function<std::optional<SelectedPacket>()> selectedPacket;
    std::function<void(quint32)> goToFrame;
    std::function<void(const QString &)> applyFilter;
    // Compiles a display filter with Wireshark (optional; heuristics are used without it).
    std::function<bool(const QString &filter, QString *error)> validateFilter;
};

class InspectorPanel : public QWidget {
    Q_OBJECT
public:
    explicit InspectorPanel(Host host, QWidget *parent = nullptr);
    ~InspectorPanel() override;

    AiClient *client() const { return client_; }
    ChatView *chat() const { return chat_; }
    Dashboard *dashboard() const { return dashboard_; }

public slots:
    void refresh();
    void runTriage();
    void explainSelectedPacket();
    void askQuestion();
    void showReport();
    void showOverview();
    void openSettings();

signals:
    void transcriptChanged();

protected:
    void changeEvent(QEvent *event) override;

private:
    void send(const QString &shownRequest, const QString &userMessage);
    void setBusy(bool busy, const QString &status = QString());
    bool generationCurrent() const;
    bool actionAllowed();
    QString captureContext(quint32 maxFindings);
    // Enables or disables the assistant's tools for this request and returns
    // the capture context to embed in the message (empty when tools are on).
    QString prepareTools(const struct UiSettings &settings);
    void populateFindings();
    void applyFindingFilters();
    void showFindingDetail();
    void applyStyle();
    void updateModelLabel();
    QTreeWidgetItem *selectedFinding() const;

    Host host_;
    AiClient *client_;
    std::unique_ptr<EngineTools> tools_;
    Redactor redactor_;
    quint64 dataGeneration_ = 0;
    quint64 conversationGeneration_ = 0;
    QJsonObject summary_;
    QTimer busyTicker_;
    QString busyText_;

    QLabel *title_;
    QLabel *summaryLabel_;
    QTabWidget *tabs_;
    Dashboard *dashboard_;
    QLineEdit *search_;
    QComboBox *severityFilter_;
    QComboBox *categoryFilter_;
    QTreeWidget *findings_;
    QTextBrowser *detail_;
    QPushButton *goFirst_;
    QPushButton *filterBtn_;
    QPlainTextEdit *report_;
    ChatView *chat_;
    QLabel *modelLabel_;
    QLineEdit *question_;
    QPushButton *askBtn_;
    QPushButton *triageBtn_;
    QPushButton *explainBtn_;
    QPushButton *cancelBtn_;
    QList<QPushButton *> suggestionBtns_;
    QProgressBar *progress_;
    QLabel *status_;
};

// Shows (or re-shows) the assistant as a dock on the host window.
QDockWidget *showDock(QMainWindow *window, Host host);

} // namespace aiinspector
