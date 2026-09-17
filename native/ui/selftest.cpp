// SPDX-License-Identifier: GPL-2.0-or-later
//
// In-application integration self-test, enabled only when the environment
// variable AI_INSPECTOR_UI_SELFTEST=1 is set. It drives the real plugin inside a
// running Wireshark: waits for a capture, opens the dock, reads findings,
// selects a packet and dumps its tree, applies a filter and (if
// AI_INSPECTOR_ENDPOINT is set) runs an AI triage, then exits Wireshark with
// status 0 on success. Results are printed to stderr.

#include "config.h"

#include <epan/cfile.h>
#include <ui/plugins/include/plugin_if.h>

#include "selftest.h"
#include "chat_view.h"
#include "dashboard.h"

#include <QApplication>
#include <QDockWidget>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMainWindow>
#include <QDir>
#include <QPlainTextEdit>
#include <QTabWidget>
#include <QTextBrowser>
#include <QPointer>
#include <QTimer>
#include <QTreeWidget>

#include <cstdio>
#include <cstdlib>
#include <memory>

namespace aiinspector {

namespace {

// All timers belong to this object. It is parented to the main window, which
// Wireshark deletes before unloading UI plugins, so no timer or callable from
// this library survives until QApplication's destructor.
QPointer<QObject> g_ctx;

void after(int ms, std::function<void()> fn) {
    if (!g_ctx) return;
    auto *t = new QTimer(g_ctx);
    t->setSingleShot(true);
    QObject::connect(t, &QTimer::timeout, t, [t, fn = std::move(fn)] {
        fn();
        if (t) t->deleteLater();
    });
    t->start(ms);
}

struct Run {
    Host host;
    std::function<InspectorPanel *()> open;
    InspectorPanel *panel = nullptr;
    int failures = 0;
    int step = 0;
    int waits = 0;
    quint32 target = 0;
};

void check(Run &r, bool ok, const QString &what) {
    std::fprintf(stderr, "AI_INSPECTOR_UI_SELFTEST %s %s\n", ok ? "ok  " : "FAIL", what.toUtf8().constData());
    if (!ok) ++r.failures;
}

void *displayedCount(capture_file *cf, void *out) {
    if (!cf) return nullptr;
    *static_cast<uint32_t *>(out) = cf->displayed_count;
    return out;
}

void finish(const std::shared_ptr<Run> &r) {
    std::fprintf(stderr, "AI_INSPECTOR_UI_SELFTEST %s (%d failures)\n", r->failures ? "FAILED" : "PASSED", r->failures);
    std::fflush(stderr);
    const int code = r->failures ? 1 : 0;
    // Upstream 4.7 PacketList touches itself from focusChanged() while being
    // destroyed; keep focus away from it when exiting programmatically.
    if (r->panel) r->panel->setFocus(Qt::OtherFocusReason);
    after(200, [code] { QCoreApplication::exit(code); });
    // A modal dialog or nested event loop can swallow exit(); never leave a test run hanging.
    after(10000, [code] { std::_Exit(code); });
}

void tick(const std::shared_ptr<Run> &r) {
    auto again = [r](int ms) { after(ms, [r] { tick(r); }); };
    if (++r->waits > 240) {
        ws_info_t *info = nullptr;
        plugin_if_get_ws_info(&info);
        check(*r, false, QStringLiteral("timed out in step %1 (engine %2, generation %3, file state %4, frames %5)")
                             .arg(r->step).arg(r->host.engineAvailable() ? 1 : 0).arg(r->host.generation())
                             .arg(info ? static_cast<int>(info->cf_state) : -1).arg(info ? info->cf_count : 0));
        finish(r);
        return;
    }
    switch (r->step) {
    case 0: { // wait for the capture to finish loading
        ws_info_t *info = nullptr;
        plugin_if_get_ws_info(&info);
        if (!info || info->cf_state != FILE_READ_DONE || info->cf_count == 0 || r->host.generation() == 0) {
            again(500);
            return;
        }
        check(*r, true, QStringLiteral("capture loaded (%1 frames)").arg(info->cf_count));
        r->step = 1;
        again(500);
        return;
    }
    case 1: {
        check(*r, r->host.engineAvailable(), QStringLiteral("analysis engine detected"));
        r->panel = r->open();
        check(*r, r->panel != nullptr, QStringLiteral("dock panel opened"));
        if (!r->panel) return finish(r);
        auto *dock = qobject_cast<QDockWidget *>(r->panel->parentWidget());
        check(*r, dock && dock->isVisible(), QStringLiteral("dock visible"));
        check(*r, r->open() == r->panel, QStringLiteral("reopening reuses the panel"));
        const QJsonObject sum = QJsonDocument::fromJson(r->host.summaryJson(0).toUtf8()).object();
        const QJsonArray findings = sum.value(QStringLiteral("findings")).toArray();
        check(*r, !findings.isEmpty(), QStringLiteral("summary has %1 finding types").arg(findings.size()));
        auto *tree = r->panel->findChild<QTreeWidget *>(QStringLiteral("findings"));
        check(*r, tree && tree->topLevelItemCount() == findings.size(), QStringLiteral("findings table populated"));
        check(*r, r->panel->dashboard()->chartCount() >= 3, QStringLiteral("overview dashboard has %1 charts").arg(r->panel->dashboard()->chartCount()));
        check(*r, r->host.reportText().contains(QStringLiteral("capture findings report")), QStringLiteral("report text"));
        r->target = findings.isEmpty() ? 1 : findings.at(0).toObject().value(QStringLiteral("first_frame")).toVariant().toUInt();
        if (qEnvironmentVariableIntValue("AI_INSPECTOR_UI_SELFTEST_FRAME") > 0)
            r->target = static_cast<quint32>(qEnvironmentVariableIntValue("AI_INSPECTOR_UI_SELFTEST_FRAME"));
        r->host.goToFrame(r->target);
        r->step = 2;
        again(1500);
        return;
    }
    case 2: {
        const auto pkt = r->host.selectedPacket();
        if (!pkt || pkt->frame != r->target) {
            again(500);
            return;
        }
        check(*r, true, QStringLiteral("goToFrame selected frame %1").arg(r->target));
        check(*r, pkt->tree.contains(QStringLiteral("Frame ")), QStringLiteral("selected packet tree dumped (%1 chars)").arg(pkt->tree.size()));
        check(*r, QJsonDocument::fromJson(pkt->findingsJson.toUtf8()).isArray(), QStringLiteral("frame findings JSON"));
        check(*r, !pkt->tree.contains(QStringLiteral("AI Inspector:")), QStringLiteral("AI Inspector subtree excluded from dump"));
        r->host.applyFilter(QStringLiteral("ai_inspector.severity >= 3"));
        r->step = 3;
        again(2000);
        return;
    }
    case 3: {
        uint32_t shown = 0;
        plugin_if_get_capture_file(displayedCount, &shown);
        ws_info_t *info = nullptr;
        plugin_if_get_ws_info(&info);
        check(*r, shown > 0 && info && shown <= info->cf_count,
              QStringLiteral("display filter on ai_inspector.severity applied (%1 shown)").arg(shown));
        if (r->host.validateFilter) {
            QString why;
            check(*r, !r->host.validateFilter(QStringLiteral("shop.example.test"), &why) && !why.isEmpty(),
                  QStringLiteral("compiler rejects bare host name (%1)").arg(why));
            const QString hostFilter = ChatView::toDisplayFilter(QStringLiteral("shop.example.test"), r->host.validateFilter);
            check(*r, hostFilter.contains(QStringLiteral("http.host")) && r->host.validateFilter(hostFilter, nullptr),
                  QStringLiteral("host name converted to valid filter"));
            check(*r, ChatView::toDisplayFilter(QStringLiteral("10.0.0.66"), r->host.validateFilter) == QStringLiteral("ip.addr == 10.0.0.66"),
                  QStringLiteral("address converted to ip.addr filter"));
        }
        if (qEnvironmentVariableIsEmpty("AI_INSPECTOR_ENDPOINT")) return finish(r);
        auto *transcript = r->panel->findChild<QTextBrowser *>(QStringLiteral("transcript"));
        QObject::connect(r->panel->client(), &AiClient::finished, r->panel, [r, transcript](const QString &text) {
            if (r->step == 10) {
                check(*r, text.contains(QStringLiteral("MOCK")), QStringLiteral("AI triage response received"));
                check(*r, transcript && transcript->toPlainText().contains(QStringLiteral("MOCK")), QStringLiteral("transcript shows response"));
                r->step = 11;
                after(100, [r] { r->panel->explainSelectedPacket(); });
            } else if (r->step == 11) {
                check(*r, r->panel->client()->conversationTurns() == 2, QStringLiteral("explain packet continued the conversation"));
                check(*r, r->panel->chat()->chartCount() >= 1, QStringLiteral("assistant rendered inline chart"));
                const QString shots = qEnvironmentVariable("AI_INSPECTOR_UI_SCREENSHOTS");
                if (!shots.isEmpty()) {
                    QDir().mkpath(shots);
                    if (auto *mw = qobject_cast<QMainWindow *>(r->panel->window())) {
                        mw->resize(1600, 1000);
                        if (auto *dk = qobject_cast<QDockWidget *>(r->panel->parentWidget())) mw->resizeDocks({dk}, {760}, Qt::Horizontal);
                        QCoreApplication::processEvents();
                    }
                    auto *dock = r->panel->parentWidget();
                    auto *tabs = r->panel->findChild<QTabWidget *>(QStringLiteral("tabs"));
                    for (int i = 0; tabs && i < tabs->count(); ++i) {
                        tabs->setCurrentIndex(i);
                        QCoreApplication::processEvents();
                        (dock ? dock : r->panel)->grab().save(QDir(shots).filePath(QStringLiteral("tab%1.png").arg(i)));
                    }
                    if (auto *win = r->panel->window()) win->grab().save(QDir(shots).filePath(QStringLiteral("window.png")));
                }
                r->step = 12;
                finish(r);
            }
        });
        QObject::connect(r->panel->client(), &AiClient::failed, r->panel, [r](const QString &err) {
            if (r->step >= 12) return;
            check(*r, false, QStringLiteral("AI request failed: ") + err);
            r->step = 12;
            finish(r);
        });
        r->step = 10;
        r->panel->runTriage();
        after(30000, [r] {
            if (r->step < 12) {
                check(*r, false, QStringLiteral("AI requests did not complete"));
                r->step = 12;
                finish(r);
            }
        });
        return;
    }
    default:
        return;
    }
}

} // namespace

void startIntegrationSelfTest(const Host &host, std::function<InspectorPanel *()> openPanel) {
    auto r = std::make_shared<Run>();
    r->host = host;
    r->open = std::move(openPanel);
    std::fprintf(stderr, "AI_INSPECTOR_UI_SELFTEST started\n");
    QObject *mainWindow = nullptr;
    for (QWidget *w : QApplication::topLevelWidgets())
        if (w->inherits("WiresharkMainWindow")) mainWindow = w;
    g_ctx = new QObject(mainWindow ? mainWindow : static_cast<QObject *>(qApp));
    after(1000, [r] { tick(r); });
}

} // namespace aiinspector
