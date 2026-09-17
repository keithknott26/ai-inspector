// SPDX-License-Identifier: GPL-2.0-or-later
//
// AI Inspector Qt UI plugin: Tools > AI Inspector menu, dock panel,
// and the adapter between Wireshark (plugin_if, taps, capture file) and the
// Qt-only panel code.
//
// How the pieces connect
// ----------------------
//   uiqt_register_ai_inspector()   called by Wireshark after epan_init()
//     - registers the Tools > AI Inspector menu (plugin_if ext_menubar)
//     - registers a listener on the engine's "ai_inspector" tap; the tap record
//       carries the engine API table (ai_inspector_api.h), stored in Controller
//   makeHost()                      adapts Wireshark to aiinspector::Host so the
//                                   panel stays testable without Wireshark
//   openPanel()                     finds the single WiresharkMainWindow and docks
//                                   the InspectorPanel (panel.cpp)
//
// Lifetime rules (important)
// --------------------------
// Wireshark unloads UI plugins before destroying QApplication. Any Qt object or
// callable that lives in this library must therefore be owned by the main
// window (deleted first) or by another object we own. Never use
// QTimer::singleShot(..., qApp, lambda) or qApp-parented objects here: a pending
// timer would run code from an unloaded library at exit (segfault on macOS).
// Use QMetaObject::invokeMethod(ownedObject, ..., Qt::QueuedConnection) instead.
//
// All plugin_if and capture_file access happens on the GUI thread.
#include "config.h"

#include <epan/cfile.h>
#include <epan/dfilter/dfilter.h>
#include <epan/epan_dissect.h>
#include <epan/proto.h>
#include <epan/tap.h>
#include <epan/ftypes/ftypes.h>
#include <wsutil/wmem/wmem.h>
#include <ui/plugins/include/plugin_if.h>

#include "ai_inspector_api.h"
#include "ai_inspector_version.h"
#include "panel.h"
#include "redactor.h"
#include "selftest.h"
#include "settings.h"

#include <QApplication>
#include <QDockWidget>
#include <QMainWindow>
#include <QMessageBox>
#include <QPointer>
#include <QThread>
#include <QTimer>

extern "C" {
void uiqt_register_ai_inspector(void);
}

namespace {

constexpr int MAX_TREE_LINES = 600;
constexpr int MAX_TREE_CHARS = 32000;

struct Controller {
    const ai_inspector_engine_api_t *api = nullptr;
    bool engineLoaded = false;
    bool dirty = false;
    QPointer<QDockWidget> dock;
};

Controller &ctl() {
    static Controller c;
    return c;
}

bool onGuiThread() {
    auto *app = qobject_cast<QApplication *>(QCoreApplication::instance());
    return app && QThread::currentThread() == app->thread();
}

// Exactly one Wireshark main window; refuse ambiguous hosts.
QMainWindow *findHost() {
    QMainWindow *candidate = nullptr;
    for (QWidget *w : QApplication::topLevelWidgets()) {
        if (!w->inherits("WiresharkMainWindow")) continue;
        auto *mw = qobject_cast<QMainWindow *>(w);
        if (!mw) continue;
        if (candidate) return nullptr;
        candidate = mw;
    }
    return candidate;
}

QString takeString(char *s) {
    const ai_inspector_engine_api_t *api = ctl().api;
    if (!s) return {};
    QString out = QString::fromUtf8(s);
    if (api) api->free_string(s);
    return out;
}

// ---------------------------------------------------------------- selected packet tree
struct TreeDump {
    QString text;
    QStringList secrets;
    int lines = 0;
    int depth = 0;
    bool truncated = false;
};

void dumpNode(proto_node *node, void *data) {
    auto *d = static_cast<TreeDump *>(data);
    if (d->truncated) return;
    field_info *fi = PNODE_FINFO(node);
    if (fi && FI_GET_FLAG(fi, FI_HIDDEN)) return;
    bool printed = false;
    if (fi && fi->hfinfo) {
        const QString abbrev = QString::fromUtf8(fi->hfinfo->abbrev);
        if (abbrev.startsWith(QLatin1String("ai_inspector"))) return;
        QString label;
        if (aiinspector::isSensitiveField(abbrev)) {
            label = QString::fromUtf8(fi->hfinfo->name) + QStringLiteral(": [redacted]");
            if (fi->value && fi->hfinfo->type != FT_NONE && fi->hfinfo->type != FT_PROTOCOL) {
                char *repr = fvalue_to_string_repr(nullptr, fi->value, FTREPR_DISPLAY, fi->hfinfo->display);
                if (repr) {
                    d->secrets << QString::fromUtf8(repr);
                    wmem_free(nullptr, repr);
                }
            }
        } else if (fi->rep) {
            label = QString::fromUtf8(fi->rep->representation);
        } else {
            char buf[ITEM_LABEL_LENGTH];
            buf[0] = '\0';
            size_t off = 0;
            proto_item_fill_label(fi, buf, &off);
            label = QString::fromUtf8(buf);
        }
        if (label.size() > 200) label = label.left(197) + QStringLiteral("...");
        d->text += QString(d->depth * 2, QLatin1Char(' ')) + label + QLatin1Char('\n');
        printed = true;
        if (++d->lines >= MAX_TREE_LINES || d->text.size() >= MAX_TREE_CHARS) {
            d->text += QStringLiteral("... (truncated)\n");
            d->truncated = true;
            return;
        }
    }
    if (node->first_child) {
        if (printed) ++d->depth;
        proto_tree_children_foreach(node, dumpNode, d);
        if (printed) --d->depth;
    }
}

struct SelectedResult {
    quint32 frame = 0;
    QString tree;
};

void *extractSelected(capture_file *cf, void *user) {
    auto *res = static_cast<SelectedResult *>(user);
    if (!cf || !cf->current_frame) return nullptr;
    res->frame = cf->current_frame->num;
    if (cf->edt && cf->edt->tree) {
        TreeDump dump;
        proto_tree_children_foreach(cf->edt->tree, dumpNode, &dump);
        // Text-only lines (e.g. "PASS hunter2") repeat secret values; remove them everywhere.
        res->tree = aiinspector::scrubSecrets(dump.text, dump.secrets);
    }
    return res;
}

// ---------------------------------------------------------------- host adapter
aiinspector::Host makeHost() {
    aiinspector::Host h;
    h.engineAvailable = [] { return ctl().engineLoaded; };
    h.generation = [] { return ctl().api ? ctl().api->generation() : quint64(0); };
    h.summaryJson = [](quint32 maxFindings) {
        return ctl().api ? takeString(ctl().api->summary_json(maxFindings)) : QStringLiteral("{}");
    };
    h.reportText = [] {
        return ctl().api ? takeString(ctl().api->report_text())
                         : QStringLiteral("No capture has been analyzed yet. Open or reload a capture file.");
    };
    h.selectedPacket = []() -> std::optional<aiinspector::SelectedPacket> {
        SelectedResult res;
        if (!plugin_if_get_capture_file(extractSelected, &res) || res.frame == 0) return std::nullopt;
        aiinspector::SelectedPacket p;
        p.frame = res.frame;
        p.tree = res.tree;
        if (ctl().api) p.findingsJson = takeString(ctl().api->frame_findings_json(res.frame));
        return p;
    };
    h.validateFilter = [](const QString &filter, QString *error) {
        const QByteArray text = filter.toUtf8();
        dfilter_t *df = nullptr;
        df_error_t *err = nullptr;
        const bool ok = dfilter_compile(text.constData(), &df, &err) && df != nullptr;
        if (!ok && error) *error = err && err->msg ? QString::fromUtf8(err->msg) : QStringLiteral("empty filter");
        if (df) dfilter_free(df);
        if (err) df_error_free(&err);
        return ok;
    };
    h.goToFrame = [](quint32 frame) {
        if (frame > 0) plugin_if_goto_frame(frame);
    };
    h.applyFilter = [](const QString &filter) {
        const QByteArray bytes = filter.toUtf8();
        plugin_if_apply_filter(bytes.constData(), true);
    };
    return h;
}

aiinspector::InspectorPanel *openPanel() {
    if (!onGuiThread()) return nullptr;
    QMainWindow *window = findHost();
    if (!window) {
        QMessageBox::warning(nullptr, QStringLiteral("AI Inspector"),
                             QStringLiteral("Could not identify exactly one Wireshark main window."));
        return nullptr;
    }
    QDockWidget *dock = aiinspector::showDock(window, makeHost());
    ctl().dock = dock;
    return dock ? dock->findChild<aiinspector::InspectorPanel *>() : nullptr;
}

// ---------------------------------------------------------------- tap listener
void tapReset(void *) {
    ctl().dirty = true;
}

tap_packet_status tapPacket(void *, packet_info *, epan_dissect_t *, const void *data, tap_flags_t) {
    const auto *td = static_cast<const ai_inspector_tap_data_t *>(data);
    if (!td || td->abi != AI_INSPECTOR_API_ABI || !td->api || td->api->abi != AI_INSPECTOR_API_ABI) return TAP_PACKET_DONT_REDRAW;
    ctl().api = td->api;
    if (td->first_pass) ctl().dirty = true;
    return TAP_PACKET_DONT_REDRAW;
}

void tapDraw(void *) {
    Controller &c = ctl();
    if (!c.dirty || !c.dock || !c.dock->isVisible()) return;
    c.dirty = false;
    if (auto *panel = c.dock->findChild<aiinspector::InspectorPanel *>())
        QMetaObject::invokeMethod(panel, "refresh", Qt::QueuedConnection);
}

// ---------------------------------------------------------------- menu actions
void menuOpen(ext_menubar_gui_type type, void *, void *) {
    if (type != EXT_MENUBAR_QT_GUI) return;
    if (auto *p = openPanel()) p->showOverview();
}
void menuReport(ext_menubar_gui_type type, void *, void *) {
    if (type != EXT_MENUBAR_QT_GUI) return;
    if (auto *p = openPanel()) p->showReport();
}
void menuTriage(ext_menubar_gui_type type, void *, void *) {
    if (type != EXT_MENUBAR_QT_GUI) return;
    if (auto *p = openPanel()) p->runTriage();
}
void menuExplain(ext_menubar_gui_type type, void *, void *) {
    if (type != EXT_MENUBAR_QT_GUI) return;
    if (auto *p = openPanel()) p->explainSelectedPacket();
}
void menuSettings(ext_menubar_gui_type type, void *, void *) {
    if (type != EXT_MENUBAR_QT_GUI || !onGuiThread()) return;
    aiinspector::SettingsDialog dlg(findHost());
    dlg.exec();
}
void menuAbout(ext_menubar_gui_type type, void *, void *) {
    if (type != EXT_MENUBAR_QT_GUI || !onGuiThread()) return;
    const aiinspector::UiSettings s = aiinspector::UiSettings::load();
    QMessageBox::about(findHost(), QStringLiteral("About AI Inspector"),
        QStringLiteral("AI Inspector " AI_INSPECTOR_VERSION "\n\n"
                       "Analysis engine: %1\n"
                       "AI provider: %2 (%3)\n"
                       "API key: %4\n\n"
                       "Display filters: ai_inspector, ai_inspector.severity, ai_inspector.id, ai_inspector.category\n"
                       "TShark: -z ai_inspector,report or -z ai_inspector,json\n\n"
                       "AI output can be wrong; verify conclusions against the packets.")
            .arg(ctl().engineLoaded ? QStringLiteral("loaded") : QStringLiteral("NOT loaded"),
                 aiinspector::AiConfig::providerName(s.ai.provider), s.ai.effectiveModel(),
                 s.ai.apiKey.isEmpty() ? QStringLiteral("not configured") : QStringLiteral("configured")));
}

} // namespace

void uiqt_register_ai_inspector(void) {
    int proto = proto_get_id_by_filter_name("ai_inspector");
    ctl().engineLoaded = proto > 0 && find_tap_id(AI_INSPECTOR_TAP_NAME) > 0;
    if (proto <= 0) proto = proto_register_protocol("AI Inspector UI", "AI_INSPECTOR_UI", "ai_inspector_ui");

    ext_menu_t *menu = ext_menubar_register_menu(proto, "AI Inspector", true);
    ext_menubar_set_parentmenu(menu, "Tools");
    ext_menubar_add_entry(menu, "Open Inspector Panel", "Show the capture overview, findings and the AI assistant", menuOpen, nullptr);
    ext_menubar_add_entry(menu, "Findings Report", "Show the capture findings report", menuReport, nullptr);
    ext_menubar_add_separator(menu);
    ext_menubar_add_entry(menu, "AI Capture Triage", "Ask the AI provider to triage the capture", menuTriage, nullptr);
    ext_menubar_add_entry(menu, "Explain Selected Packet", "Ask the AI provider about the selected packet", menuExplain, nullptr);
    ext_menubar_add_separator(menu);
    ext_menubar_add_entry(menu, "Settings...", "Configure the AI provider and privacy options", menuSettings, nullptr);
    ext_menubar_add_entry(menu, "About AI Inspector", "Version and status", menuAbout, nullptr);

    if (qEnvironmentVariable("AI_INSPECTOR_UI_SELFTEST") == QLatin1String("1"))
        aiinspector::startIntegrationSelfTest(makeHost(), [] { return openPanel(); });

    if (ctl().engineLoaded) {
        static int token;
        GString *err = register_tap_listener(AI_INSPECTOR_TAP_NAME, &token, nullptr, TL_REQUIRES_NOTHING, tapReset, tapPacket, tapDraw, nullptr);
        if (err) {
            g_string_free(err, true);
            ctl().engineLoaded = false;
        }
    }
}
