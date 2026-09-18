// SPDX-License-Identifier: GPL-2.0-or-later
#include "engine_tools.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace aiinspector {

namespace {

constexpr int MAX_TREE_CHARS = 20000;
constexpr int MAX_REPORT_CHARS = 40000;

QJsonObject obj(std::initializer_list<QPair<QString, QJsonValue>> kv) {
    QJsonObject o;
    for (const auto &p : kv) o.insert(p.first, p.second);
    return o;
}

QJsonObject schema(const QJsonObject &properties, const QStringList &required = {}) {
    QJsonObject s{{QStringLiteral("type"), QStringLiteral("object")},
                  {QStringLiteral("properties"), properties}};
    if (!required.isEmpty()) s.insert(QStringLiteral("required"), QJsonArray::fromStringList(required));
    return s;
}

QJsonObject prop(const QString &type, const QString &description) {
    return obj({{QStringLiteral("type"), type}, {QStringLiteral("description"), description}});
}

ToolResult ok(const QJsonValue &value) {
    ToolResult r;
    r.content = QString::fromUtf8(QJsonDocument(value.isArray() ? QJsonDocument(value.toArray())
                                                                : QJsonDocument(value.toObject()))
                                      .toJson(QJsonDocument::Compact));
    return r;
}

ToolResult okText(const QString &text) {
    ToolResult r;
    r.content = text;
    return r;
}

ToolResult fail(const QString &why) {
    ToolResult r;
    r.isError = true;
    r.content = why;
    return r;
}

int severityLevel(const QString &name) {
    const QString n = name.trimmed().toLower();
    if (n.startsWith(QLatin1String("err"))) return 4;
    if (n.startsWith(QLatin1String("warn"))) return 3;
    if (n.startsWith(QLatin1String("note"))) return 2;
    if (n.startsWith(QLatin1String("info"))) return 1;
    return 0;
}

} // namespace

QVector<ToolSpec> EngineTools::specs() {
    QVector<ToolSpec> t;
    t.append({QStringLiteral("get_findings"),
              QStringLiteral("Findings from the analysis engine, newest analysis of the open capture. Filter by "
                             "severity, category, protocol or text and page through them. Returns id, severity, "
                             "category, protocol, title, count, first_frame, last_frame, display filter and example "
                             "values."),
              schema(obj({{QStringLiteral("min_severity"),
                           prop(QStringLiteral("string"), QStringLiteral("Lowest severity to return: info, note, warning or error."))},
                          {QStringLiteral("category"),
                           prop(QStringLiteral("string"), QStringLiteral("Only findings in this category (e.g. security, performance, protocol)."))},
                          {QStringLiteral("protocol"),
                           prop(QStringLiteral("string"), QStringLiteral("Only findings for this protocol (e.g. tls, dns, tcp)."))},
                          {QStringLiteral("contains"),
                           prop(QStringLiteral("string"), QStringLiteral("Only findings whose id, title or detail contains this text."))},
                          {QStringLiteral("limit"),
                           prop(QStringLiteral("integer"), QStringLiteral("Maximum findings to return (default 25)."))},
                          {QStringLiteral("offset"),
                           prop(QStringLiteral("integer"), QStringLiteral("Skip this many matching findings (for paging)."))}}))});
    t.append({QStringLiteral("get_capture_summary"),
              QStringLiteral("Capture-level context: frames analyzed, duration, severity totals, protocol counts, "
                             "categories, the findings timeline, top hosts and the inventory (SNI, JA3/JA4, user "
                             "agents, certificates). Findings themselves come from get_findings."),
              schema(obj({{QStringLiteral("include_findings"),
                           prop(QStringLiteral("boolean"), QStringLiteral("Also include the findings array (default false; prefer get_findings)."))}}))});
    t.append({QStringLiteral("get_frame_findings"),
              QStringLiteral("Findings the engine recorded for one frame."),
              schema(obj({{QStringLiteral("frame"), prop(QStringLiteral("integer"), QStringLiteral("Frame number."))}}),
                     {QStringLiteral("frame")})});
    t.append({QStringLiteral("get_selected_packet"),
              QStringLiteral("The packet currently selected in the packet list: its frame number, its findings and "
                             "its decoded protocol tree (credential values removed)."),
              schema({})});
    t.append({QStringLiteral("get_report"),
              QStringLiteral("The engine's full plain-text report for the capture."),
              schema({})});
    t.append({QStringLiteral("validate_filter"),
              QStringLiteral("Compiles a Wireshark display filter and reports whether it is valid. Use this before "
                             "putting a filter in the answer."),
              schema(obj({{QStringLiteral("filter"), prop(QStringLiteral("string"), QStringLiteral("The display filter to check."))}}),
                     {QStringLiteral("filter")})});
    return t;
}

ToolResult EngineTools::run(const ToolCall &call) const {
    if (!host_) return fail(QStringLiteral("The analysis engine is not available."));
    const QString &n = call.name;
    if (n == QLatin1String("get_findings")) return findings(call.args);
    if (n == QLatin1String("get_capture_summary")) return captureSummary(call.args);
    if (n == QLatin1String("get_frame_findings")) return frameFindings(call.args);
    if (n == QLatin1String("get_selected_packet")) return selectedPacket();
    if (n == QLatin1String("get_report")) return report();
    if (n == QLatin1String("validate_filter")) return validateFilter(call.args);
    return fail(QStringLiteral("No tool named '%1' is available.").arg(n));
}

ToolResult EngineTools::findings(const QJsonObject &args) const {
    if (!host_->summaryJson) return fail(QStringLiteral("No capture has been analyzed yet."));
    const QJsonObject summary = QJsonDocument::fromJson(host_->summaryJson(0).toUtf8()).object();
    const QJsonArray all = summary.value(QStringLiteral("findings")).toArray();

    const int minSev = severityLevel(args.value(QStringLiteral("min_severity")).toString());
    const QString category = args.value(QStringLiteral("category")).toString().trimmed().toLower();
    const QString protocol = args.value(QStringLiteral("protocol")).toString().trimmed().toLower();
    const QString contains = args.value(QStringLiteral("contains")).toString().trimmed();
    const int offset = qMax(0, args.value(QStringLiteral("offset")).toInt(0));
    const int limit = qBound(1, args.value(QStringLiteral("limit")).toInt(25), maxFindings_);

    QJsonArray out;
    int matched = 0;
    for (const auto &v : all) {
        const QJsonObject f = v.toObject();
        if (minSev && f.value(QStringLiteral("severity_level")).toInt() < minSev) continue;
        if (!category.isEmpty() && f.value(QStringLiteral("category")).toString().toLower() != category) continue;
        if (!protocol.isEmpty() && !f.value(QStringLiteral("protocol")).toString().toLower().contains(protocol)) continue;
        if (!contains.isEmpty()) {
            const QString hay = f.value(QStringLiteral("id")).toString() + QLatin1Char(' ')
                                + f.value(QStringLiteral("title")).toString() + QLatin1Char(' ')
                                + f.value(QStringLiteral("detail")).toString();
            if (!hay.contains(contains, Qt::CaseInsensitive)) continue;
        }
        if (++matched <= offset) continue;
        if (out.size() < limit) out.append(f);
    }
    return ok(obj({{QStringLiteral("matched"), matched},
                   {QStringLiteral("returned"), out.size()},
                   {QStringLiteral("offset"), offset},
                   {QStringLiteral("total_findings"), all.size()},
                   {QStringLiteral("findings"), out}}));
}

ToolResult EngineTools::captureSummary(const QJsonObject &args) const {
    if (!host_->summaryJson) return fail(QStringLiteral("No capture has been analyzed yet."));
    const bool withFindings = args.value(QStringLiteral("include_findings")).toBool(false);
    QJsonObject summary = QJsonDocument::fromJson(
                              host_->summaryJson(withFindings ? static_cast<quint32>(maxFindings_) : 1).toUtf8())
                              .object();
    if (summary.isEmpty()) return fail(QStringLiteral("No capture has been analyzed yet."));
    if (!withFindings) {
        const int total = summary.value(QStringLiteral("findings")).toArray().size();
        summary.remove(QStringLiteral("findings"));
        summary.insert(QStringLiteral("findings_note"),
                       QStringLiteral("Findings omitted (%1 shown here); call get_findings for them.").arg(total));
    }
    return ok(summary);
}

ToolResult EngineTools::frameFindings(const QJsonObject &args) const {
    const QJsonValue f = args.value(QStringLiteral("frame"));
    const quint32 frame = static_cast<quint32>(f.toVariant().toUInt());
    if (frame == 0) return fail(QStringLiteral("Pass a frame number greater than zero."));
    if (!host_->frameFindingsJson) return fail(QStringLiteral("Per-frame findings are not available."));
    const QString json = host_->frameFindingsJson(frame);
    return okText(json.trimmed().isEmpty() ? QStringLiteral("[]") : json);
}

ToolResult EngineTools::selectedPacket() const {
    const auto pkt = host_->selectedPacket ? host_->selectedPacket() : std::nullopt;
    if (!pkt || pkt->frame == 0) return fail(QStringLiteral("No packet is selected in the packet list."));
    QString tree = includePacketTree_ ? pkt->tree : QStringLiteral("(packet tree omitted by the analyst's privacy setting)");
    if (tree.size() > MAX_TREE_CHARS) tree = tree.left(MAX_TREE_CHARS) + QStringLiteral("\n... (truncated)");
    return okText(QStringLiteral("Frame %1\n\nFindings (JSON):\n%2\n\nDecoded tree:\n%3")
                      .arg(pkt->frame)
                      .arg(pkt->findingsJson.isEmpty() ? QStringLiteral("[]") : pkt->findingsJson, tree));
}

ToolResult EngineTools::report() const {
    if (!host_->reportText) return fail(QStringLiteral("No capture has been analyzed yet."));
    QString text = host_->reportText();
    if (text.size() > MAX_REPORT_CHARS) text = text.left(MAX_REPORT_CHARS) + QStringLiteral("\n... (truncated)");
    return okText(text);
}

ToolResult EngineTools::validateFilter(const QJsonObject &args) const {
    const QString filter = args.value(QStringLiteral("filter")).toString().trimmed();
    if (filter.isEmpty()) return fail(QStringLiteral("Pass a display filter to check."));
    if (!host_->validateFilter)
        return ok(obj({{QStringLiteral("filter"), filter},
                       {QStringLiteral("valid"), QJsonValue::Null},
                       {QStringLiteral("reason"), QStringLiteral("Wireshark's filter compiler is not available here.")}}));
    QString error;
    const bool valid = host_->validateFilter(filter, &error);
    return ok(obj({{QStringLiteral("filter"), filter},
                   {QStringLiteral("valid"), valid},
                   {QStringLiteral("reason"), valid ? QString() : error}}));
}

} // namespace aiinspector
