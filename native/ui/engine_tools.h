// SPDX-License-Identifier: GPL-2.0-or-later
//
// EngineTools: the capture data the assistant can pull on demand.
//
// Instead of pushing one large JSON blob into the first message, the panel
// declares these tools to the model and answers the calls from the analysis
// engine through the same Host callbacks the rest of the panel uses. Results
// still pass through the panel's privacy pipeline before they leave the
// machine; see InspectorPanel::send().
//
// Nothing here talks to Wireshark directly, so tests can drive it with a fake
// Host.
#pragma once

#include "ai_client.h"
#include "panel.h"

namespace aiinspector {

class EngineTools {
public:
    explicit EngineTools(const Host *host) : host_(host) {}

    // Declarations sent to the provider.
    static QVector<ToolSpec> specs();

    // Runs one call. Never throws; failures come back as ToolResult::isError.
    ToolResult run(const ToolCall &call) const;

    // The selected packet's decoded tree is only returned when the privacy
    // setting allows it; the panel keeps this in step with Settings.
    void setIncludePacketTree(bool include) { includePacketTree_ = include; }
    // Upper bound for findings returned by one get_findings call.
    void setMaxFindings(int max) { maxFindings_ = max; }

private:
    ToolResult findings(const QJsonObject &args) const;
    ToolResult captureSummary(const QJsonObject &args) const;
    ToolResult frameFindings(const QJsonObject &args) const;
    ToolResult selectedPacket() const;
    ToolResult report() const;
    ToolResult validateFilter(const QJsonObject &args) const;

    const Host *host_;
    bool includePacketTree_ = true;
    int maxFindings_ = 60;
};

} // namespace aiinspector
