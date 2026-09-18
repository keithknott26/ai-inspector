// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <QByteArray>
#include <QElapsedTimer>
#include <QJsonArray>
#include <QNetworkAccessManager>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QStringList>
#include <QJsonObject>
#include <QMap>
#include <QTimer>
#include <QUrl>
#include <QVector>

#include <functional>

class QNetworkReply;

namespace aiinspector {

enum class Provider { Anthropic = 0, OpenAI = 1, OpenAICompatible = 2 };

struct AiConfig {
    Provider provider = Provider::Anthropic;
    QString model;         // blank = provider default
    QString endpoint;      // blank = provider default
    QString apiKey;
    int timeoutSeconds = 0; // maximum silence (no bytes received) before failing; 0 = auto
    int maxTokens = 0;      // 0 = auto (provider-appropriate default)
    bool stream = true;

    QString effectiveModel() const;
    QUrl effectiveEndpoint() const;
    int effectiveTimeoutSeconds() const;
    int effectiveMaxTokens() const;
    static int autoTimeoutSeconds(Provider p);
    static int autoMaxTokens(Provider p);
    // Environment variable conventionally holding this provider's key (e.g. ANTHROPIC_API_KEY).
    static QString apiKeyEnvVar(Provider p);
    // URL of the provider's model list (GET), derived from the effective endpoint.
    QUrl modelsUrl() const;
    // A few well-known model ids shown before (or instead of) the live list.
    static QStringList suggestedModels(Provider p);
    // Empty string when valid, otherwise a user-facing reason.
    QString validate() const;
    static QString defaultModel(Provider p);
    static QString defaultEndpoint(Provider p);
    static QString providerName(Provider p);
};

// ------------------------------------------------------------------ tool use
// The assistant can pull more capture data on demand instead of receiving one
// large JSON blob up front. Tools are declared by the panel and executed by its
// handler, which reads them from the engine and applies the same privacy
// pipeline as any other text sent to the provider.

// Declaration sent to the provider.
struct ToolSpec {
    QString name;
    QString description;
    QJsonObject schema; // JSON Schema object describing the arguments
};

// One request from the model.
struct ToolCall {
    QString id;
    QString name;
    QJsonObject args;
};

// What the handler hands back.
struct ToolResult {
    QString content;
    bool isError = false;
};

// Asynchronous, streaming chat client for Anthropic Messages, OpenAI Chat
// Completions and OpenAI-compatible servers. One request at a time; keeps a
// bounded conversation so follow-up questions have context.
class AiClient : public QObject {
    Q_OBJECT
public:
    explicit AiClient(QObject *parent = nullptr);
    ~AiClient() override;

    static QString systemPrompt();

    bool busy() const { return !reply_.isNull(); }
    qint64 elapsedMs() const { return busy() ? elapsed_.elapsed() : 0; }
    void resetConversation();
    int conversationTurns() const { return static_cast<int>(history_.size() / 2); }

    // Starts a request. Emits delta() while text streams in, then finished()
    // or failed() exactly once.
    void ask(const AiConfig &config, const QString &userMessage);
    void cancel();

    // Tools the model may call. The handler runs on this thread and must
    // return quickly; it is called at most maxToolRounds() times per request.
    void setTools(QVector<ToolSpec> tools, std::function<ToolResult(const ToolCall &)> handler);
    void clearTools();
    bool toolsEnabled() const { return !tools_.isEmpty() && static_cast<bool>(toolHandler_); }
    int maxToolRounds() const { return maxToolRounds_; }
    void setMaxToolRounds(int rounds) { maxToolRounds_ = qBound(1, rounds, 20); }

    // Exposed for tests.
    static bool parseResponse(Provider provider, int httpStatus, const QByteArray &body, QString &text, QString &error);
    static QByteArray buildRequestBody(const AiConfig &config, const QJsonArray &messages,
                                       const QVector<ToolSpec> &tools = {});
    // Tool calls in a complete (non-streaming) response body.
    static QVector<ToolCall> parseToolCalls(Provider provider, const QByteArray &body);
    // The assistant turn to replay in the next round, and the matching results.
    static QJsonObject assistantToolMessage(Provider provider, const QString &text, const QVector<ToolCall> &calls);
    static QJsonArray toolResultMessages(Provider provider, const QVector<ToolCall> &calls,
                                         const QVector<ToolResult> &results);
    // Partial tool call arriving over SSE; index identifies the call in the turn.
    struct ToolDelta {
        int index = -1;
        QString id;
        QString name;
        QString argsFragment;
    };
    struct StreamEvent {
        QString text;
        QString error;
        bool truncated = false;
        bool done = false;
        QVector<ToolDelta> toolDeltas;
    };
    // Parses one SSE "data:" payload.
    static StreamEvent parseStreamData(Provider provider, const QByteArray &data);
    // Parses a GET /models response ({"data":[{"id":...}]} or Ollama {"models":[{"name":...}]}).
    static QStringList parseModelList(Provider provider, const QByteArray &body);

signals:
    void delta(const QString &text);
    void finished(const QString &text);
    void failed(const QString &error);
    // Emitted when the model asks for capture data, before the handler runs.
    void toolCall(const QString &name, const QString &arguments);

private:
    void sendRound();
    bool runToolRound(const QVector<ToolCall> &calls);
    void appendTrace(const QString &line);
    void completeTurn(const QString &text);
    void onReadyRead();
    void onReplyFinished();
    void onIdleTimeout();
    void processSseBuffer(bool flush);
    void finishWithError(const QString &error);

    QNetworkAccessManager *nam_;
    QPointer<QNetworkReply> reply_;
    QTimer idle_;
    QElapsedTimer elapsed_;
    QJsonArray history_;
    QJsonArray messages_;   // this turn: history plus tool exchanges
    QString pendingUser_;
    AiConfig pendingConfig_;
    Provider pendingProvider_ = Provider::Anthropic;
    QVector<ToolSpec> tools_;
    std::function<ToolResult(const ToolCall &)> toolHandler_;
    QMap<int, ToolCall> streamTools_;   // accumulating tool calls from SSE
    QMap<int, QString> streamToolArgs_; // raw argument JSON fragments
    QString answer_;        // text accumulated across tool rounds
    int maxToolRounds_ = 6;
    int toolRound_ = 0;
    bool toolsExhausted_ = false;
    QByteArray body_;       // non-streaming body or error body
    QByteArray sse_;        // unparsed SSE bytes
    QString streamed_;      // text accumulated from stream events
    QString streamError_;
    bool isStream_ = false;
    bool streamTruncated_ = false;
    bool timedOut_ = false;
    bool cancelled_ = false;
};

} // namespace aiinspector
