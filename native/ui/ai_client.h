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
#include <QTimer>
#include <QUrl>

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

    // Exposed for tests.
    static bool parseResponse(Provider provider, int httpStatus, const QByteArray &body, QString &text, QString &error);
    static QByteArray buildRequestBody(const AiConfig &config, const QJsonArray &messages);
    struct StreamEvent {
        QString text;
        QString error;
        bool truncated = false;
        bool done = false;
    };
    // Parses one SSE "data:" payload.
    static StreamEvent parseStreamData(Provider provider, const QByteArray &data);
    // Parses a GET /models response ({"data":[{"id":...}]} or Ollama {"models":[{"name":...}]}).
    static QStringList parseModelList(Provider provider, const QByteArray &body);

signals:
    void delta(const QString &text);
    void finished(const QString &text);
    void failed(const QString &error);

private:
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
    QString pendingUser_;
    Provider pendingProvider_ = Provider::Anthropic;
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
