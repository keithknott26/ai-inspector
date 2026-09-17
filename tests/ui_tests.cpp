// SPDX-License-Identifier: GPL-2.0-or-later
// Qt tests for the UI plugin components that do not require Wireshark:
// AI client (against a local mock server), redaction, settings and panel.
#include "ai_client.h"
#include "charts.h"
#include "chat_view.h"
#include "dashboard.h"
#include "panel.h"
#include "redactor.h"
#include "settings.h"

#include <QDockWidget>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QPlainTextEdit>
#include <QProcess>
#include <QRegularExpression>
#include <QPushButton>
#include <QSignalSpy>
#include <QSettings>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTest>
#include <QTextBrowser>
#include <QTreeWidget>

using namespace aiinspector;

class UiTests : public QObject {
    Q_OBJECT
    QProcess server_;
    QTemporaryDir tmp_;
    int port_ = 0;

    QString url(const QString &path) const { return QStringLiteral("http://127.0.0.1:%1%2").arg(port_).arg(path); }
    QList<QJsonObject> loggedRequests() const {
        QList<QJsonObject> out;
        QFile f(tmp_.filePath(QStringLiteral("mock.log")));
        if (!f.open(QIODevice::ReadOnly)) return out;
        for (const QByteArray &line : f.readAll().split('\n'))
            if (!line.trimmed().isEmpty()) out << QJsonDocument::fromJson(line).object();
        return out;
    }
    static bool waitFor(AiClient &c, QString &text, QString &error, int ms = 15000) {
        QSignalSpy ok(&c, &AiClient::finished), bad(&c, &AiClient::failed);
        QElapsedTimer t;
        t.start();
        while (ok.isEmpty() && bad.isEmpty() && t.elapsed() < ms) QTest::qWait(20);
        if (!ok.isEmpty()) { text = ok.first().first().toString(); return true; }
        if (!bad.isEmpty()) error = bad.first().first().toString();
        return false;
    }

private slots:
    void initTestCase() {
        QVERIFY(tmp_.isValid());
        qputenv("HOME", tmp_.path().toUtf8());
        qputenv("XDG_CONFIG_HOME", tmp_.filePath(QStringLiteral("config")).toUtf8());
        qunsetenv("AI_INSPECTOR_API_KEY");
        qunsetenv("ANTHROPIC_API_KEY");
        qunsetenv("OPENAI_API_KEY");
        QStandardPaths::setTestModeEnabled(true);
        // On macOS QSettings' native format is CFPreferences, which ignores HOME and
        // would read (and overwrite) the developer's real AI Inspector preferences.
        QSettings::setDefaultFormat(QSettings::IniFormat);
        const QString script = QStringLiteral(AI_INSPECTOR_TESTS_DIR "/mock_ai_server.py");
        const QString portFile = tmp_.filePath(QStringLiteral("port"));
        server_.start(QStringLiteral(AI_INSPECTOR_PYTHON), {script, QStringLiteral("--log"), tmp_.filePath(QStringLiteral("mock.log")),
                                                  QStringLiteral("--port-file"), portFile});
        QVERIFY2(server_.waitForStarted(), qPrintable(QStringLiteral("could not start %1: %2").arg(QStringLiteral(AI_INSPECTOR_PYTHON), server_.errorString())));
        QTRY_VERIFY_WITH_TIMEOUT(QFile::exists(portFile) && QFile(portFile).size() > 0, 10000);
        QFile pf(portFile);
        QVERIFY(pf.open(QIODevice::ReadOnly));
        port_ = pf.readAll().trimmed().toInt();
        QVERIFY(port_ > 0);
    }
    void cleanupTestCase() {
        server_.kill();
        server_.waitForFinished();
    }

    // ---------------------------------------------------------------- config validation
    void validation() {
        AiConfig c;
        c.provider = Provider::Anthropic;
        QVERIFY(c.validate().contains(QStringLiteral("No API key")));
        c.apiKey = QStringLiteral("sk-ant-abc_123");
        QVERIFY(c.validate().isEmpty());
        QCOMPARE(c.effectiveEndpoint().toString(), QStringLiteral("https://api.anthropic.com/v1/messages"));
        c.endpoint = QStringLiteral("http://api.example.test/v1/messages");
        QVERIFY(c.validate().contains(QStringLiteral("localhost")));
        c.endpoint = QStringLiteral("http://127.0.0.1:1234/v1");
        QVERIFY(c.validate().isEmpty());
        c.endpoint = QStringLiteral("ftp://127.0.0.1/");
        QVERIFY(!c.validate().isEmpty());
        c.endpoint.clear();
        c.apiKey = QStringLiteral("abc\r\nX-Injected: 1");
        QVERIFY(c.validate().contains(QStringLiteral("unexpected characters")));
        c.apiKey = QStringLiteral("k");
        c.model = QStringLiteral("bad model$");
        QVERIFY(c.validate().contains(QStringLiteral("model")));
        AiConfig local;
        local.provider = Provider::OpenAICompatible;
        QVERIFY(local.validate().isEmpty()); // no key needed for local servers
    }

    // ---------------------------------------------------------------- response parsing
    void parsing() {
        QString text, err;
        QVERIFY(AiClient::parseResponse(Provider::Anthropic, 200,
            R"({"content":[{"type":"text","text":"a"},{"type":"tool_use"},{"type":"text","text":"b"}],"stop_reason":"end_turn"})", text, err));
        QCOMPARE(text, QStringLiteral("a\nb"));
        QVERIFY(AiClient::parseResponse(Provider::Anthropic, 200, R"({"content":[{"type":"text","text":"x"}],"stop_reason":"max_tokens"})", text, err));
        QVERIFY(text.contains(QStringLiteral("truncated")));
        QVERIFY(AiClient::parseResponse(Provider::OpenAI, 200, R"({"choices":[{"message":{"content":"hi"},"finish_reason":"stop"}]})", text, err));
        QCOMPARE(text, QStringLiteral("hi"));
        QVERIFY(!AiClient::parseResponse(Provider::OpenAI, 429, R"({"error":{"message":"rate limited"}})", text, err));
        QVERIFY(err.contains(QStringLiteral("429")) && err.contains(QStringLiteral("rate limited")));
        QVERIFY(!AiClient::parseResponse(Provider::Anthropic, 200, "<html>", text, err));
        QVERIFY(err.contains(QStringLiteral("non-JSON")));
        QVERIFY(!AiClient::parseResponse(Provider::OpenAI, 200, R"({"choices":[]})", text, err));
        QVERIFY(err.contains(QStringLiteral("empty")));
        QVERIFY(!AiClient::parseResponse(Provider::Anthropic, 200, R"([1,2])", text, err));
    }

    void autoValuesAndModels() {
        AiConfig c;
        c.provider = Provider::Anthropic;
        QCOMPARE(c.effectiveTimeoutSeconds(), AiConfig::autoTimeoutSeconds(Provider::Anthropic));
        QCOMPARE(c.effectiveMaxTokens(), AiConfig::autoMaxTokens(Provider::Anthropic));
        c.timeoutSeconds = 2;
        QCOMPARE(c.effectiveTimeoutSeconds(), 5);
        QVERIFY(!c.validate().contains(QStringLiteral("timeout")));
        QCOMPARE(AiConfig::apiKeyEnvVar(Provider::OpenAI), QStringLiteral("OPENAI_API_KEY"));
        QCOMPARE(c.modelsUrl().toString(), QStringLiteral("https://api.anthropic.com/v1/models"));
        c.provider = Provider::OpenAICompatible;
        c.endpoint = QStringLiteral("http://localhost:11434/v1/chat/completions?x=1");
        QCOMPARE(c.modelsUrl().toString(), QStringLiteral("http://localhost:11434/v1/models"));
        QVERIFY(AiConfig::autoTimeoutSeconds(Provider::OpenAICompatible) > AiConfig::autoTimeoutSeconds(Provider::OpenAI));
        const QStringList oa = AiClient::parseModelList(Provider::OpenAI,
            R"({"data":[{"id":"gpt-4.1"},{"id":"text-embedding-3-small"},{"id":"o4-mini"},{"id":"whisper-1"},{"id":"gpt-4o-audio-preview"}]})");
        QCOMPARE(oa, (QStringList{QStringLiteral("gpt-4.1"), QStringLiteral("o4-mini")}));
        const QStringList an = AiClient::parseModelList(Provider::Anthropic, R"({"data":[{"id":"claude-b"},{"id":"claude-a"}]})");
        QCOMPARE(an, (QStringList{QStringLiteral("claude-b"), QStringLiteral("claude-a")}));
        QCOMPARE(AiClient::parseModelList(Provider::OpenAICompatible, R"({"models":[{"name":"llama3.1:8b"}]})"),
                 QStringList{QStringLiteral("llama3.1:8b")});
        QVERIFY(AiClient::parseModelList(Provider::OpenAI, "not json").isEmpty());
        QVERIFY(UiSettings::isEnvVarName(QStringLiteral("ANTHROPIC_API_KEY")));
        QVERIFY(UiSettings::isEnvVarName(QStringLiteral("$MY_KEY")));
        QVERIFY(!UiSettings::isEnvVarName(QStringLiteral("sk-ant-api03-abc")));
        UiSettings u;
        u.ai.provider = Provider::OpenAICompatible;
        QCOMPARE(u.effectiveMaxFindings(), UiSettings::autoMaxFindings(Provider::OpenAICompatible));
        u.maxFindings = 1000;
        QCOMPARE(u.effectiveMaxFindings(), 500);
    }

    void keyFromNamedVariable() {
        const QString keyFile = tmp_.filePath(QStringLiteral("keys2/api_key"));
        qputenv("AI_INSPECTOR_KEY_FILE", keyFile.toUtf8());
        UiSettings u = UiSettings::load(false);
        u.ai.provider = Provider::OpenAI;
        u.keyEnvVar = QStringLiteral("MY_TEAM_OPENAI_KEY");
        u.save();
        qputenv("MY_TEAM_OPENAI_KEY", "team-key");
        const UiSettings v = UiSettings::load();
        QCOMPARE(v.keyEnvVar, QStringLiteral("MY_TEAM_OPENAI_KEY"));
        QCOMPARE(v.ai.apiKey, QStringLiteral("team-key"));
        QVERIFY(v.keySource.contains(QStringLiteral("MY_TEAM_OPENAI_KEY")));
        qunsetenv("MY_TEAM_OPENAI_KEY");
        u.keyEnvVar.clear();
        u.save();
        QVERIFY(UiSettings::load().keyEnvVar.isEmpty());
        qunsetenv("AI_INSPECTOR_KEY_FILE");
    }

    void requestBody() {
        AiConfig c;
        c.provider = Provider::OpenAI;
        c.maxTokens = 10; // clamped
        QJsonArray msgs{QJsonObject{{QStringLiteral("role"), QStringLiteral("user")}, {QStringLiteral("content"), QStringLiteral("q")}}};
        const QJsonObject o = QJsonDocument::fromJson(AiClient::buildRequestBody(c, msgs)).object();
        QCOMPARE(o.value(QStringLiteral("max_tokens")).toInt(), 256);
        QCOMPARE(o.value(QStringLiteral("messages")).toArray().size(), 2);
        QCOMPARE(o.value(QStringLiteral("messages")).toArray().at(0).toObject().value(QStringLiteral("role")).toString(), QStringLiteral("system"));
        c.provider = Provider::Anthropic;
        const QJsonObject a = QJsonDocument::fromJson(AiClient::buildRequestBody(c, msgs)).object();
        QVERIFY(a.value(QStringLiteral("system")).toString().contains(QStringLiteral("untrusted")));
        QCOMPARE(a.value(QStringLiteral("messages")).toArray().size(), 1);
    }

    // ---------------------------------------------------------------- live requests against the mock
    void anthropicConversation() {
        AiClient client;
        AiConfig c;
        c.provider = Provider::Anthropic;
        c.endpoint = url(QStringLiteral("/anthropic/v1/messages"));
        c.apiKey = QStringLiteral("test-key-123");
        QString text, err;
        client.ask(c, QStringLiteral("first"));
        QVERIFY(client.busy());
        QVERIFY2(waitFor(client, text, err), qPrintable(err));
        QVERIFY2(text.startsWith(QStringLiteral("MOCK-ANTHROPIC turn 1")), qPrintable(text));
        QVERIFY(text.contains(QStringLiteral("```chart")));
        client.ask(c, QStringLiteral("second"));
        QVERIFY2(waitFor(client, text, err), qPrintable(err));
        QVERIFY2(text.startsWith(QStringLiteral("MOCK-ANTHROPIC turn 3")), qPrintable(text));
        QCOMPARE(client.conversationTurns(), 2);
        const QJsonObject last = loggedRequests().last();
        QJsonObject headers;
        const QJsonObject raw = last.value(QStringLiteral("headers")).toObject();
        for (auto it = raw.constBegin(); it != raw.constEnd(); ++it)
            headers.insert(it.key().toLower(), it.value());
        QCOMPARE(headers.value(QStringLiteral("x-api-key")).toString(), QStringLiteral("test-key-123"));
        QCOMPARE(headers.value(QStringLiteral("anthropic-version")).toString(), QStringLiteral("2023-06-01"));
        QVERIFY(!headers.contains(QStringLiteral("authorization")));
        client.resetConversation();
        QCOMPARE(client.conversationTurns(), 0);
    }

    void openaiAndErrors() {
        AiClient client;
        AiConfig c;
        c.provider = Provider::OpenAI;
        c.endpoint = url(QStringLiteral("/openai/v1/chat/completions"));
        c.apiKey = QStringLiteral("sk-test");
        QString text, err;
        client.ask(c, QStringLiteral("hello"));
        QVERIFY2(waitFor(client, text, err), qPrintable(err));
        QVERIFY2(text.startsWith(QStringLiteral("MOCK-OPENAI turn 2")), qPrintable(text));
        const QJsonObject hdr = loggedRequests().last().value(QStringLiteral("headers")).toObject();
        bool bearer = false;
        for (auto it = hdr.constBegin(); it != hdr.constEnd(); ++it)
            if (it.key().toLower() == QLatin1String("authorization")) bearer = it.value().toString() == QLatin1String("Bearer sk-test");
        QVERIFY(bearer);

        c.provider = Provider::Anthropic;
        c.endpoint = url(QStringLiteral("/anthropic/v1/messages"));
        c.apiKey = QStringLiteral("wrong");
        client.ask(c, QStringLiteral("x"));
        QVERIFY(!waitFor(client, text, err));
        QVERIFY2(err.contains(QStringLiteral("401")) && err.contains(QStringLiteral("invalid x-api-key")), qPrintable(err));

        c.endpoint = url(QStringLiteral("/broken"));
        client.ask(c, QStringLiteral("x"));
        QVERIFY(!waitFor(client, text, err));
        QVERIFY2(err.contains(QStringLiteral("non-JSON")), qPrintable(err));

        c.endpoint = url(QStringLiteral("/redirect"));
        client.ask(c, QStringLiteral("x"));
        QVERIFY(!waitFor(client, text, err));
        QVERIFY2(err.contains(QStringLiteral("redirect")), qPrintable(err));

        c.endpoint = QStringLiteral("http://127.0.0.1:1/v1");
        client.ask(c, QStringLiteral("x"));
        QVERIFY(!waitFor(client, text, err));
        QVERIFY2(err.contains(QStringLiteral("Network error")), qPrintable(err));
        QCOMPARE(client.conversationTurns(), 1); // failures don't pollute history
    }

    void timeoutAndCancel() {
        AiClient client;
        AiConfig c;
        c.provider = Provider::OpenAICompatible;
        c.endpoint = url(QStringLiteral("/slow"));
        c.timeoutSeconds = 5;
        QString text, err;
        client.ask(c, QStringLiteral("x"));
        client.ask(c, QStringLiteral("y")); // rejected while busy
        QVERIFY(!waitFor(client, text, err, 1000));
        QVERIFY(err.contains(QStringLiteral("already in progress")));
        err.clear();
        QVERIFY(!waitFor(client, text, err, 12000));
        QVERIFY2(err.contains(QStringLiteral("No response")), qPrintable(err));
        client.ask(c, QStringLiteral("z"));
        QTest::qWait(200);
        QSignalSpy cancelled(&client, &AiClient::failed);
        client.cancel();
        QTRY_COMPARE_WITH_TIMEOUT(cancelled.size(), 1, 5000);
        QVERIFY2(cancelled.first().first().toString().contains(QStringLiteral("cancelled")),
                 qPrintable(cancelled.first().first().toString()));
        QVERIFY(!client.busy());
    }

    void streamingAndNonStreaming() {
        // Streaming delivers incremental deltas; non-streaming returns one body.
        AiClient client;
        AiConfig c;
        c.provider = Provider::OpenAI;
        c.endpoint = url(QStringLiteral("/openai/v1/chat/completions"));
        c.apiKey = QStringLiteral("sk-test");
        QSignalSpy deltas(&client, &AiClient::delta);
        QString text, err;
        client.ask(c, QStringLiteral("stream please"));
        QVERIFY2(waitFor(client, text, err), qPrintable(err));
        QVERIFY(deltas.size() > 3);
        QString joined;
        for (const auto &d : deltas) joined += d.first().toString();
        QCOMPARE(joined, text);
        QVERIFY(QJsonDocument::fromJson(loggedRequests().last().value(QStringLiteral("body")).toString().toUtf8())
                    .object().value(QStringLiteral("stream")).toBool());
        client.resetConversation();
        c.stream = false;
        deltas.clear();
        client.ask(c, QStringLiteral("no stream"));
        QVERIFY2(waitFor(client, text, err), qPrintable(err));
        QCOMPARE(deltas.size(), 0);
        QVERIFY(!QJsonDocument::fromJson(loggedRequests().last().value(QStringLiteral("body")).toString().toUtf8())
                     .object().contains(QStringLiteral("stream")));

        auto ev = AiClient::parseStreamData(Provider::Anthropic,
            R"({"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}})");
        QCOMPARE(ev.text, QStringLiteral("hi"));
        ev = AiClient::parseStreamData(Provider::Anthropic, R"({"type":"message_delta","delta":{"stop_reason":"max_tokens"}})");
        QVERIFY(ev.truncated);
        ev = AiClient::parseStreamData(Provider::Anthropic, R"({"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}})");
        QCOMPARE(ev.error, QStringLiteral("Overloaded"));
        ev = AiClient::parseStreamData(Provider::OpenAI, " [DONE] ");
        QVERIFY(ev.done);
        ev = AiClient::parseStreamData(Provider::OpenAI, R"({"choices":[{"delta":{"content":"x"},"finish_reason":"length"}]})");
        QVERIFY(ev.text == QStringLiteral("x") && ev.truncated);
        ev = AiClient::parseStreamData(Provider::OpenAI, "garbage{");
        QVERIFY(ev.text.isEmpty() && ev.error.isEmpty());
    }

    void chartsAndChat() {
        ChartSpec spec;
        QString err;
        QVERIFY(parseChartSpec(QJsonDocument::fromJson(R"({"type":"hbar","title":"t","labels":["a","b"],"series":[{"name":"n","values":[1,2.5]}]})").object(), spec, &err));
        QCOMPARE(spec.type, ChartSpec::HBar);
        QCOMPARE(spec.total(), 3.5);
        QVERIFY(parseChartSpec(QJsonDocument::fromJson(R"({"type":"pie","labels":["a"],"values":[3]})").object(), spec, &err));
        QVERIFY(!parseChartSpec(QJsonDocument::fromJson(R"({"type":"bar","labels":["a","b"],"series":[{"values":[1]}]})").object(), spec, &err));
        QVERIFY(!parseChartSpec(QJsonDocument::fromJson(R"({"type":"bar","labels":["a"],"series":[{"values":["x"]}]})").object(), spec, &err));
        QVERIFY(!parseChartSpec(QJsonDocument::fromJson(R"({"type":"radar","labels":["a"],"series":[{"values":[1]}]})").object(), spec, &err));
        QVERIFY(!parseChartSpec(QJsonDocument::fromJson(R"({"type":"donut","labels":["a"],"series":[{"values":[-1]}]})").object(), spec, &err));
        QJsonArray many;
        for (int i = 0; i < 100; ++i) many.append(QString::number(i));
        QVERIFY(!parseChartSpec(QJsonObject{{QStringLiteral("type"), QStringLiteral("bar")}, {QStringLiteral("labels"), many}}, spec, &err));
        const Theme theme = Theme::fromPalette(QPalette());
        for (auto type : {ChartSpec::Bar, ChartSpec::HBar, ChartSpec::Donut, ChartSpec::Line, ChartSpec::StackedColumn}) {
            ChartSpec s;
            s.type = type;
            s.title = QStringLiteral("Chart");
            s.labels = {QStringLiteral("x"), QStringLiteral("y"), QStringLiteral("z")};
            s.series = {ChartSeries{QStringLiteral("a"), {1, 0, 3}, QColor()}, ChartSeries{QStringLiteral("b"), {2, 2, 0}, QColor()}};
            const QImage img = renderChart(s, QSize(300, 180), theme, 1.0);
            QVERIFY(!img.isNull());
            ChartWidget w;
            w.setSpec(s);
            w.resize(320, 220);
            QVERIFY(!w.grab().isNull());
        }
        QCOMPARE(formatNumber(12500), QStringLiteral("12.5k"));
        QCOMPARE(formatNumber(0.5), QStringLiteral("0.5"));

        QCOMPARE(ChatView::extractFilters(QStringLiteral("Use `tls.handshake.type == 2` and `ip.addr == 1.2.3.4`, not `rm -rf /` or `x`; `dns`.")),
                 QStringList({QStringLiteral("tls.handshake.type == 2"), QStringLiteral("ip.addr == 1.2.3.4"), QStringLiteral("dns")}));
        // Host names / addresses become real filters; only compiling filters survive.
        const ChatView::FilterValidator fake = [](const QString &f, QString *err) {
            static const QRegularExpression field(QStringLiteral("^(tls|http|dns|ip|ipv6|eth|tcp)(\\.|$)"));
            const bool ok = field.match(f).hasMatch();
            if (!ok && err) *err = QStringLiteral("\"%1\" is not a valid protocol or protocol field.").arg(f);
            return ok;
        };
        QCOMPARE(ChatView::toDisplayFilter(QStringLiteral("shop.example.test"), fake),
                 QStringLiteral("http.host == \"shop.example.test\" || tls.handshake.extensions_server_name == \"shop.example.test\" || dns.qry.name == \"shop.example.test\""));
        QCOMPARE(ChatView::toDisplayFilter(QStringLiteral("10.0.0.5"), fake), QStringLiteral("ip.addr == 10.0.0.5"));
        QCOMPARE(ChatView::toDisplayFilter(QStringLiteral("2001:db8::1"), fake), QStringLiteral("ipv6.addr == 2001:db8::1"));
        QCOMPARE(ChatView::toDisplayFilter(QStringLiteral("aa-bb-cc-dd-ee-ff"), fake), QStringLiteral("eth.addr == aa:bb:cc:dd:ee:ff"));
        QCOMPARE(ChatView::toDisplayFilter(QStringLiteral("tcp.port == 443"), fake), QStringLiteral("tcp.port == 443"));
        QCOMPARE(ChatView::toDisplayFilter(QStringLiteral("IP-3(private)"), fake), QString());
        QCOMPARE(ChatView::toDisplayFilter(QStringLiteral("bogus.field == 1"), fake), QString());
        QVERIFY(ChatView::toDisplayFilter(QStringLiteral("api.example.com"), nullptr).startsWith(QStringLiteral("http.host")));
        QVERIFY(!ChatView::looksLikeFilter(QStringLiteral("<script>alert(1)</script>")));
        QVERIFY(!ChatView::looksLikeFilter(QStringLiteral("hello world")));

        ChatView chat;
        chat.resize(600, 500);
        QSignalSpy filters(&chat, &ChatView::applyFilterRequested), frames(&chat, &ChatView::goToFrameRequested);
        chat.addUser(QStringLiteral("q <b>not bold</b>"));
        chat.beginAssistant();
        chat.appendAssistant(QStringLiteral("## Head\nSee frame 42 and `tcp.port == 443`.\n\n```chart\n{\"type\":\"donut\",\"labels\":[\"a\",\"b\"],"));
        QTest::qWait(150);
        QVERIFY(chat.toPlainText().contains(QStringLiteral("Preparing chart")));
        chat.finishAssistant(QStringLiteral("## Head\nSee frame 42 and `tcp.port == 443`.\n\n```chart\n{\"type\":\"donut\",\"labels\":[\"a\",\"b\"],\"values\":[1,2]}\n```\n<img src=\"http://evil/x.png\">"));
        QCOMPARE(chat.chartCount(), 1);
        QVERIFY(chat.toPlainText().contains(QStringLiteral("<img")));  // raw HTML is shown as text, never interpreted
        QVERIFY(chat.toPlainText().contains(QStringLiteral("<b>not bold</b>")));
        QVERIFY(chat.toHtml().contains(QStringLiteral("wsframe:go?n=42")));
        emit chat.anchorClicked(QUrl(QStringLiteral("wsframe:go?n=42")));
        emit chat.anchorClicked(QUrl(QStringLiteral("wsfilter:") + QString::fromLatin1(QByteArrayLiteral("tcp.port == 443").toHex())));
        emit chat.anchorClicked(QUrl(QStringLiteral("wsfilter:") + QString::fromLatin1(QByteArrayLiteral("<bad>").toHex())));
        emit chat.anchorClicked(QUrl(QStringLiteral("https://example.com/")));
        QCOMPARE(frames.size(), 1);
        QCOMPARE(frames.first().first().toUInt(), 42u);
        QCOMPARE(filters.size(), 1);
        QCOMPARE(filters.first().first().toString(), QStringLiteral("tcp.port == 443"));
        // Hostname chips are converted and validated; invalid filters are rejected with a reason.
        ChatView chat2;
        chat2.resize(600, 400);
        chat2.setFilterValidator(fake);
        Redactor red;
        const QString sent = red.apply(QStringLiteral("10.0.0.5 talked to 8.8.8.8"));
        chat2.setDisplayTransform([&red](const QString &t) { return red.restore(t); });
        QSignalSpy rejected(&chat2, &ChatView::filterRejected), applied(&chat2, &ChatView::applyFilterRequested);
        chat2.beginAssistant();
        chat2.finishAssistant(QStringLiteral("Host `shop.example.test`, `IP-1(private)` and IP-2; bad `bogus.field == 1`."));
        const QString html = chat2.toHtml();
        QVERIFY2(chat2.toPlainText().contains(QStringLiteral("ip.addr == 10.0.0.5")), qPrintable(chat2.toPlainText()));
        QVERIFY(chat2.toPlainText().contains(QStringLiteral("and 8.8.8.8")));
        QVERIFY(chat2.toPlainText().contains(QStringLiteral("dns.qry.name == \"shop.example.test\"")));
        QVERIFY(!chat2.toPlainText().contains(QStringLiteral("\u25b8\u00a0bogus.field")));
        QVERIFY(!html.contains(QString::fromLatin1(QByteArrayLiteral("bogus.field == 1").toHex())));
        emit chat2.anchorClicked(QUrl(QStringLiteral("wsfilter:") + QString::fromLatin1(QByteArrayLiteral("shop.example.test").toHex())));
        QCOMPARE(rejected.size(), 1);
        QVERIFY(rejected.first().at(1).toString().contains(QStringLiteral("not a valid")));
        QCOMPARE(applied.size(), 0);
        QVERIFY(red.restore(QStringLiteral("IP-1 IP-1(private) IP-10 MAC-9")) == QStringLiteral("10.0.0.5 10.0.0.5 IP-10 MAC-9"));
        Q_UNUSED(sent);

        chat.addError(QStringLiteral("boom"));
        QVERIFY(chat.plainTranscript().contains(QStringLiteral("== Error ==")));
    }

    // ---------------------------------------------------------------- redaction / scrubbing
    void redaction() {
        Redactor r;
        const QString out = r.apply(QStringLiteral(
            "src 10.1.2.3 dst 8.8.8.8 again 10.1.2.3 mac aa:bb:cc:dd:ee:ff oui Apple_12:34:56 v6 2001:db8::1 "
            "ll fe80::1%en0 time 12:30:45 ver 1.2.3.4.5 bad 999.1.1.1 hex 0x0301 json \"ip\":\"192.168.1.9\""));
        QVERIFY2(out.contains(QStringLiteral("IP-1(private)")) && out.count(QStringLiteral("IP-1(private)")) == 2, qPrintable(out));
        QVERIFY(out.contains(QStringLiteral("IP-2 ")) && !out.contains(QStringLiteral("8.8.8.8")));
        QVERIFY(out.contains(QStringLiteral("MAC-1")) && !out.contains(QStringLiteral("aa:bb")));
        QVERIFY2(out.contains(QStringLiteral("MAC-2")) && !out.contains(QStringLiteral("Apple_")), qPrintable(out));
        QVERIFY2(out.contains(QStringLiteral("IP6-1")) && !out.contains(QStringLiteral("2001:db8")), qPrintable(out));
        QVERIFY2(!out.contains(QStringLiteral("fe80")), qPrintable(out));
        QVERIFY(out.contains(QStringLiteral("12:30:45")));
        QVERIFY(out.contains(QStringLiteral("999.1.1.1")));
        QVERIFY(out.contains(QStringLiteral("0x0301")));
        QVERIFY2(out.contains(QStringLiteral("\"ip\":\"IP-3(private)\"")), qPrintable(out));
        QCOMPARE(r.apply(QStringLiteral("8.8.8.8")), QStringLiteral("IP-2")); // stable mapping
        r.reset();
        QCOMPARE(r.apply(QStringLiteral("8.8.8.8")), QStringLiteral("IP-1"));

        QVERIFY(isSensitiveField(QStringLiteral("http.authorization")));
        QVERIFY(isSensitiveField(QStringLiteral("ftp.request.arg")));
        QVERIFY(!isSensitiveField(QStringLiteral("tcp.srcport")));

        const QString s = scrubSecrets(QStringLiteral("PASS hunter2\nGET /login?user=bob&password=se%20cret&x=1 token=abc\n"
                                                      "Authorization: Basic YWRtaW46aHVudGVyMg==\nkeep=this"),
                                       {QStringLiteral("hunter2"), QStringLiteral("ab")});
        QVERIFY2(!s.contains(QStringLiteral("hunter2")) && !s.contains(QStringLiteral("se%20cret")), qPrintable(s));
        QVERIFY2(!s.contains(QStringLiteral("YWRtaW46")) && s.contains(QStringLiteral("token=[redacted]")), qPrintable(s));
        QVERIFY(s.contains(QStringLiteral("user=bob")) && s.contains(QStringLiteral("x=1")) && s.contains(QStringLiteral("keep=this")));
    }

    // ---------------------------------------------------------------- settings / key file
    void settingsAndKeyFile() {
        const QString keyFile = tmp_.filePath(QStringLiteral("keys/api_key"));
        qputenv("AI_INSPECTOR_KEY_FILE", keyFile.toUtf8());
        QString err;
        QVERIFY2(UiSettings::storeApiKey(QStringLiteral("  file-key-1  "), &err), qPrintable(err));
        QFile f(keyFile);
        QVERIFY(f.exists());
#ifndef Q_OS_WIN
        QCOMPARE(f.permissions() & (QFile::ReadGroup | QFile::WriteGroup | QFile::ReadOther | QFile::WriteOther), QFileDevice::Permissions());
#endif
        UiSettings u = UiSettings::load();
        QCOMPARE(u.ai.apiKey, QStringLiteral("file-key-1"));
        u.ai.provider = Provider::OpenAI;
        u.ai.model = QStringLiteral("gpt-test");
        u.maxFindings = 1000; // clamped on load
        u.save();
        qputenv("AI_INSPECTOR_MODEL", "env-model");
        UiSettings v = UiSettings::load();
        QCOMPARE(v.ai.provider, Provider::OpenAI);
        QCOMPARE(v.ai.model, QStringLiteral("env-model"));
        QCOMPARE(UiSettings::load(false).ai.model, QStringLiteral("gpt-test")); // env never persisted
        QCOMPARE(v.maxFindings, 500);
        // Anthropic SDK variables apply to the Anthropic provider.
        qunsetenv("AI_INSPECTOR_MODEL");
        u.ai.provider = Provider::Anthropic;
        u.save();
        qputenv("ANTHROPIC_MODEL", "claude-haiku-4-5");
        qputenv("ANTHROPIC_API_KEY", "ant-env-key");
        qputenv("ANTHROPIC_BASE_URL", "https://gateway.example.test/");
        UiSettings a = UiSettings::load();
        QCOMPARE(a.ai.model, QStringLiteral("claude-haiku-4-5"));
        QCOMPARE(a.ai.apiKey, QStringLiteral("ant-env-key"));
        QCOMPARE(a.ai.endpoint, QStringLiteral("https://gateway.example.test/v1/messages"));
        QCOMPARE(UiSettings::load(false).ai.model, QStringLiteral("gpt-test"));
        qunsetenv("ANTHROPIC_MODEL");
        qunsetenv("ANTHROPIC_API_KEY");
        qunsetenv("ANTHROPIC_BASE_URL");
        u.ai.provider = Provider::OpenAI;
        u.save();
        qputenv("OPENAI_API_KEY", "env-key");
        QCOMPARE(UiSettings::load().ai.apiKey, QStringLiteral("env-key"));
        qunsetenv("OPENAI_API_KEY");
        qunsetenv("AI_INSPECTOR_MODEL");
        QVERIFY(UiSettings::storeApiKey(QString(), &err));
        QVERIFY(!QFile::exists(keyFile));
        qunsetenv("AI_INSPECTOR_KEY_FILE");
    }

    // ---------------------------------------------------------------- panel with a fake host
    void panel() {
        quint64 generation = 7;
        quint32 wentTo = 0;
        QString filter;
        const QJsonObject summary{
            {QStringLiteral("capture"), QJsonObject{{QStringLiteral("frames_analyzed"), 120}}},
            {QStringLiteral("severity_totals"), QJsonObject{{QStringLiteral("error"), 1}, {QStringLiteral("warning"), 2},
                                                            {QStringLiteral("note"), 0}, {QStringLiteral("info"), 0}}},
            {QStringLiteral("findings"), QJsonArray{
                QJsonObject{{QStringLiteral("id"), QStringLiteral("tcp.zero_window")}, {QStringLiteral("severity"), QStringLiteral("Warning")},
                            {QStringLiteral("severity_level"), 3}, {QStringLiteral("protocol"), QStringLiteral("TCP")},
                            {QStringLiteral("title"), QStringLiteral("TCP zero window")}, {QStringLiteral("count"), 9},
                            {QStringLiteral("first_frame"), 40}, {QStringLiteral("filter"), QStringLiteral("tcp.analysis.zero_window")}},
                QJsonObject{{QStringLiteral("id"), QStringLiteral("tls.weak_cipher.rc4")}, {QStringLiteral("severity"), QStringLiteral("Error")},
                            {QStringLiteral("severity_level"), 4}, {QStringLiteral("protocol"), QStringLiteral("TLS")},
                            {QStringLiteral("title"), QStringLiteral("Weak cipher")}, {QStringLiteral("count"), 1},
                            {QStringLiteral("first_frame"), 5}, {QStringLiteral("filter"), QStringLiteral("tls.handshake.ciphersuite == 0x0005")}}}}};
        Host host;
        host.engineAvailable = [] { return true; };
        host.generation = [&] { return generation; };
        host.summaryJson = [&](quint32) { return QString::fromUtf8(QJsonDocument(summary).toJson(QJsonDocument::Compact)); };
        host.reportText = [] { return QStringLiteral("REPORT"); };
        host.selectedPacket = [] { return std::optional<SelectedPacket>(SelectedPacket{5, QStringLiteral("Frame 5\n  src 10.0.0.5\n  PASS x"), QStringLiteral("[]")}); };
        host.goToFrame = [&](quint32 f) { wentTo = f; };
        host.applyFilter = [&](const QString &f) { filter = f; };

        QMainWindow window;
        QDockWidget *dock = showDock(&window, host);
        QVERIFY(dock);
        QCOMPARE(showDock(&window, host), dock);
        auto *p = dock->findChild<InspectorPanel *>();
        QVERIFY(p);
        auto *tree = p->findChild<QTreeWidget *>(QStringLiteral("findings"));
        QCOMPARE(tree->topLevelItemCount(), 2);
        QCOMPARE(tree->topLevelItem(0)->text(1), QStringLiteral("TLS")); // sorted by severity, errors first
        QCOMPARE(p->findChild<QPlainTextEdit *>(QStringLiteral("report"))->toPlainText(), QStringLiteral("REPORT"));
        tree->setCurrentItem(tree->topLevelItem(1));
        p->findChild<QPushButton *>(QStringLiteral("goFirst"))->click();
        QCOMPARE(wentTo, quint32(40));
        p->findChild<QPushButton *>(QStringLiteral("applyFilter"))->click();
        QCOMPARE(filter, QStringLiteral("tcp.analysis.zero_window"));

        // Overview dashboard renders KPI cards and charts from the summary.
        QCOMPARE(p->dashboard()->findChild<KpiCard *>(QStringLiteral("kpi_errors"))->value(), QStringLiteral("1"));
        QVERIFY(p->dashboard()->chart(QStringLiteral("chartSeverity"))->spec().total() >= 3);
        QSignalSpy sevClicks(p->dashboard(), &Dashboard::severityClicked);
        emit p->dashboard()->chart(QStringLiteral("chartSeverity"))->itemClicked(0);
        QCOMPARE(sevClicks.size(), 1);
        QCOMPARE(p->findChild<QComboBox *>(QStringLiteral("severityFilter"))->currentData().toInt(), 4);
        int visible = 0;
        for (int i = 0; i < tree->topLevelItemCount(); ++i) visible += tree->topLevelItem(i)->isHidden() ? 0 : 1;
        QCOMPARE(visible, 1);
        p->findChild<QComboBox *>(QStringLiteral("severityFilter"))->setCurrentIndex(0);
        p->findChild<QLineEdit *>(QStringLiteral("findingSearch"))->setText(QStringLiteral("zero window"));
        visible = 0;
        for (int i = 0; i < tree->topLevelItemCount(); ++i) visible += tree->topLevelItem(i)->isHidden() ? 0 : 1;
        QCOMPARE(visible, 1);
        p->findChild<QLineEdit *>(QStringLiteral("findingSearch"))->clear();
        tree->setCurrentItem(tree->topLevelItem(1));

        // A capture change must not replay actions from stale findings.
        generation = 8;
        wentTo = 0;
        tree->setCurrentItem(tree->topLevelItem(0));
        p->findChild<QPushButton *>(QStringLiteral("goFirst"))->click();
        QCOMPARE(wentTo, quint32(0));

        // End-to-end AI flow through the panel against the mock (redaction on).
        {
            UiSettings s = UiSettings::load(false);
            s.redact = true;
            s.includePacketTree = true;
            s.save();
        }
        qputenv("AI_INSPECTOR_PROVIDER", "compatible");
        qputenv("AI_INSPECTOR_ENDPOINT", url(QStringLiteral("/openai/v1/chat/completions")).toUtf8());
        const int before = loggedRequests().size();
        p->explainSelectedPacket();
        QTRY_VERIFY_WITH_TIMEOUT(!p->client()->busy(), 10000);
        QTRY_VERIFY(p->findChild<QTextBrowser *>(QStringLiteral("transcript"))->toPlainText().contains(QStringLiteral("MOCK-OPENAI")));
        const auto reqs = loggedRequests();
        QCOMPARE(reqs.size(), before + 1);
        const QString body = reqs.last().value(QStringLiteral("body")).toString();
        QVERIFY2(!body.contains(QStringLiteral("10.0.0.5")) && body.contains(QStringLiteral("IP-1(private)")), qPrintable(body.left(400)));
        p->findChild<QLineEdit *>(QStringLiteral("question"))->setText(QStringLiteral("and then?"));
        p->askQuestion();
        QTRY_VERIFY_WITH_TIMEOUT(!p->client()->busy(), 10000);
        QCOMPARE(p->client()->conversationTurns(), 2);
        qunsetenv("AI_INSPECTOR_PROVIDER");
        qunsetenv("AI_INSPECTOR_ENDPOINT");

        // Engine missing: panel explains instead of failing silently.
        Host none = host;
        none.engineAvailable = [] { return false; };
        InspectorPanel missing(none);
        QVERIFY(missing.findChild<QLabel *>(QStringLiteral("summary"))->text().contains(QStringLiteral("not loaded")));
        QVERIFY(!missing.findChild<QPushButton *>(QStringLiteral("triage"))->isEnabled());
    }
};

QTEST_MAIN(UiTests)
#include "ui_tests.moc"
