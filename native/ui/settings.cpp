// SPDX-License-Identifier: GPL-2.0-or-later
#include "settings.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSettings>
#include <QSpinBox>
#include <QStandardPaths>
#include <QToolButton>
#include <QVBoxLayout>

namespace aiinspector {

namespace {
QSettings store() {
    return QSettings(QStringLiteral("AI-Inspector"), QStringLiteral("AIInspector"));
}

// Returns the key from the standard environment variables and sets *name to the variable used.
QString envKey(Provider p, QString *name) {
    const QStringList vars = p == Provider::Anthropic ? QStringList{QStringLiteral("AI_INSPECTOR_API_KEY"), QStringLiteral("ANTHROPIC_API_KEY")}
                           : p == Provider::OpenAI    ? QStringList{QStringLiteral("AI_INSPECTOR_API_KEY"), QStringLiteral("OPENAI_API_KEY")}
                                                      : QStringList{QStringLiteral("AI_INSPECTOR_API_KEY")};
    for (const auto &v : vars) {
        const QString k = qEnvironmentVariable(v.toLatin1().constData()).trimmed();
        if (!k.isEmpty()) {
            if (name) *name = v;
            return k;
        }
    }
    return {};
}

int clampOrAuto(int v, int lo, int hi) {
    return v <= 0 ? 0 : qBound(lo, v, hi);
}
} // namespace

QString UiSettings::keyFilePath() {
    const QString override = qEnvironmentVariable("AI_INSPECTOR_KEY_FILE");
    if (!override.isEmpty()) return override;
#ifdef Q_OS_WIN
    // %APPDATA%\AI-Inspector\api_key (fixed; not derived from the host app's Qt names)
    QString base = qEnvironmentVariable("APPDATA");
    if (base.isEmpty()) base = QDir::home().filePath(QStringLiteral("AppData/Roaming"));
    return QDir(base).filePath(QStringLiteral("AI-Inspector/api_key"));
#else
    return QDir::home().filePath(QStringLiteral(".config/ai-inspector/api_key"));
#endif
}

bool UiSettings::storeApiKey(const QString &key, QString *error) {
    const QString path = keyFilePath();
    if (key.trimmed().isEmpty()) {
        if (QFile::exists(path) && !QFile::remove(path)) {
            if (error) *error = QStringLiteral("Could not remove %1").arg(path);
            return false;
        }
        return true;
    }
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile::setPermissions(QFileInfo(path).absolutePath(), QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
    QSaveFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error) *error = f.errorString();
        return false;
    }
    f.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
    f.write(key.trimmed().toUtf8());
    f.write("\n");
    if (!f.commit()) {
        if (error) *error = f.errorString();
        return false;
    }
    QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner);
    return true;
}

bool UiSettings::isEnvVarName(const QString &text) {
    static const QRegularExpression re(QStringLiteral("^\\$?[A-Z_][A-Z0-9_]{2,99}$"));
    return re.match(text.trimmed()).hasMatch();
}

int UiSettings::autoMaxFindings(Provider p) {
    // Local models usually have small context windows.
    return p == Provider::OpenAICompatible ? 25 : 60;
}

int UiSettings::effectiveMaxFindings() const {
    return maxFindings <= 0 ? autoMaxFindings(ai.provider) : qBound(5, maxFindings, 500);
}

UiSettings UiSettings::load(bool applyEnvironment) {
    QSettings s = store();
    UiSettings u;
    u.ai.provider = static_cast<Provider>(qBound(0, s.value(QStringLiteral("ai/provider"), 0).toInt(), 2));
    u.ai.model = s.value(QStringLiteral("ai/model")).toString();
    u.ai.endpoint = s.value(QStringLiteral("ai/endpoint")).toString();
    u.ai.timeoutSeconds = clampOrAuto(s.value(QStringLiteral("ai/timeout"), 0).toInt(), 5, 900);
    u.ai.maxTokens = clampOrAuto(s.value(QStringLiteral("ai/max_tokens"), 0).toInt(), 256, 32000);
    u.redact = s.value(QStringLiteral("privacy/redact"), true).toBool();
    u.includePacketTree = s.value(QStringLiteral("privacy/include_packet_tree"), true).toBool();
    u.useTools = s.value(QStringLiteral("ai/use_tools"), true).toBool();
    u.maxFindings = clampOrAuto(s.value(QStringLiteral("ai/max_findings"), 0).toInt(), 5, 500);
    const QString envName = s.value(QStringLiteral("ai/api_key_env")).toString().trimmed();
    if (isEnvVarName(envName)) u.keyEnvVar = envName.startsWith(QLatin1Char('$')) ? envName.mid(1) : envName;

    // Environment overrides (managed deployments, automated tests).
    const QString envProvider = applyEnvironment ? qEnvironmentVariable("AI_INSPECTOR_PROVIDER").trimmed().toLower() : QString();
    if (envProvider == QLatin1String("anthropic")) u.ai.provider = Provider::Anthropic;
    else if (envProvider == QLatin1String("openai")) u.ai.provider = Provider::OpenAI;
    else if (envProvider == QLatin1String("compatible")) u.ai.provider = Provider::OpenAICompatible;
    if (applyEnvironment && qEnvironmentVariableIsSet("AI_INSPECTOR_ENDPOINT")) u.ai.endpoint = qEnvironmentVariable("AI_INSPECTOR_ENDPOINT").trimmed();
    if (applyEnvironment && u.ai.provider == Provider::Anthropic) {
        // Standard Anthropic SDK variables.
        const QString model = qEnvironmentVariable("ANTHROPIC_MODEL").trimmed();
        if (!model.isEmpty()) u.ai.model = model;
        const QString base = qEnvironmentVariable("ANTHROPIC_BASE_URL").trimmed();
        if (!base.isEmpty() && !qEnvironmentVariableIsSet("AI_INSPECTOR_ENDPOINT")) {
            QString b = base;
            while (b.endsWith(QLatin1Char('/'))) b.chop(1);
            u.ai.endpoint = b.endsWith(QLatin1String("/v1/messages")) ? b : b + QStringLiteral("/v1/messages");
        }
    }
    if (applyEnvironment && qEnvironmentVariableIsSet("AI_INSPECTOR_MODEL")) u.ai.model = qEnvironmentVariable("AI_INSPECTOR_MODEL").trimmed();

    QString usedVar;
    u.ai.apiKey = envKey(u.ai.provider, &usedVar);
    if (u.ai.apiKey.isEmpty() && !u.keyEnvVar.isEmpty()) {
        u.ai.apiKey = qEnvironmentVariable(u.keyEnvVar.toLatin1().constData()).trimmed();
        usedVar = u.keyEnvVar;
    }
    if (!u.ai.apiKey.isEmpty()) {
        u.keySource = QStringLiteral("environment variable %1").arg(usedVar);
    } else {
        QString path = keyFilePath();
#ifndef Q_OS_WIN
        // Key saved before the project was renamed from "Wireshark Assist".
        const QString legacy = QDir::home().filePath(QStringLiteral(".config/wireshark-assist/api_key"));
        if (!QFile::exists(path) && qEnvironmentVariableIsEmpty("AI_INSPECTOR_KEY_FILE") && QFile::exists(legacy)) path = legacy;
#endif
        QFile f(path);
        if (f.size() < 4096 && f.open(QIODevice::ReadOnly)) {
            u.ai.apiKey = QString::fromUtf8(f.readAll()).trimmed();
            if (!u.ai.apiKey.isEmpty()) u.keySource = path;
        }
    }
    return u;
}

void UiSettings::save() const {
    QSettings s = store();
    s.setValue(QStringLiteral("ai/provider"), static_cast<int>(ai.provider));
    s.setValue(QStringLiteral("ai/model"), ai.model.trimmed());
    s.setValue(QStringLiteral("ai/endpoint"), ai.endpoint.trimmed());
    s.setValue(QStringLiteral("ai/timeout"), ai.timeoutSeconds);
    s.setValue(QStringLiteral("ai/max_tokens"), ai.maxTokens);
    s.setValue(QStringLiteral("ai/max_findings"), maxFindings);
    if (keyEnvVar.isEmpty()) s.remove(QStringLiteral("ai/api_key_env"));
    else s.setValue(QStringLiteral("ai/api_key_env"), keyEnvVar);
    s.setValue(QStringLiteral("privacy/redact"), redact);
    s.setValue(QStringLiteral("privacy/include_packet_tree"), includePacketTree);
    s.setValue(QStringLiteral("ai/use_tools"), useTools);
    s.sync();
}

// ---------------------------------------------------------------------------------------
// Settings dialog

namespace {
bool isProviderDefaultEndpoint(const QString &url) {
    const QString t = url.trimmed();
    if (t.isEmpty()) return true;
    for (int i = 0; i < 3; ++i)
        if (t == AiConfig::defaultEndpoint(static_cast<Provider>(i))) return true;
    return false;
}

bool isProviderSuggestedModel(const QString &model) {
    const QString t = model.trimmed();
    if (t.isEmpty()) return true;
    for (int i = 0; i < 3; ++i) {
        const auto p = static_cast<Provider>(i);
        if (t == AiConfig::defaultModel(p) || AiConfig::suggestedModels(p).contains(t)) return true;
    }
    return false;
}

QSpinBox *autoSpin(QWidget *parent, int min, int max, int step, const QString &suffix, int value, const QString &name) {
    auto *sb = new QSpinBox(parent);
    sb->setObjectName(name);
    sb->setRange(0, max);         // 0 shows the "Auto" special text
    sb->setSingleStep(step);
    sb->setSuffix(suffix);
    sb->setValue(value <= 0 ? 0 : qBound(min, value, max));
    sb->setToolTip(QStringLiteral("Set to 0 (Auto) to use a value suited to the selected provider."));
    sb->setMinimumWidth(150);
    return sb;
}
} // namespace

SettingsDialog::SettingsDialog(QWidget *parent) : QDialog(parent), nam_(new QNetworkAccessManager(this)) {
    setWindowTitle(QStringLiteral("AI Inspector Settings"));
    setObjectName(QStringLiteral("aiInspectorSettings"));
    setMinimumWidth(560);
    initial_ = UiSettings::load(false);
    const UiSettings &cur = initial_;
    lastProvider_ = cur.ai.provider;

    auto *form = new QFormLayout;
    form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);

    provider_ = new QComboBox(this);
    provider_->setObjectName(QStringLiteral("provider"));
    for (int i = 0; i < 3; ++i) provider_->addItem(AiConfig::providerName(static_cast<Provider>(i)), i);
    provider_->setCurrentIndex(static_cast<int>(cur.ai.provider));
    form->addRow(QStringLiteral("Provider"), provider_);

    endpoint_ = new QLineEdit(cur.ai.endpoint.trimmed().isEmpty() ? AiConfig::defaultEndpoint(cur.ai.provider) : cur.ai.endpoint, this);
    endpoint_->setObjectName(QStringLiteral("endpoint"));
    endpoint_->setClearButtonEnabled(true);
    form->addRow(QStringLiteral("Endpoint URL"), endpoint_);

    apiKey_ = new QLineEdit(this);
    apiKey_->setObjectName(QStringLiteral("apiKey"));
    apiKey_->setClearButtonEnabled(true);
    if (!cur.keyEnvVar.isEmpty())
        apiKey_->setText(cur.keyEnvVar);
    else if (cur.keySource.isEmpty() || cur.keySource.startsWith(QStringLiteral("environment variable")))
        apiKey_->setText(AiConfig::apiKeyEnvVar(cur.ai.provider)); // default: read the standard variable
    // else: a key is saved in the key file; leave blank to keep it.
    apiKey_->setPlaceholderText(QStringLiteral("Saved key (leave blank to keep)"));
    connect(apiKey_, &QLineEdit::textEdited, this, [this] { keyEdited_ = true; });
    connect(apiKey_, &QLineEdit::textChanged, this, &SettingsDialog::updateKeyInfo);
    form->addRow(QStringLiteral("API key"), apiKey_);
    keyInfo_ = new QLabel(this);
    keyInfo_->setWordWrap(true);
    keyInfo_->setTextFormat(Qt::PlainText);
    keyInfo_->setObjectName(QStringLiteral("keyInfo"));
    form->addRow(QString(), keyInfo_);

    model_ = new QComboBox(this);
    model_->setObjectName(QStringLiteral("model"));
    model_->setEditable(true);
    model_->setInsertPolicy(QComboBox::NoInsert);
    model_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    refreshModels_ = new QToolButton(this);
    refreshModels_->setObjectName(QStringLiteral("refreshModels"));
    refreshModels_->setText(QStringLiteral("Refresh"));
    refreshModels_->setToolTip(QStringLiteral("Load the models available to this key from the provider"));
    auto *modelRow = new QHBoxLayout;
    modelRow->setContentsMargins(0, 0, 0, 0);
    modelRow->addWidget(model_, 1);
    modelRow->addWidget(refreshModels_);
    form->addRow(QStringLiteral("Model"), modelRow);
    modelStatus_ = new QLabel(this);
    modelStatus_->setObjectName(QStringLiteral("modelStatus"));
    modelStatus_->setWordWrap(true);
    modelStatus_->setTextFormat(Qt::PlainText);
    form->addRow(QString(), modelStatus_);
    setModelChoices(AiConfig::suggestedModels(cur.ai.provider));
    model_->setCurrentText(cur.ai.effectiveModel());

    const UiSettings effective = UiSettings::load(true);
    if (effective.ai.model != cur.ai.model || effective.ai.endpoint != cur.ai.endpoint) {
        auto *envNote = new QLabel(QStringLiteral("Environment overrides in effect: model %1, endpoint %2")
                                       .arg(effective.ai.effectiveModel(), effective.ai.effectiveEndpoint().toString()), this);
        envNote->setWordWrap(true);
        envNote->setTextFormat(Qt::PlainText);
        form->addRow(QString(), envNote);
    }

    timeout_ = autoSpin(this, 5, 900, 5, QStringLiteral(" s"), cur.ai.timeoutSeconds, QStringLiteral("timeout"));
    form->addRow(QStringLiteral("Request timeout"), timeout_);
    maxTokens_ = autoSpin(this, 256, 32000, 256, QString(), cur.ai.maxTokens, QStringLiteral("maxTokens"));
    form->addRow(QStringLiteral("Max response tokens"), maxTokens_);
    maxFindings_ = autoSpin(this, 5, 500, 5, QString(), cur.maxFindings, QStringLiteral("maxFindings"));
    form->addRow(QStringLiteral("Findings sent to AI"), maxFindings_);

    redact_ = new QCheckBox(QStringLiteral("Replace IP and MAC addresses with placeholders before sending"), this);
    redact_->setChecked(cur.redact);
    form->addRow(QStringLiteral("Privacy"), redact_);
    packetTree_ = new QCheckBox(QStringLiteral("Include the decoded packet tree when explaining a packet"), this);
    packetTree_->setChecked(cur.includePacketTree);
    form->addRow(QString(), packetTree_);
    useTools_ = new QCheckBox(QStringLiteral("Let the assistant request capture data as it needs it (tool calls)"), this);
    useTools_->setChecked(cur.useTools);
    useTools_->setToolTip(QStringLiteral("The assistant asks the engine for findings, frames and filters instead of "
                                         "receiving one large block up front. Turn this off for models that do not "
                                         "support tool calling."));
    form->addRow(QStringLiteral("Assistant"), useTools_);

    auto *note = new QLabel(QStringLiteral("Findings, protocol statistics and (optionally) one decoded packet are sent to the "
                                           "selected provider, including anything it requests through tool calls. Raw "
                                           "capture bytes are never sent and credential-bearing fields are always removed."), this);
    note->setWordWrap(true);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel | QDialogButtonBox::RestoreDefaults, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &SettingsDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(buttons->button(QDialogButtonBox::RestoreDefaults), &QPushButton::clicked, this, [this] {
        const Provider p = currentProvider();
        endpoint_->setText(AiConfig::defaultEndpoint(p));
        model_->setCurrentText(AiConfig::defaultModel(p));
        timeout_->setValue(0);
        maxTokens_->setValue(0);
        maxFindings_->setValue(0);
        redact_->setChecked(true);
        packetTree_->setChecked(true);
        useTools_->setChecked(true);
        if (UiSettings::isEnvVarName(apiKey_->text()) || apiKey_->text().isEmpty()) apiKey_->setText(AiConfig::apiKeyEnvVar(p));
    });
    connect(provider_, qOverload<int>(&QComboBox::currentIndexChanged), this, &SettingsDialog::providerChanged);
    connect(refreshModels_, &QToolButton::clicked, this, &SettingsDialog::loadModels);
    connect(apiKey_, &QLineEdit::editingFinished, this, &SettingsDialog::loadModels);
    connect(endpoint_, &QLineEdit::editingFinished, this, &SettingsDialog::loadModels);

    auto *layout = new QVBoxLayout(this);
    layout->addLayout(form);
    layout->addWidget(note);
    layout->addWidget(buttons);

    updateAutoLabels();
    updateKeyInfo();
    loadModels();
}

Provider SettingsDialog::currentProvider() const {
    return static_cast<Provider>(provider_->currentIndex());
}

void SettingsDialog::providerChanged() {
    const Provider p = currentProvider();
    const Provider old = lastProvider_;
    lastProvider_ = p;
    // Replace values that were just the previous provider's defaults; keep custom entries.
    if (isProviderDefaultEndpoint(endpoint_->text())) endpoint_->setText(AiConfig::defaultEndpoint(p));
    const QString model = model_->currentText();
    setModelChoices(AiConfig::suggestedModels(p));
    model_->setCurrentText(isProviderSuggestedModel(model) ? AiConfig::defaultModel(p) : model);
    const QString key = apiKey_->text().trimmed();
    if (key.isEmpty() ? initial_.keySource.isEmpty() : key == AiConfig::apiKeyEnvVar(old))
        apiKey_->setText(AiConfig::apiKeyEnvVar(p));
    updateAutoLabels();
    updateKeyInfo();
    loadModels();
}

void SettingsDialog::updateAutoLabels() {
    const Provider p = currentProvider();
    timeout_->setSpecialValueText(QStringLiteral("Auto (%1 s)").arg(AiConfig::autoTimeoutSeconds(p)));
    maxTokens_->setSpecialValueText(QStringLiteral("Auto (%1)").arg(AiConfig::autoMaxTokens(p)));
    maxFindings_->setSpecialValueText(QStringLiteral("Auto (%1)").arg(UiSettings::autoMaxFindings(p)));
}

void SettingsDialog::updateKeyInfo() {
    const QString text = apiKey_->text().trimmed();
    const Provider p = currentProvider();
    if (UiSettings::isEnvVarName(text)) {
        const QString name = text.startsWith(QLatin1Char('$')) ? text.mid(1) : text;
        apiKey_->setEchoMode(QLineEdit::Normal);
        const bool set = !qEnvironmentVariable(name.toLatin1().constData()).trimmed().isEmpty();
        if (!set && p == Provider::OpenAICompatible) {
            keyInfo_->setText(QStringLiteral("Optional: most local servers need no key. If yours does, set %1 or paste the key here.").arg(name));
            return;
        }
        keyInfo_->setText(set ? QStringLiteral("Reads the key from the environment variable %1 (currently set). Only the name is saved.").arg(name)
                              : QStringLiteral("Reads the key from the environment variable %1, which is not set for Wireshark. "
                                               "Set it before starting Wireshark, or paste a key here to save it to %2.")
                                    .arg(name, UiSettings::keyFilePath()));
    } else if (text.isEmpty()) {
        apiKey_->setEchoMode(QLineEdit::Password);
        keyInfo_->setText(initial_.keySource.isEmpty() || initial_.keySource.startsWith(QStringLiteral("environment variable"))
            ? (p == Provider::OpenAICompatible ? QStringLiteral("No key needed for most local servers.")
                                                : QStringLiteral("No key configured. Enter %1 or paste a key.").arg(AiConfig::apiKeyEnvVar(p)))
            : QStringLiteral("Using the key saved in %1.").arg(initial_.keySource));
    } else {
        apiKey_->setEchoMode(QLineEdit::Password);
        keyInfo_->setText(QStringLiteral("The key will be saved to %1 with owner-only permissions.").arg(UiSettings::keyFilePath()));
    }
}

QString SettingsDialog::resolvedKey() const {
    const QString text = apiKey_->text().trimmed();
    if (UiSettings::isEnvVarName(text)) {
        const QString name = text.startsWith(QLatin1Char('$')) ? text.mid(1) : text;
        const QString k = qEnvironmentVariable(name.toLatin1().constData()).trimmed();
        if (!k.isEmpty()) return k;
    } else if (!text.isEmpty()) {
        return text;
    }
    QString unused;
    const QString env = envKey(currentProvider(), &unused);
    if (!env.isEmpty()) return env;
    return initial_.keySource.startsWith(QStringLiteral("environment variable")) ? QString() : initial_.ai.apiKey;
}

void SettingsDialog::setModelChoices(const QStringList &models) {
    const QString text = model_->currentText();
    model_->blockSignals(true);
    model_->clear();
    model_->addItems(models);
    model_->setCurrentText(text);
    model_->blockSignals(false);
}

void SettingsDialog::loadModels() {
    if (modelsReply_) modelsReply_->abort();
    AiConfig c;
    c.provider = currentProvider();
    c.endpoint = endpoint_->text().trimmed();
    c.apiKey = resolvedKey();
    const QUrl url = c.modelsUrl();
    if (!url.isValid() || url.host().isEmpty()) {
        modelStatus_->setText(QStringLiteral("Enter a valid endpoint URL to load the model list."));
        return;
    }
    if (c.provider != Provider::OpenAICompatible && c.apiKey.isEmpty()) {
        modelStatus_->setText(QStringLiteral("Showing common models. Add an API key to load the full list."));
        return;
    }
    const QString invalid = c.validate();
    if (!invalid.isEmpty() && !invalid.startsWith(QStringLiteral("No API key"))) {
        modelStatus_->setText(invalid);
        return;
    }
    QNetworkRequest req(url);
    req.setRawHeader("Accept", "application/json");
    req.setTransferTimeout(10000);
    const QByteArray key = c.apiKey.toUtf8();
    if (c.provider == Provider::Anthropic) {
        req.setRawHeader("x-api-key", key);
        req.setRawHeader("anthropic-version", "2023-06-01");
    } else if (!key.isEmpty()) {
        req.setRawHeader("Authorization", "Bearer " + key);
    }
    modelStatus_->setText(QStringLiteral("Loading models..."));
    refreshModels_->setEnabled(false);
    modelsReply_ = nam_->get(req);
    modelsReply_->setProperty("provider", static_cast<int>(c.provider));
    connect(modelsReply_.data(), &QNetworkReply::finished, this, &SettingsDialog::onModelsReply);
}

void SettingsDialog::onModelsReply() {
    auto *reply = qobject_cast<QNetworkReply *>(sender());
    if (!reply) return;
    reply->deleteLater();
    if (reply != modelsReply_) return; // superseded
    refreshModels_->setEnabled(true);
    const auto provider = static_cast<Provider>(reply->property("provider").toInt());
    if (provider != currentProvider()) return;
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (reply->error() == QNetworkReply::OperationCanceledError) return;
    if (reply->error() != QNetworkReply::NoError || status >= 400) {
        modelStatus_->setText(status == 401 || status == 403
            ? QStringLiteral("The provider rejected the API key (HTTP %1). Showing common models.").arg(status)
            : QStringLiteral("Could not load models (%1). Showing common models.")
                  .arg(status > 0 ? QStringLiteral("HTTP %1").arg(status) : reply->errorString()));
        return;
    }
    const QStringList models = AiClient::parseModelList(provider, reply->readAll());
    if (models.isEmpty()) {
        modelStatus_->setText(QStringLiteral("The provider returned no models. Showing common models."));
        return;
    }
    setModelChoices(models);
    modelStatus_->setText(QStringLiteral("%1 models available.").arg(models.size()));
}

UiSettings SettingsDialog::settings() const {
    UiSettings u = UiSettings::load(false);
    const Provider p = currentProvider();
    u.ai.provider = p;
    const QString model = model_->currentText().trimmed();
    u.ai.model = model == AiConfig::defaultModel(p) ? QString() : model;
    const QString endpoint = endpoint_->text().trimmed();
    u.ai.endpoint = endpoint == AiConfig::defaultEndpoint(p) ? QString() : endpoint;
    u.ai.timeoutSeconds = timeout_->value() == 0 ? 0 : qMax(5, timeout_->value());
    u.ai.maxTokens = maxTokens_->value() == 0 ? 0 : qMax(256, maxTokens_->value());
    u.maxFindings = maxFindings_->value() == 0 ? 0 : qMax(5, maxFindings_->value());
    u.redact = redact_->isChecked();
    u.includePacketTree = packetTree_->isChecked();
    u.useTools = useTools_->isChecked();
    const QString keyText = apiKey_->text().trimmed();
    if (UiSettings::isEnvVarName(keyText)) {
        u.keyEnvVar = keyText.startsWith(QLatin1Char('$')) ? keyText.mid(1) : keyText;
        // The standard variable for this provider is read anyway; no need to store it.
        if (u.keyEnvVar == AiConfig::apiKeyEnvVar(p) || u.keyEnvVar == QLatin1String("AI_INSPECTOR_API_KEY")) u.keyEnvVar.clear();
    } else if (keyEdited_ && !keyText.isEmpty()) {
        u.keyEnvVar.clear();
    }
    u.ai.apiKey = resolvedKey();
    return u;
}

void SettingsDialog::accept() {
    UiSettings u = settings();
    const QString invalid = u.ai.validate();
    // A missing key is allowed at save time (the user may set an env var later).
    if (!invalid.isEmpty() && !invalid.startsWith(QStringLiteral("No API key"))) {
        QMessageBox::warning(this, windowTitle(), invalid);
        return;
    }
    const QString keyText = apiKey_->text().trimmed();
    if (keyEdited_ && !keyText.isEmpty() && !UiSettings::isEnvVarName(keyText)) {
        QString err;
        if (!UiSettings::storeApiKey(keyText, &err)) {
            QMessageBox::warning(this, windowTitle(), QStringLiteral("Could not save the API key: %1").arg(err));
            return;
        }
    }
    u.save();
    QDialog::accept();
}

} // namespace aiinspector
