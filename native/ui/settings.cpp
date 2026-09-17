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
#include <QMessageBox>
#include <QSaveFile>
#include <QSettings>
#include <QSpinBox>
#include <QStandardPaths>
#include <QVBoxLayout>

namespace aiinspector {

namespace {
QSettings store() {
    return QSettings(QStringLiteral("AI-Inspector"), QStringLiteral("AIInspector"));
}

QString envKey(Provider p) {
    QString k = qEnvironmentVariable("AI_INSPECTOR_API_KEY");
    if (!k.trimmed().isEmpty()) return k.trimmed();
    if (p == Provider::Anthropic) return qEnvironmentVariable("ANTHROPIC_API_KEY").trimmed();
    if (p == Provider::OpenAI) return qEnvironmentVariable("OPENAI_API_KEY").trimmed();
    return {};
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

UiSettings UiSettings::load(bool applyEnvironment) {
    QSettings s = store();
    UiSettings u;
    u.ai.provider = static_cast<Provider>(qBound(0, s.value(QStringLiteral("ai/provider"), 0).toInt(), 2));
    u.ai.model = s.value(QStringLiteral("ai/model")).toString();
    u.ai.endpoint = s.value(QStringLiteral("ai/endpoint")).toString();
    u.ai.timeoutSeconds = qBound(5, s.value(QStringLiteral("ai/timeout"), 90).toInt(), 900);
    u.ai.maxTokens = qBound(256, s.value(QStringLiteral("ai/max_tokens"), 2048).toInt(), 32000);
    u.redact = s.value(QStringLiteral("privacy/redact"), true).toBool();
    u.includePacketTree = s.value(QStringLiteral("privacy/include_packet_tree"), true).toBool();
    u.maxFindings = qBound(5, s.value(QStringLiteral("ai/max_findings"), 60).toInt(), 500);

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

    u.ai.apiKey = envKey(u.ai.provider);
    if (!u.ai.apiKey.isEmpty()) {
        u.keySource = QStringLiteral("environment variable");
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
    s.setValue(QStringLiteral("privacy/redact"), redact);
    s.setValue(QStringLiteral("privacy/include_packet_tree"), includePacketTree);
    s.sync();
}

SettingsDialog::SettingsDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle(QStringLiteral("AI Inspector Settings"));
    setObjectName(QStringLiteral("aiInspectorSettings"));
    const UiSettings cur = UiSettings::load(false);

    auto *form = new QFormLayout;
    provider_ = new QComboBox(this);
    for (int i = 0; i < 3; ++i) provider_->addItem(AiConfig::providerName(static_cast<Provider>(i)), i);
    provider_->setCurrentIndex(static_cast<int>(cur.ai.provider));
    form->addRow(QStringLiteral("Provider"), provider_);

    model_ = new QLineEdit(cur.ai.model, this);
    form->addRow(QStringLiteral("Model"), model_);
    const UiSettings effective = UiSettings::load(true);
    if (effective.ai.model != cur.ai.model || effective.ai.endpoint != cur.ai.endpoint) {
        auto *envNote = new QLabel(QStringLiteral("Environment overrides in effect: model %1, endpoint %2")
                                       .arg(effective.ai.effectiveModel(), effective.ai.effectiveEndpoint().toString()), this);
        envNote->setWordWrap(true);
        envNote->setTextFormat(Qt::PlainText);
        form->addRow(QString(), envNote);
    }
    endpoint_ = new QLineEdit(cur.ai.endpoint, this);
    form->addRow(QStringLiteral("Endpoint URL"), endpoint_);

    apiKey_ = new QLineEdit(this);
    apiKey_->setEchoMode(QLineEdit::Password);
    apiKey_->setObjectName(QStringLiteral("apiKey"));
    connect(apiKey_, &QLineEdit::textEdited, this, [this] { keyEdited_ = true; });
    form->addRow(QStringLiteral("API key"), apiKey_);
    keyInfo_ = new QLabel(this);
    keyInfo_->setWordWrap(true);
    keyInfo_->setTextFormat(Qt::PlainText);
    keyInfo_->setText(cur.ai.apiKey.isEmpty()
        ? QStringLiteral("No key stored. Keys are saved to %1 with owner-only permissions, or set AI_INSPECTOR_API_KEY.").arg(UiSettings::keyFilePath())
        : QStringLiteral("A key is configured (from %1). Leave blank to keep it; type a new key to replace it.").arg(cur.keySource));
    form->addRow(QString(), keyInfo_);

    timeout_ = new QSpinBox(this);
    timeout_->setRange(5, 900);
    timeout_->setSuffix(QStringLiteral(" s"));
    timeout_->setValue(cur.ai.timeoutSeconds);
    form->addRow(QStringLiteral("Request timeout"), timeout_);
    maxTokens_ = new QSpinBox(this);
    maxTokens_->setRange(256, 32000);
    maxTokens_->setSingleStep(256);
    maxTokens_->setValue(cur.ai.maxTokens);
    form->addRow(QStringLiteral("Max response tokens"), maxTokens_);
    maxFindings_ = new QSpinBox(this);
    maxFindings_->setRange(5, 500);
    maxFindings_->setValue(cur.maxFindings);
    form->addRow(QStringLiteral("Findings sent to AI"), maxFindings_);
    redact_ = new QCheckBox(QStringLiteral("Replace IP and MAC addresses with placeholders before sending"), this);
    redact_->setChecked(cur.redact);
    form->addRow(QStringLiteral("Privacy"), redact_);
    packetTree_ = new QCheckBox(QStringLiteral("Include the decoded packet tree when explaining a packet"), this);
    packetTree_->setChecked(cur.includePacketTree);
    form->addRow(QString(), packetTree_);

    auto *note = new QLabel(QStringLiteral("Findings, protocol statistics and (optionally) one decoded packet are sent to the "
                                           "selected provider. Credential-bearing fields are always removed."), this);
    note->setWordWrap(true);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &SettingsDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(provider_, qOverload<int>(&QComboBox::currentIndexChanged), this, &SettingsDialog::providerChanged);

    auto *layout = new QVBoxLayout(this);
    layout->addLayout(form);
    layout->addWidget(note);
    layout->addWidget(buttons);
    providerChanged();
}

void SettingsDialog::providerChanged() {
    const auto p = static_cast<Provider>(provider_->currentIndex());
    model_->setPlaceholderText(AiConfig::defaultModel(p));
    endpoint_->setPlaceholderText(AiConfig::defaultEndpoint(p));
}

UiSettings SettingsDialog::settings() const {
    UiSettings u = UiSettings::load(false);
    u.ai.provider = static_cast<Provider>(provider_->currentIndex());
    u.ai.model = model_->text().trimmed();
    u.ai.endpoint = endpoint_->text().trimmed();
    u.ai.timeoutSeconds = timeout_->value();
    u.ai.maxTokens = maxTokens_->value();
    u.maxFindings = maxFindings_->value();
    u.redact = redact_->isChecked();
    u.includePacketTree = packetTree_->isChecked();
    if (keyEdited_ && !apiKey_->text().trimmed().isEmpty()) u.ai.apiKey = apiKey_->text().trimmed();
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
    if (keyEdited_ && !apiKey_->text().trimmed().isEmpty()) {
        QString err;
        if (!UiSettings::storeApiKey(apiKey_->text(), &err)) {
            QMessageBox::warning(this, windowTitle(), QStringLiteral("Could not save the API key: %1").arg(err));
            return;
        }
    }
    u.save();
    QDialog::accept();
}

} // namespace aiinspector
