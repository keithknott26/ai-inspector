// SPDX-License-Identifier: GPL-2.0-or-later
//
// AI provider and privacy settings.
//
// Resolution order (highest first):
//   Provider / endpoint / model: AI_INSPECTOR_PROVIDER, AI_INSPECTOR_ENDPOINT,
//     AI_INSPECTOR_MODEL; for the Anthropic provider also ANTHROPIC_MODEL and
//     ANTHROPIC_BASE_URL; then values saved from the Settings dialog (QSettings,
//     organisation "AI-Inspector"). Environment values are never saved.
//   API key: AI_INSPECTOR_API_KEY, then ANTHROPIC_API_KEY / OPENAI_API_KEY for the
//     matching provider, then a variable named in Settings (stored as its NAME, never
//     its value), then the key file (~/.config/ai-inspector/api_key, owner-only
//     permissions; override with AI_INSPECTOR_KEY_FILE).
//   Timeout, max tokens and findings sent to AI accept 0 = Auto.
#pragma once

#include "ai_client.h"

#include <QDialog>
#include <QPointer>
#include <QString>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QNetworkAccessManager;
class QNetworkReply;
class QSpinBox;
class QToolButton;

namespace aiinspector {

struct UiSettings {
    AiConfig ai;
    bool redact = true;
    bool includePacketTree = true;
    bool useTools = true; // let the assistant pull capture data on demand
    int maxFindings = 0;  // 0 = auto
    QString keyEnvVar;    // name of an environment variable holding the key (e.g. ANTHROPIC_API_KEY)
    QString keySource; // where the key came from (display only)

    int effectiveMaxFindings() const;
    static int autoMaxFindings(Provider p);
    // True for names such as ANTHROPIC_API_KEY (uppercase letters, digits, underscore).
    static bool isEnvVarName(const QString &text);

    // Loads persisted settings. The API key comes from AI_INSPECTOR_API_KEY, the
    // provider-specific environment variable, or the per-user key file.
    static UiSettings load(bool applyEnvironment = true);
    void save() const;

    static QString keyFilePath();
    // Writes the key file with owner-only permissions. Empty key deletes it.
    static bool storeApiKey(const QString &key, QString *error);
};

class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(QWidget *parent = nullptr);
    UiSettings settings() const;

private:
    Provider currentProvider() const;
    void providerChanged();
    void updateAutoLabels();
    void updateKeyInfo();
    QString resolvedKey() const;
    void setModelChoices(const QStringList &models);
    void loadModels();
    void onModelsReply();
    void accept() override;

    UiSettings initial_;
    Provider lastProvider_ = Provider::Anthropic;
    QComboBox *provider_;
    QComboBox *model_;
    QToolButton *refreshModels_;
    QLabel *modelStatus_;
    QLineEdit *endpoint_;
    QLineEdit *apiKey_;
    QLabel *keyInfo_;
    QSpinBox *timeout_;
    QSpinBox *maxTokens_;
    QSpinBox *maxFindings_;
    QCheckBox *redact_;
    QCheckBox *packetTree_;
    QCheckBox *useTools_;
    QNetworkAccessManager *nam_;
    QPointer<QNetworkReply> modelsReply_;
    bool keyEdited_ = false;
};

} // namespace aiinspector
