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
//     matching provider, then the key file (~/.config/ai-inspector/api_key,
//     owner-only permissions; override with AI_INSPECTOR_KEY_FILE).
#pragma once

#include "ai_client.h"

#include <QDialog>
#include <QString>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QSpinBox;

namespace aiinspector {

struct UiSettings {
    AiConfig ai;
    bool redact = true;
    bool includePacketTree = true;
    int maxFindings = 60;
    QString keySource; // where the key came from (display only)

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
    void providerChanged();
    void accept() override;

    QComboBox *provider_;
    QLineEdit *model_;
    QLineEdit *endpoint_;
    QLineEdit *apiKey_;
    QLabel *keyInfo_;
    QSpinBox *timeout_;
    QSpinBox *maxTokens_;
    QSpinBox *maxFindings_;
    QCheckBox *redact_;
    QCheckBox *packetTree_;
    bool keyEdited_ = false;
};

} // namespace aiinspector
