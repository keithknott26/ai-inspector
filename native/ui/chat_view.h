// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "charts.h"

#include <QHash>
#include <QImage>
#include <QTextBrowser>
#include <QTimer>
#include <QVector>

#include <functional>

namespace aiinspector {

// Conversation transcript: renders analyst requests and AI answers as cards,
// Markdown formatted, with inline charts (```chart blocks), clickable display
// filters (`...`) and frame references ("frame 123"). Raw HTML from the model
// is never interpreted and no external resources are loaded.
class ChatView : public QTextBrowser {
    Q_OBJECT
public:
    explicit ChatView(QWidget *parent = nullptr);

    void addUser(const QString &text);
    void beginAssistant();
    void appendAssistant(const QString &delta);
    void finishAssistant(const QString &fullText);
    void addError(const QString &text);
    void clearConversation();
    bool isEmpty() const { return messages_.isEmpty(); }
    int chartCount() const { return static_cast<int>(charts_.size()); }
    // Plain text of the whole conversation (for copy).
    QString plainTranscript() const;

    // Checks a display filter with Wireshark's compiler (false + reason if invalid).
    using FilterValidator = std::function<bool(const QString &filter, QString *error)>;
    void setFilterValidator(FilterValidator validator) {
        validator_ = std::move(validator);
        for (auto &m : messages_) m.cachedHtml.clear();
    }
    // Applied to an answer once it is complete (e.g. restoring redacted addresses).
    void setDisplayTransform(std::function<QString(const QString &)> transform) { transform_ = std::move(transform); }

    // Extracted actions (exposed for tests).
    static QStringList extractFilters(const QString &markdown);
    static bool looksLikeFilter(const QString &s);
    // Turns a code span into a usable display filter: valid filters as-is,
    // addresses and host names into matching filters. Empty if unusable.
    static QString toDisplayFilter(const QString &candidate, const FilterValidator &validator);

signals:
    void applyFilterRequested(const QString &filter);
    void filterRejected(const QString &filter, const QString &reason);
    void goToFrameRequested(quint32 frame);

protected:
    QVariant loadResource(int type, const QUrl &name) override;
    void changeEvent(QEvent *event) override;

private:
    struct Message {
        enum Role { User, Assistant, Error } role;
        QString text;
        bool streaming = false;
        // Rendered form of a settled message. Streaming rebuilds the whole
        // document every tick; without this every earlier answer would be
        // re-parsed from Markdown each time. Cleared when the text or the
        // palette changes.
        QString cachedHtml;
    };
    void scheduleRender();
    void render();
    QString renderMessage(int index, const Message &m, const Theme &t);
    QString markdownToHtml(QString markdown, int messageIndex, QStringList *filters, bool streaming);
    // Hides a block that has only half arrived (an open code fence, a partial
    // table row), so the document height does not oscillate while streaming.
    static QString hideIncompleteBlocks(const QString &markdown);

    QVector<Message> messages_;
    QHash<QString, QImage> charts_;
    QTimer renderTimer_;
    FilterValidator validator_;
    std::function<QString(const QString &)> transform_;
};

} // namespace aiinspector
