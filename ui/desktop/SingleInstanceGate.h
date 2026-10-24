#pragma once

#include <QLocalServer>
#include <QLockFile>
#include <QObject>
#include <QString>
#include <functional>
#include <memory>

// User-scoped, fail-closed single-instance gate for the Qt desktop.
// The daemon and Boss runtime are NOT owned by this gate.
class SingleInstanceGate final : public QObject {
public:
    enum class StartResult { Primary, ActivatedExisting, Error };
    explicit SingleInstanceGate(QObject* parent = nullptr);
    void onActivation(std::function<void()> callback);
    StartResult start(const QString& runtimeRoot);
    QString lastError() const;
private:
    void processConnection();
    bool activateExisting();
    QLocalServer server_;
    std::unique_ptr<QLockFile> lock_;
    QString socketPath_;
    QString error_;
    std::function<void()> activate_;
};
