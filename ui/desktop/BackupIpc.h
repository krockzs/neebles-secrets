#pragma once
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <atomic>
#include <functional>

namespace BackupIpc {
using Rpc=std::function<QJsonObject(const QJsonObject&,QString*)>;
struct Result {bool ok=false;QString error;int count=0;};
struct PreviewResult {
    bool ok=false;
    QString error;
    QString mode;
    QStringList names;
    QStringList hashes;
    qint64 bytes=0;
};
struct CompatibilityResult {bool ok=false;QString error;int count=0;QStringList names;QString confirmation;};
CompatibilityResult verifyRestoreMasterKey(const Rpc& call,const QString& sourcePath,
    const QString& selectedTarget,const std::atomic_bool* cancelled,
    const std::function<void(int)>& progress,bool prepareForCommit=false);
Result commitPreparedRestore(const Rpc& call,const QString& confirmation);
Result discardPreparedRestore(const Rpc& call);
PreviewResult inspectRestoreBackup(const QString& sourcePath,
    const std::atomic_bool* cancelled,
    const std::function<void(int)>& progress);
QStringList catalog(const Rpc& call,QString* error);
Result exportEncrypted(const Rpc& call,bool full,const QString& name,
    const QString& destination,const std::atomic_bool* cancelled,
    const std::function<void(int)>& progress);
}
