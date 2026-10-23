#pragma once
#include <QJsonObject>
#include <QString>
#include <atomic>
#include <functional>
namespace PortableExportIpc {
using Rpc=std::function<QJsonObject(const QJsonObject&,QString*)>;
struct Result{bool ok=false;QString error;int entries=0;};
Result run(const Rpc& rpc,const QString& kind,int length,int quantity,
    const QString& passphrase,const QString& destination,const std::atomic_bool* cancelled,
    const std::function<void(int)>& progress);
}
