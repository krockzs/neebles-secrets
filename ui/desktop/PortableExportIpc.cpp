#include "PortableExportIpc.h"
#include <QCryptographicHash>
#include <QByteArray>
#include <QFileDevice>
#include <QJsonArray>
#include <QJsonObject>
#include <QSaveFile>
#include <QtGlobal>

namespace PortableExportIpc {
namespace {
constexpr int kMaxEntries=250;
constexpr int kChunk=6144;
QString failure(const QJsonObject& response,const QString& transport){
    if(!transport.isEmpty())return transport;
    return response.value(QStringLiteral("error")).toString(QStringLiteral("IPC inválido"));
}
bool good(const QJsonObject& response){return response.value(QStringLiteral("ok")).toBool();}
}
Result run(const Rpc& rpc,const QString& kind,int length,int quantity,
    const QString& passphrase,const QString& destination,const std::atomic_bool* cancelled,
    const std::function<void(int)>& progress){
    Result result;
    if(quantity<1||quantity>kMaxEntries||passphrase.toUtf8().size()<12||passphrase.toUtf8().size()>512){
        result.error=QStringLiteral("Cantidad o contraseña de exportación no válida.");return result;
    }
    if(cancelled && cancelled->load()){
        result.error=QStringLiteral("Exportación cancelada.");return result;
    }
    QString err;
    const auto opened=rpc(QJsonObject{{QStringLiteral("op"),QStringLiteral("portable.begin")},
       {QStringLiteral("passphrase"),passphrase}},&err);
    if(!good(opened)){result.error=failure(opened,err);return result;}
    const QString token=opened.value(QStringLiteral("data")).toObject()
        .value(QStringLiteral("token")).toString();
    if(token.size()!=32){result.error=QStringLiteral("Sesión IPC inválida.");return result;}
    const auto close=[&rpc,&token](){
        QString ignored;
        rpc(QJsonObject{{QStringLiteral("op"),QStringLiteral("portable.close")},
           {QStringLiteral("token"),token}},&ignored);
    };
    for(int generated=0;generated<quantity;){
        if(cancelled && cancelled->load()){
            close();result.error=QStringLiteral("Exportación cancelada.");return result;
        }
        err.clear();
        const int count=qMin(8,quantity-generated);
        const auto batch=rpc(QJsonObject{{QStringLiteral("op"),QStringLiteral("batch.generate")},
            {QStringLiteral("kind"),kind},{QStringLiteral("length"),length},
            {QStringLiteral("count"),count}},&err);
        if(!good(batch)){close();result.error=failure(batch,err);return result;}
        const auto values=batch.value(QStringLiteral("data")).toObject()
            .value(QStringLiteral("values")).toArray();
        if(values.size()!=count){close();result.error=QStringLiteral("Lote IPC incompleto.");return result;}
        for(const auto& item:values){
            if(cancelled && cancelled->load()){
                close();result.error=QStringLiteral("Exportación cancelada.");return result;
            }
            if(!item.isString()){close();result.error=QStringLiteral("Elemento IPC inválido.");return result;}
            err.clear();
            const auto added=rpc(QJsonObject{{QStringLiteral("op"),QStringLiteral("portable.append")},
                {QStringLiteral("token"),token},{QStringLiteral("value"),item.toString()}},&err);
            if(!good(added)){close();result.error=failure(added,err);return result;}
            ++generated;result.entries=generated;
            if(progress)progress(generated*70/quantity);
        }
    }
    err.clear();
    const auto sealed=rpc(QJsonObject{{QStringLiteral("op"),QStringLiteral("portable.seal")},
        {QStringLiteral("token"),token}},&err);
    if(!good(sealed)){close();result.error=failure(sealed,err);return result;}
    const auto item=sealed.value(QStringLiteral("data")).toObject();
    const qint64 size=static_cast<qint64>(item.value(QStringLiteral("size")).toDouble(-1));
    const QByteArray expected=item.value(QStringLiteral("sha256")).toString().toLatin1();
    if(size<128||size>64ll*1024*1024||expected.size()!=64){
        close();result.error=QStringLiteral("Metadatos KDBX inválidos.");return result;
    }
    QSaveFile output(destination);
    output.setDirectWriteFallback(false);
    if(!output.open(QIODevice::WriteOnly)||
       !output.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner)){
        output.cancelWriting();close();result.error=QStringLiteral("No se pudo crear destino privado 0600.");return result;
    }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    qint64 offset=0;
    while(offset<size){
        if(cancelled && cancelled->load()){
            output.cancelWriting();close();result.error=QStringLiteral("Exportación cancelada.");return result;
        }
        const int count=static_cast<int>(qMin<qint64>(kChunk,size-offset));
        err.clear();
        const auto packet=rpc(QJsonObject{{QStringLiteral("op"),QStringLiteral("portable.read")},
            {QStringLiteral("token"),token},{QStringLiteral("offset"),static_cast<double>(offset)},
            {QStringLiteral("count"),count}},&err);
        if(!good(packet)){
            output.cancelWriting();close();result.error=failure(packet,err);return result;
        }
        const auto data=packet.value(QStringLiteral("data")).toObject();
        const auto decoded=QByteArray::fromBase64Encoding(
            data.value(QStringLiteral("value")).toString().toLatin1(),
            QByteArray::AbortOnBase64DecodingErrors);
        const qint64 next=static_cast<qint64>(data.value(QStringLiteral("next")).toDouble(-1));
        if(!decoded||decoded.decoded.size()!=count||next!=offset+count||
           output.write(decoded.decoded)!=count){
            output.cancelWriting();close();result.error=QStringLiteral("Lectura KDBX incompleta.");return result;
        }
        hash.addData(decoded.decoded);
        offset=next;
        if(progress)progress(70+static_cast<int>(offset*30/size));
    }
    if(hash.result().toHex()!=expected){
        output.cancelWriting();close();result.error=QStringLiteral("SHA-256 de KDBX no coincide.");return result;
    }
    if(!output.commit()){
        close();result.error=QStringLiteral("No se pudo confirmar KDBX cifrada.");return result;
    }
    close();result.ok=true;
    if(progress)progress(100);
    return result;
}
}
