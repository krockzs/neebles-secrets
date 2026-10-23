#include "BackupIpc.h"
#include <QCryptographicHash>
#include <QFile>
#include <QSet>
#include <QRegularExpression>
#include <QJsonParseError>
#include <QDateTime>
#include <QDir>
#include <QFileDevice>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSaveFile>
#include <QList>
#include <QtEndian>

namespace {
constexpr int Chunk=6144;
constexpr qint64 MaxEach=512LL*1024*1024;
constexpr qint64 MaxAll=1024LL*1024*1024;
struct Item {QString name; qint64 size=0; QString hash;};
QByteArray be32(quint32 n){
    QByteArray bytes(4,'\0');
    qToBigEndian<quint32>(n,reinterpret_cast<uchar*>(bytes.data()));
    return bytes;
}
bool write(QSaveFile& file,const QByteArray& data){return file.write(data)==data.size();}
QString failure(const QJsonObject& json,const QString& transport){
    return transport.isEmpty()?json.value(QStringLiteral("error")).toString(QStringLiteral("Error IPC")):transport;
}
}
namespace BackupIpc {
QStringList catalog(const Rpc& call,QString* error){
    const QJsonObject response=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("backup.catalog")}},error);
    if(!response.value(QStringLiteral("ok")).toBool()){
        if(error && error->isEmpty())*error=failure(response,QString());
        return {};
    }
    QStringList result;
    const auto names=response.value(QStringLiteral("data")).toObject().value(QStringLiteral("names")).toArray();
    for(const auto& name:names){if(name.isString())result<<name.toString();}
    return result;
}
Result exportEncrypted(const Rpc& call,bool full,const QString& name,
                       const QString& destination,const std::atomic_bool* cancelled,
                       const std::function<void(int)>& progress){
    Result result;
    const QFileInfo dest(destination);
    if(destination.isEmpty() || dest.isSymLink() || dest.absoluteDir().canonicalPath().isEmpty()){
        result.error=QStringLiteral("Destino de respaldo inválido");return result;
    }
    if((full&&!destination.endsWith(QStringLiteral(".nbsbak"),Qt::CaseInsensitive)) ||
       (!full&&!destination.endsWith(QStringLiteral(".kdbx"),Qt::CaseInsensitive))){
        result.error=QStringLiteral("Extensión del respaldo incorrecta");return result;
    }
    const QJsonObject opening{{QStringLiteral("op"),QStringLiteral("backup.open")},
        {QStringLiteral("mode"),full?QStringLiteral("full"):QStringLiteral("single")},
        {QStringLiteral("name"),name}};
    QString error;
    const auto response=call(opening,&error);
    if(!response.value(QStringLiteral("ok")).toBool()){
        result.error=failure(response,error);return result;
    }
    const auto data=response.value(QStringLiteral("data")).toObject();
    const QString token=data.value(QStringLiteral("token")).toString();
    const auto entries=data.value(QStringLiteral("files")).toArray();
    const qint64 total=static_cast<qint64>(data.value(QStringLiteral("total")).toDouble(-1));
    // close even if later local verification or IO fails
    const auto close=[&](){
        QString ignored;
        call(QJsonObject{{QStringLiteral("op"),QStringLiteral("backup.close")},
                         {QStringLiteral("token"),token}},&ignored);
    };
    if(token.size()!=32 || entries.isEmpty() || entries.size()>64 || total<128 || total>MaxAll ||
       (!full&&entries.size()!=1)){
        close();result.error=QStringLiteral("Inventario IPC inválido");return result;
    }
    QList<Item> items; qint64 verifiedTotal=0;
    QJsonArray manifestItems;
    for(const auto& entry:entries){
        const auto obj=entry.toObject();
        const QString itemName=obj.value(QStringLiteral("name")).toString();
        const qint64 size=static_cast<qint64>(obj.value(QStringLiteral("size")).toDouble(-1));
        const QString hash=obj.value(QStringLiteral("sha256")).toString();
        if(!itemName.startsWith(QStringLiteral("vault-")) || !itemName.endsWith(QStringLiteral(".kdbx")) ||
           itemName.contains(QLatin1Char('/')) || itemName.contains(QStringLiteral("..")) ||
           size<128 || size>MaxEach || hash.size()!=64 || verifiedTotal>MaxAll-size){
            close();result.error=QStringLiteral("Inventario IPC inseguro");return result;
        }
        verifiedTotal+=size;items.push_back({itemName,size,hash});
        manifestItems.append(QJsonObject{{QStringLiteral("name"),itemName},
            {QStringLiteral("size"),static_cast<double>(size)},
            {QStringLiteral("sha256"),hash}});
    }
    if(verifiedTotal!=total || (!full&&items.front().name!=name)){
        close();result.error=QStringLiteral("Inventario IPC inconsistente");return result;
    }
    QSaveFile output(destination);
    output.setDirectWriteFallback(false);
    if(!output.open(QIODevice::WriteOnly) ||
       !output.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner)){
        output.cancelWriting();close();result.error=QStringLiteral("No se pudo crear un respaldo protegido (0600)");return result;
    }
    if(full){
        const QJsonObject manifest{
            {QStringLiteral("schema"),QStringLiteral("neebles-secrets-backup")},
            {QStringLiteral("version"),1},
            {QStringLiteral("created_utc"),QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
            {QStringLiteral("master_key_included"),false},
            {QStringLiteral("vaults"),manifestItems}
        };
        const QByteArray bytes=QJsonDocument(manifest).toJson(QJsonDocument::Compact);
        if(bytes.size()>1024*1024 || !write(output,QByteArray("NBSKDBX1",8)) ||
           !write(output,be32(static_cast<quint32>(bytes.size()))) || !write(output,bytes)){
            output.cancelWriting();close();result.error=QStringLiteral("Fallo al escribir el inventario");return result;
        }
    }
    qint64 copied=0;
    for(int i=0;i<items.size();++i){
        const auto& item=items.at(i);
        QCryptographicHash digest(QCryptographicHash::Sha256);
        qint64 offset=0;
        while(offset<item.size){
            if(cancelled && cancelled->load()){
                output.cancelWriting();close();result.error=QStringLiteral("Respaldo cancelado");return result;
            }
            const int amount=static_cast<int>(qMin<qint64>(Chunk,item.size-offset));
            error.clear();
            const auto resp=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("backup.read")},
                {QStringLiteral("token"),token},{QStringLiteral("index"),i},
                {QStringLiteral("offset"),static_cast<double>(offset)},
                {QStringLiteral("count"),amount}},&error);
            if(!resp.value(QStringLiteral("ok")).toBool()){
                output.cancelWriting();close();result.error=failure(resp,error);return result;
            }
            const auto payload=resp.value(QStringLiteral("data")).toObject();
            const QByteArray encoded=payload.value(QStringLiteral("value")).toString().toLatin1();
            const auto decoded=QByteArray::fromBase64Encoding(encoded,QByteArray::AbortOnBase64DecodingErrors);
            const qint64 next=static_cast<qint64>(payload.value(QStringLiteral("next")).toDouble(-1));
            if(!decoded || decoded.decoded.size()!=amount || next!=offset+amount || !write(output,decoded.decoded)){
                output.cancelWriting();close();result.error=QStringLiteral("Datos de respaldo incompletos o inválidos");return result;
            }
            digest.addData(decoded.decoded);offset+=amount;copied+=amount;
            if(progress)progress(static_cast<int>((copied*100)/total));
        }
        if(QString::fromLatin1(digest.result().toHex())!=item.hash){
            output.cancelWriting();close();result.error=QStringLiteral("SHA-256 del KDBX no coincide");return result;
        }
    }
    if(cancelled && cancelled->load()){
        output.cancelWriting();close();result.error=QStringLiteral("Respaldo cancelado");return result;
    }
    if(!output.commit()){
        close();result.error=QStringLiteral("No se pudo confirmar la escritura atómica");return result;
    }
    close();result.ok=true;result.count=items.size();return result;
}
}


namespace {
constexpr qint64 VerifyChunk=32768;
constexpr quint32 MaxManifest=1024*1024;

bool validVaultName(const QString& n){
    if(n==QStringLiteral("vault-general.kdbx"))return true;
    const auto match=QRegularExpression(QStringLiteral("^vault-([a-z][a-z0-9-]{1,63})\\.kdbx$"))
        .match(n);
    if(!match.hasMatch())return false;
    const auto module=match.captured(1);
    return module.size()<=64 && !module.endsWith(QLatin1Char('-'))
        && !module.contains(QStringLiteral("--"));
}

bool sha256Hex(const QString& value){
    if(value.size()!=64)return false;
    for(const auto c:value){
        if(!((c>=QLatin1Char('0')&&c<=QLatin1Char('9')) ||
             (c>=QLatin1Char('a')&&c<=QLatin1Char('f'))))return false;
    }
    return true;
}

bool cancelled(const std::atomic_bool* stop){return stop && stop->load();}

bool readAndHash(QFile& source,qint64 size,QString* checksum,
                 const std::atomic_bool* stop,
                 qint64* processed,qint64 total,
                 const std::function<void(int)>& progress,
                 QString* error){
    QCryptographicHash hash(QCryptographicHash::Sha256);
    qint64 consumed=0;
    QByteArray header;
    while(consumed<size){
        if(cancelled(stop)){*error=QStringLiteral("Verificación cancelada");return false;}
        const auto amount=qMin(VerifyChunk,size-consumed);
        const QByteArray bytes=source.read(amount);
        if(bytes.size()!=amount){*error=QStringLiteral("Archivo truncado o lectura fallida");return false;}
        if(header.size()<4)header.append(bytes.left(4-header.size()));
        hash.addData(bytes);
        consumed+=bytes.size();*processed+=bytes.size();
        if(progress && total>0)progress(static_cast<int>((*processed*100)/total));
    }
    if(header!=QByteArray::fromHex("03d9a29a")){
        *error=QStringLiteral("La entrada no contiene la cabecera KDBX esperada");return false;
    }
    *checksum=QString::fromLatin1(hash.result().toHex());
    return true;
}
}

BackupIpc::PreviewResult BackupIpc::inspectRestoreBackup(
        const QString& sourcePath,const std::atomic_bool* stop,
        const std::function<void(int)>& progress){
    PreviewResult result;
    const QFileInfo info(sourcePath);
    if(!info.exists() || !info.isFile() || info.isSymLink()){
        result.error=QStringLiteral("Selecciona un archivo regular y no un enlace simbólico");return result;
    }
    const bool bundle=sourcePath.endsWith(QStringLiteral(".nbsbak"),Qt::CaseInsensitive);
    const bool single=sourcePath.endsWith(QStringLiteral(".kdbx"),Qt::CaseInsensitive);
    if(!bundle && !single){
        result.error=QStringLiteral("Solo se admiten archivos .kdbx o .nbsbak");return result;
    }
    QFile source(sourcePath);
    if(!source.open(QIODevice::ReadOnly)){
        result.error=QStringLiteral("No se pudo abrir el respaldo para lectura");return result;
    }
    const qint64 fileLength=source.size();
    if(fileLength<128 || fileLength>MaxAll+MaxManifest+12){
        result.error=QStringLiteral("Tamaño de respaldo fuera de límites");return result;
    }
    if(single){
        if(fileLength>MaxEach){result.error=QStringLiteral("KDBX supera el tamaño permitido");return result;}
        qint64 processed=0;
        QString hash;
        if(!readAndHash(source,fileLength,&hash,stop,&processed,fileLength,progress,&result.error))return result;
        if(!source.atEnd()){
            result.error=QStringLiteral("El KDBX cambió durante la verificación");return result;
        }
        result.ok=true;
        result.mode=QStringLiteral("individual");
        result.names<<info.fileName();
        result.hashes<<hash;
        result.bytes=fileLength;
        return result;
    }
    if(source.read(8)!=QByteArray("NBSKDBX1",8)){
        result.error=QStringLiteral("Cabecera del paquete NEEBLES inválida");return result;
    }
    const QByteArray lengthData=source.read(4);
    if(lengthData.size()!=4){result.error=QStringLiteral("Inventario truncado");return result;}
    const quint32 manifestSize=qFromBigEndian<quint32>(
        reinterpret_cast<const uchar*>(lengthData.constData()));
    if(manifestSize==0 || manifestSize>MaxManifest || manifestSize>fileLength-12){
        result.error=QStringLiteral("Longitud de inventario inválida");return result;
    }
    const QByteArray raw=source.read(manifestSize);
    if(raw.size()!=static_cast<int>(manifestSize)){
        result.error=QStringLiteral("Inventario incompleto");return result;
    }
    QJsonParseError parseError;
    const auto doc=QJsonDocument::fromJson(raw,&parseError);
    if(parseError.error!=QJsonParseError::NoError || !doc.isObject()){
        result.error=QStringLiteral("Inventario JSON inválido");return result;
    }
    const auto inventory=doc.object();
    if(inventory.value(QStringLiteral("schema")).toString()!=QStringLiteral("neebles-secrets-backup") ||
       inventory.value(QStringLiteral("version")).toInt(-1)!=1 ||
       inventory.value(QStringLiteral("master_key_included")).toBool(true) ||
       !inventory.value(QStringLiteral("vaults")).isArray()){
        result.error=QStringLiteral("Esquema de respaldo no reconocido");return result;
    }
    const QJsonArray items=inventory.value(QStringLiteral("vaults")).toArray();
    if(items.isEmpty() || items.size()>64){
        result.error=QStringLiteral("Cantidad de bóvedas inválida");return result;
    }
    QSet<QString> seen;
    QList<Item> entries;
    qint64 expectedBytes=0;
    for(const auto& item:items){
        if(!item.isObject()){
            result.error=QStringLiteral("Entrada del inventario inválida");return result;
        }
        const auto row=item.toObject();
        const QString name=row.value(QStringLiteral("name")).toString();
        const QString hash=row.value(QStringLiteral("sha256")).toString();
        const auto sizeValue=row.value(QStringLiteral("size"));
        if(!sizeValue.isDouble()){
            result.error=QStringLiteral("Tamaño de bóveda inválido");return result;
        }
        const double sizeFloat=sizeValue.toDouble();
        const qint64 size=static_cast<qint64>(sizeFloat);
        if(!validVaultName(name) || seen.contains(name) || !sha256Hex(hash) ||
           sizeFloat!=static_cast<double>(size) || size<128 || size>MaxEach ||
           expectedBytes>MaxAll-size){
            result.error=QStringLiteral("Inventario inseguro o inconsistente");return result;
        }
        seen.insert(name);
        expectedBytes+=size;
        entries.append({name,size,hash});
    }
    if(fileLength!=12+static_cast<qint64>(manifestSize)+expectedBytes){
        result.error=QStringLiteral("Longitud del paquete no coincide con el inventario");return result;
    }
    qint64 processed=0;
    for(const auto& entry:entries){
        QString actualHash;
        if(!readAndHash(source,entry.size,&actualHash,stop,&processed,expectedBytes,progress,&result.error))return result;
        if(actualHash!=entry.hash){
            result.error=QStringLiteral("SHA-256 no coincide para ")+entry.name;return result;
        }
        result.names<<entry.name;
        result.hashes<<entry.hash;
    }
    if(!source.atEnd()){
        result.error=QStringLiteral("Datos adicionales inesperados");return result;
    }
    result.ok=true;
    result.mode=QStringLiteral("completo");
    result.bytes=expectedBytes;
    return result;
}

// F11-C — Verify that imported encrypted KDBX data opens with the CURRENT
// unlocked Secrets Master Key. This is exclusively a staging dry-run and never
// replaces a live KDBX. The ciphertext is transferred through the authorized IPC.
BackupIpc::CompatibilityResult BackupIpc::verifyRestoreMasterKey(
        const Rpc& call,const QString& sourcePath,const QString& selectedTarget,
        const std::atomic_bool* stop,const std::function<void(int)>& progress,bool prepareForCommit){
    CompatibilityResult result;
    if(prepareForCommit){
        QString ignored;
        call(QJsonObject{{QStringLiteral("op"),QStringLiteral("restore.discard")}},&ignored);
    }
    struct Cleanup {
        const Rpc& rpc;
        bool needed;
        ~Cleanup(){if(needed){QString ignored;rpc(QJsonObject{{QStringLiteral("op"),QStringLiteral("restore.discard")}},&ignored);}}
    } cleanup{call,prepareForCommit};
    const auto preview=inspectRestoreBackup(sourcePath,stop,{});
    if(!preview.ok){result.error=preview.error;return result;}
    if(preview.mode==QStringLiteral("individual") && !validVaultName(selectedTarget)){
        result.error=QStringLiteral("Selecciona una bóveda de destino válida");return result;
    }
    QFile source(sourcePath);
    if(!source.open(QIODevice::ReadOnly)){
        result.error=QStringLiteral("No se pudo leer el respaldo");return result;
    }
    if(preview.mode==QStringLiteral("completo")){
        if(source.read(8)!=QByteArray("NBSKDBX1",8)){
            result.error=QStringLiteral("Cabecera inválida");return result;
        }
        const QByteArray len=source.read(4);
        if(len.size()!=4){result.error=QStringLiteral("Inventario truncado");return result;}
        const auto manifest=qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(len.constData()));
        if(manifest==0 || manifest>1024*1024 || !source.seek(12LL+manifest)){
            result.error=QStringLiteral("Inventario inválido");return result;
        }
    }
    const qint64 total=preview.bytes;
    qint64 processed=0;
    for(int index=0;index<preview.names.size();++index){
        if(cancelled(stop)){result.error=QStringLiteral("Verificación cancelada");return result;}
        const QString target=preview.mode==QStringLiteral("individual")?
            selectedTarget:preview.names.at(index);
        if(!validVaultName(target)){
            result.error=QStringLiteral("Nombre de bóveda inválido");return result;
        }
        // Determine exact ciphertext length from bundle inventory or file.
        qint64 remaining=0;
        if(preview.mode==QStringLiteral("individual")){
            remaining=total;
        }else{
            const auto base=source.pos();
            // The validated manifest is read again, using fixed offsets.
            if(!source.seek(8)){result.error=QStringLiteral("Error de lectura");return result;}
            const auto rawLen=source.read(4);
            if(rawLen.size()!=4){result.error=QStringLiteral("Inventario truncado");return result;}
            const auto manifestLength=qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(rawLen.constData()));
            const auto raw=source.read(manifestLength);
            const auto entries=QJsonDocument::fromJson(raw).object().value(QStringLiteral("vaults")).toArray();
            if(entries.size()!=preview.names.size()){
                result.error=QStringLiteral("Inventario cambió durante la lectura");return result;
            }
            remaining=static_cast<qint64>(entries.at(index).toObject().value(QStringLiteral("size")).toDouble(-1));
            if(remaining<128 || !source.seek(base)){
                result.error=QStringLiteral("Entrada del inventario inválida");return result;
            }
        }
        QString error;
        const QJsonObject opened=call(QJsonObject{
            {QStringLiteral("op"),QStringLiteral("restore.start")},
            {QStringLiteral("target"),target},
            {QStringLiteral("size"),static_cast<double>(remaining)},
            {QStringLiteral("sha256"),preview.hashes.at(index)}},&error);
        if(!opened.value(QStringLiteral("ok")).toBool()){
            result.error=failure(opened,error);return result;
        }
        const QString token=opened.value(QStringLiteral("data")).toObject().value(QStringLiteral("token")).toString();
        const auto abort=[&](){QString ignored;call(QJsonObject{
            {QStringLiteral("op"),QStringLiteral("restore.abort")},
            {QStringLiteral("token"),token}},&ignored);};
        if(token.size()!=32){abort();result.error=QStringLiteral("Sesión IPC inválida");return result;}
        qint64 offset=0;
        while(offset<remaining){
            if(cancelled(stop)){abort();result.error=QStringLiteral("Verificación cancelada");return result;}
            const int amount=static_cast<int>(qMin<qint64>(6144,remaining-offset));
            const QByteArray chunk=source.read(amount);
            if(chunk.size()!=amount){abort();result.error=QStringLiteral("Archivo truncado");return result;}
            error.clear();
            const auto reply=call(QJsonObject{
                {QStringLiteral("op"),QStringLiteral("restore.chunk")},
                {QStringLiteral("token"),token},
                {QStringLiteral("offset"),static_cast<double>(offset)},
                {QStringLiteral("value"),QString::fromLatin1(chunk.toBase64())}},&error);
            if(!reply.value(QStringLiteral("ok")).toBool()){
                abort();result.error=failure(reply,error);return result;
            }
            const qint64 next=static_cast<qint64>(reply.value(QStringLiteral("data")).toObject().value(QStringLiteral("next")).toDouble(-1));
            if(next!=offset+amount){abort();result.error=QStringLiteral("Offset IPC inconsistente");return result;}
            offset=next;processed+=amount;
            if(progress && total>0)progress(static_cast<int>(processed*100/total));
        }
        error.clear();
        const auto response=call(QJsonObject{
            {QStringLiteral("op"),QStringLiteral("restore.validate")},
            {QStringLiteral("token"),token}},&error);
        if(!response.value(QStringLiteral("ok")).toBool()){
            abort();result.error=failure(response,error);return result;
        }
        if(!response.value(QStringLiteral("data")).toObject().value(QStringLiteral("compatible")).toBool()){
            abort();result.error=QStringLiteral("Bóveda incompatible con la Master Key");return result;
        }
        if(prepareForCommit){
            error.clear();
            const auto queued=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("restore.queue")},
                {QStringLiteral("token"),token}},&error);
            if(!queued.value(QStringLiteral("ok")).toBool()){
                abort();result.error=failure(queued,error);return result;
            }
        }else{abort();}
        result.names<<target;
        ++result.count;
    }
    if(!source.atEnd()){
        result.error=QStringLiteral("El archivo cambió durante la lectura");return result;
    }
    if(prepareForCommit){
        QString error;
        const auto prepared=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("restore.plan")}},&error);
        if(!prepared.value(QStringLiteral("ok")).toBool()){
            result.error=failure(prepared,error);return result;
        }
        const auto info=prepared.value(QStringLiteral("data")).toObject();
        const auto ready=info.value(QStringLiteral("ready")).toArray();
        const QString confirmation=info.value(QStringLiteral("confirmation")).toString();
        if(!info.value(QStringLiteral("can_commit")).toBool() ||
           info.value(QStringLiteral("count")).toInt(-1)!=result.count ||
           ready.size()!=result.names.size() || confirmation.size()!=32){
            result.error=QStringLiteral("Plan de restauración incoherente");return result;
        }
        for(int i=0;i<ready.size();++i){
            if(ready.at(i).toObject().value(QStringLiteral("target")).toString()!=result.names.at(i)){
                result.error=QStringLiteral("Plan de restauración cambió");return result;
            }
        }
        result.confirmation=confirmation;
        cleanup.needed=false;
    }
    result.ok=true;
    return result;
}
BackupIpc::Result BackupIpc::commitPreparedRestore(const Rpc& call,const QString& confirmation){
    Result result;
    if(confirmation.size()!=32){result.error=QStringLiteral("Confirmación inválida");return result;}
    QString transport;
    const auto reply=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("restore.commit")},
        {QStringLiteral("confirmation"),confirmation}},&transport);
    if(!reply.value(QStringLiteral("ok")).toBool()){
        result.error=failure(reply,transport);return result;
    }
    const auto data=reply.value(QStringLiteral("data")).toObject();
    if(!data.value(QStringLiteral("committed")).toBool() || !data.value(QStringLiteral("locked")).toBool()
       || data.value(QStringLiteral("restored")).toInt(0)<1){
        result.error=QStringLiteral("Respuesta de restauración inválida");return result;
    }
    result.ok=true;result.count=data.value(QStringLiteral("restored")).toInt();return result;
}
BackupIpc::Result BackupIpc::discardPreparedRestore(const Rpc& call){
    Result result;
    QString transport;
    const auto reply=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("restore.discard")}},&transport);
    if(!reply.value(QStringLiteral("ok")).toBool()){
        result.error=failure(reply,transport);return result;
    }
    result.ok=true;return result;
}
