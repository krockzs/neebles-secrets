#include "SingleInstanceGate.h"

#include <QFile>
#include <QLocalSocket>
#include <QThread>
#include <cerrno>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace {
bool privateOwnedDirectory(const QString& path) {
    const QByteArray name=QFile::encodeName(path);
    struct stat st {};
    return ::lstat(name.constData(),&st)==0 && S_ISDIR(st.st_mode)
        && st.st_uid==::geteuid() && (st.st_mode & 0077)==0;
}
}

SingleInstanceGate::SingleInstanceGate(QObject* parent):QObject(parent) {
    connect(&server_,&QLocalServer::newConnection,this,[this] {
        while (QLocalSocket* socket=server_.nextPendingConnection()) {
            connect(socket,&QLocalSocket::disconnected,socket,&QObject::deleteLater);
            // A local stream may split the message across multiple reads.
            auto buffer=std::make_shared<QByteArray>();
            const auto receive=[this,socket,buffer] {
                buffer->append(socket->readAll());
                if (buffer->size()>32) {socket->disconnectFromServer();return;}
                if (!buffer->contains('\n')) return;
                // This is only an activation signal, never vault data.
                if (*buffer==QByteArrayLiteral("ACTIVATE\n")) {
                    if (activate_) activate_();
                    socket->write("OK\n",3);
                    socket->flush();
                }
                socket->disconnectFromServer();
            };
            connect(socket,&QLocalSocket::readyRead,this,receive);
            if (socket->bytesAvailable()>0) receive();
        }
    });
}
void SingleInstanceGate::onActivation(std::function<void()> callback) {
    activate_=std::move(callback);
}
QString SingleInstanceGate::lastError() const {return error_;}

bool SingleInstanceGate::activateExisting() {
    for (int attempt=0;attempt<12;++attempt) {
        QLocalSocket peer;
        peer.connectToServer(socketPath_,QIODevice::ReadWrite);
        if (peer.waitForConnected(180)) {
            peer.write("ACTIVATE\n",9);
            peer.flush();
            if (peer.bytesAvailable()>0 || peer.waitForReadyRead(280)) {
                if (peer.readAll()==QByteArrayLiteral("OK\n")) return true;
            }
        }
        QThread::msleep(100);
    }
    error_=QStringLiteral("Existing Secrets desktop did not acknowledge activation");
    return false;
}

SingleInstanceGate::StartResult SingleInstanceGate::start(const QString& runtimeRoot) {
    if (!privateOwnedDirectory(runtimeRoot)) {
        error_=QStringLiteral("XDG runtime directory is missing, not private, or has a different owner");
        return StartResult::Error;
    }
    const QString directory=runtimeRoot+QStringLiteral("/neebles-secrets-ui");
    const QByteArray encoded=QFile::encodeName(directory);
    if (::mkdir(encoded.constData(),0700)!=0 && errno!=EEXIST) {
        error_=QStringLiteral("Cannot create private Secrets UI runtime directory");
        return StartResult::Error;
    }
    if (!privateOwnedDirectory(directory)) {
        error_=QStringLiteral("Secrets UI runtime directory is not private and owned by the caller");
        return StartResult::Error;
    }
    socketPath_=directory+QStringLiteral("/activate.sock");
    lock_=std::make_unique<QLockFile>(directory+QStringLiteral("/instance.lock"));
    lock_->setStaleLockTime(0); // Never evict a live GUI based on a long processing time.
    if (!lock_->tryLock(0)) {
        if (lock_->error()!=QLockFile::LockFailedError) {
            error_=QStringLiteral("Cannot acquire Secrets UI instance lock");
            return StartResult::Error;
        }
        return activateExisting()?StartResult::ActivatedExisting:StartResult::Error;
    }
    // Lock is acquired; it is safe to remove a socket left by a crashed GUI.
    // removeServer() can report false when no prior socket exists.
    // Never make first launch depend on a stale path being present.
    struct stat existing {};
    const QByteArray socketName=QFile::encodeName(socketPath_);
    if (::lstat(socketName.constData(),&existing)==0) {
        if (!S_ISSOCK(existing.st_mode) || existing.st_uid!=::geteuid()
            || !QLocalServer::removeServer(socketPath_)) {
            error_=QStringLiteral("Cannot safely remove stale Secrets UI socket");
            return StartResult::Error;
        }
    } else if (errno!=ENOENT) {
        error_=QStringLiteral("Cannot inspect Secrets UI socket path");
        return StartResult::Error;
    }
    server_.setSocketOptions(QLocalServer::UserAccessOption);
    if (!server_.listen(socketPath_)) {
        error_=QStringLiteral("Cannot listen on private Secrets UI socket: ")+server_.errorString();
        return StartResult::Error;
    }
    return StartResult::Primary;
}
