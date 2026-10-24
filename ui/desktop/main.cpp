#include "MainWindow.h"
#include "SingleInstanceGate.h"
#include <QApplication>
#include <QDir>
#include <QFile>
#include <QGuiApplication>
#include <QIcon>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPointer>
#include <QStandardPaths>
#include <QPixmap>
#include <QScreen>
#include <QSplashScreen>
#include <QTimer>
#include <cstdio>

namespace {
QString installedRoot() {
    const QDir bin(QCoreApplication::applicationDirPath());
    const QDir root(bin.filePath(QStringLiteral("..")));
    QFile file(root.filePath(QStringLiteral("manifest.json")));
    if (!file.open(QIODevice::ReadOnly)) return {};
    const auto manifest=QJsonDocument::fromJson(file.readAll()).object();
    if (manifest.value(QStringLiteral("name")).toString()!=QStringLiteral("neebles-secrets")) return {};
    if (!QFile::exists(root.filePath(QStringLiteral("assets/neebles-secrets-logo.png")))) return {};
    return root.absolutePath();
}
}
int main(int argc,char** argv){
    QApplication app(argc,argv);
    app.setApplicationName(QStringLiteral("NEEBLES Secrets"));
    app.setOrganizationName(QStringLiteral("NEEBLES"));
    const QString root=installedRoot();
    if(root.isEmpty()){
        std::fputs("NEEBLES Secrets: missing installed manifest/assets beside bin/.\n",stderr);
        return 2;
    }
    // Check the existing desktop BEFORE constructing splash or MainWindow.
    // A repeated Boss Surface request raises the existing Qt process.
    SingleInstanceGate gate;
    QPointer<MainWindow> currentWindow;
    bool pendingActivation=false;
    gate.onActivation([&] {
        if (!currentWindow) {pendingActivation=true;return;}
        if (currentWindow->isMinimized()) currentWindow->showNormal();
        if (!currentWindow->isVisible()) currentWindow->show();
        currentWindow->raise();
        currentWindow->activateWindow();
    });
    const auto instance=gate.start(QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation));
    if (instance==SingleInstanceGate::StartResult::ActivatedExisting) return 0;
    if (instance!=SingleInstanceGate::StartResult::Primary) {
        std::fprintf(stderr,"NEEBLES Secrets: single-instance protection failed: %s\n",
                     qPrintable(gate.lastError()));
        return 4;
    }
    const QDir directory(root);
    const auto icon=QIcon(directory.filePath(QStringLiteral("assets/neebles-secrets-icon.png")));
    app.setWindowIcon(icon);
    QPixmap logo(directory.filePath(QStringLiteral("assets/neebles-secrets-logo.png")));
    if(logo.isNull()){std::fputs("NEEBLES Secrets: missing splash logo.\n",stderr);return 3;}
    QSize canvas(780,440);
    if(QScreen* screen=QGuiApplication::primaryScreen()){
        const auto available=screen->availableGeometry().size();
        canvas=QSize(qMin(canvas.width(),available.width()-80),qMin(canvas.height(),available.height()-80));
    }
    app.setQuitOnLastWindowClosed(false);
    QSplashScreen splash(logo.scaled(canvas,Qt::KeepAspectRatio,Qt::SmoothTransformation),
                         Qt::WindowStaysOnTopHint | Qt::FramelessWindowHint);
    splash.show();
    QTimer::singleShot(3000,&app,[&app,&splash,&currentWindow,&pendingActivation,root](){
        auto* window=new MainWindow(root);
        currentWindow=window;
        window->setAttribute(Qt::WA_DeleteOnClose);
        splash.close();
        window->show();
        if (pendingActivation) {
            pendingActivation=false;
            window->raise();
            window->activateWindow();
        }
        app.setQuitOnLastWindowClosed(true);
    });
    return app.exec();
}
