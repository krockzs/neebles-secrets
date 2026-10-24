#include "../SingleInstanceGate.h"
#include <QCoreApplication>
#include <QProcess>
#include <QTemporaryDir>
#include <QTimer>
#include <cstdio>

int main(int argc,char** argv) {
    QCoreApplication app(argc,argv);
    const auto args=app.arguments();
    if (args.size()==3 && args[1]==QStringLiteral("--secondary")) {
        SingleInstanceGate gate;
        return gate.start(args[2])==SingleInstanceGate::StartResult::ActivatedExisting?0:4;
    }
    QTemporaryDir temporary;
    if (!temporary.isValid()) return 5;
    SingleInstanceGate primary;
    int accepted=0;
    primary.onActivation([&]{++accepted;});
    if (primary.start(temporary.path())!=SingleInstanceGate::StartResult::Primary) return 6;
    QProcess child;
    int childStatus=-1;
    QObject::connect(&child,QOverload<int,QProcess::ExitStatus>::of(&QProcess::finished),
        &app,[&](int code,QProcess::ExitStatus status) {
            childStatus=(status==QProcess::NormalExit)?code:7;
            app.quit();
        });
    QTimer::singleShot(0,&app,[&] {
        child.start(app.applicationFilePath(),{QStringLiteral("--secondary"),temporary.path()});
    });
    QTimer::singleShot(8000,&app,&QCoreApplication::quit);
    app.exec();
    if (child.state()!=QProcess::NotRunning) {child.kill();child.waitForFinished(1000);return 8;}
    if (childStatus!=0 || accepted!=1) {
        std::fprintf(stderr,"Single instance smoke failed: child=%d activations=%d\n",childStatus,accepted);
        return 9;
    }
    std::puts("PASS: primary retained singleton; secondary activated it exactly once");
    return 0;
}
