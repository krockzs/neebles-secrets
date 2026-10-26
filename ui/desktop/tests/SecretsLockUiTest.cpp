#include "../MainWindow.h"
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QListWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QSaveFile>
#include <QStackedWidget>
#include <QThread>
#include <QTimer>
#include <QDir>
#include <QDebug>
#include <functional>
#include <memory>
#include <csignal>
#include <execinfo.h>
#include <unistd.h>
#include <cstdlib>

namespace {
bool waitFor(const std::function<bool()>& check,int limitMs=6200){
    QElapsedTimer timer;timer.start();
    while(timer.elapsed()<limitMs){
        QCoreApplication::processEvents(QEventLoop::AllEvents,30);
        if(check())return true;
        QThread::msleep(20);
    }
    return false;
}
bool state(const QString& path,const char* value){
    QSaveFile file(path);
    if(!file.open(QIODevice::WriteOnly))return false;
    if(file.write(value)==-1)return false;
    return file.commit();
}
int fail(int code,const char* why){qCritical("FAIL STAGE5 UI %d: %s",code,why);return code;}
}
int main(int argc,char** argv){
    // Diagnostic-only: print stack frames if the Qt harness crashes. No secrets.
    std::signal(SIGSEGV, +[](int){
        const char marker[]="STAGE5 SIGSEGV: native backtrace follows\n";
        (void)::write(STDERR_FILENO,marker,sizeof(marker)-1);
        void* frames[48];
        const int count=::backtrace(frames,48);
        ::backtrace_symbols_fd(frames,count,STDERR_FILENO);
        std::_Exit(139);
    });
    QApplication app(argc,argv);
    if(argc!=3)return fail(2,"usage: ui-lock-test module-root fixture-state-path");
    const QString statePath=QString::fromLocal8Bit(argv[2]);
    if(!state(statePath,"locked"))return fail(3,"cannot initialize private fixture state");
    MainWindow window(QString::fromLocal8Bit(argv[1]));
    window.show();
    const auto nav=window.findChildren<QPushButton*>(QStringLiteral("adminNavButton"));
    auto* list=window.findChild<QListWidget*>(QStringLiteral("secretsPersonalList"));
    auto* content=window.findChild<QLineEdit*>(QStringLiteral("secretsPersonalContent"));
    auto* copy=window.findChild<QPushButton*>(QStringLiteral("secretsPersonalCopy"));
    if(nav.size()!=7||!list||!content||!copy)return fail(4,"UI widget inventory");
    // QTabWidget owns an internal QStackedWidget with one page.  MainWindow
    // owns a different stack with seven Secrets views.  Select the stack by
    // both its complete page inventory and the actual personal-list parent,
    // never by findChild<QStackedWidget*>() which can select Qt internals.
    QStackedWidget* views=nullptr;
    for(auto* candidate:window.findChildren<QStackedWidget*>()){
        if(candidate->count()!=nav.size() || !candidate->widget(2))continue;
        if(candidate->widget(2)->findChild<QListWidget*>(QStringLiteral("secretsPersonalList"))!=list)continue;
        if(views)return fail(4,"ambiguous Secrets view stack");
        views=candidate;
    }
    if(!views)return fail(4,"Secrets seven-page view stack not found");
    qInfo("STAGE5 VIEW SELECTED: count=%d index=%d",views->count(),views->currentIndex());
    if(!waitFor([&]{return !nav[2]->isEnabled() && views->currentIndex()==0;}))return fail(5,"locked must disable My and display Dashboard");
    if(!nav[1]->isEnabled()||!nav[3]->isEnabled()||!nav[4]->isEnabled())return fail(6,"Quick, Lab, Batch remain usable locked");
    nav[2]->click();QCoreApplication::processEvents();
    if(views->currentIndex()!=0)return fail(7,"disabled navigation entered My");
    if(!state(statePath,"unlocked"))return fail(8,"fixture unlock toggle failed");
    if(!waitFor([&]{return nav[2]->isEnabled();}))return fail(9,"async unlock did not enable My");
    if(views->currentIndex()!=0)return fail(10,"unlock must not auto-navigate");
    auto changes=std::make_shared<QVector<int>>();
    QObject::connect(views,&QStackedWidget::currentChanged,views,
        [changes](int value){ changes->append(value); qInfo("STAGE5 TRACE page_changed=%d",value); });
    qInfo("STAGE5 TRACE before My click: stack_index=%d count=%d",views->currentIndex(),views->count());
    nav[2]->click();
    qInfo("STAGE5 TRACE after My click: stack_index=%d count=%d",views->currentIndex(),views->count());
    const int immediateIndex=views->currentIndex();
    if(!waitFor([&]{return views->currentIndex()==2;})){
        qCritical("STAGE5 NAV DIAG: index=%d immediateIndex=%d count=%d myPageEnabled=%d myEnabled=%d myChecked=%d listCount=%d transitions=%d",
                  views->currentIndex(),immediateIndex,views->count(),
                  int(views->widget(2) && views->widget(2)->isEnabled()),int(nav[2]->isEnabled()),
                  int(nav[2]->isChecked()),list->count(),changes->size());
        for(int change:*changes)qCritical("STAGE5 VIEW TRANSITION: %d",change);
        return fail(11,"My view did not open despite unlock");
    }
    if(!waitFor([&]{return list->count()==1;})){
        qCritical("STAGE5 LIST DIAG: index=%d myEnabled=%d listCount=%d",
                  views->currentIndex(),int(nav[2]->isEnabled()),list->count());
        return fail(26,"My list failed to load one fixture record");
    }
    qInfo("PASS STAGE5 NAV: My view and fixture list visible after guarded navigation");
    qInfo("STAGE5 TRACE My list ready; about to select fixture item");
    list->setCurrentRow(0);
    if(!waitFor([&]{return content->text()==QStringLiteral("fixture-secret-not-real");}))return fail(12,"fixture personal get failed");
    copy->click();
    if(QApplication::clipboard()->text()!=QStringLiteral("fixture-secret-not-real"))return fail(13,"fixture copy failed");
    if(!state(statePath,"locked"))return fail(14,"fixture lock toggle failed");
    if(!waitFor([&]{return !nav[2]->isEnabled() && views->currentIndex()==0 && list->count()==0 && content->text().isEmpty();}))
        return fail(15,"external lock did not return Dashboard and purge editor");
    if(!QApplication::clipboard()->text().isEmpty())return fail(16,"locked My clipboard not cleared");
    if(!nav[1]->isEnabled()||!nav[3]->isEnabled()||!nav[4]->isEnabled())return fail(17,"lock disabled independent tools");
    if(!state(statePath,"unlocked"))return fail(18,"fixture second unlock toggle failed");
    if(!waitFor([&]{return nav[2]->isEnabled();}))return fail(19,"second unlock failed");
    if(views->currentIndex()!=0||!content->text().isEmpty())return fail(20,"unlock restored sensitive view");
    if(!state(statePath,"offline"))return fail(21,"fixture offline toggle failed");
    if(!waitFor([&]{return !nav[2]->isEnabled();}))return fail(22,"offline should fail closed");
    if(!nav[1]->isEnabled()||!nav[3]->isEnabled()||!nav[4]->isEnabled())return fail(23,"offline disabled independent tools");
    if(!state(statePath,"badjson"))return fail(24,"fixture badjson toggle failed");
    // A corrupt response must never re-enable My.
    QElapsedTimer elapsed;elapsed.start();
    while(elapsed.elapsed()<2850){QCoreApplication::processEvents(QEventLoop::AllEvents,20);QThread::msleep(20);}
    if(nav[2]->isEnabled())return fail(25,"malformed status allowed My");
    qInfo("PASS STAGE5 UI: lock/unlock, disabled My, Dashboard return, purge, clipboard, offline/corrupt fail-closed, independent tools");
    return 0;
}
