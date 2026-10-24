#include "MainWindow.h"
#include "BackupIpc.h"
#include "PortableExportIpc.h"
#include <QApplication>
#include <QAbstractButton>
#include <QCryptographicHash>
#include <QGridLayout>
#include <QGroupBox>
#include <QScrollArea>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QSaveFile>
#include <QThread>
#include <QMetaObject>
#include <QFileDevice>
#include <QFormLayout>
#include <QFrame>
#include <QHBoxLayout>
#include <QIcon>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QInputDialog>
#include <QSignalBlocker>
#include <QUuid>
#include <QDialog>
#include <QDialogButtonBox>
#include <QTimer>
#include <QLocalSocket>
#include <QMessageBox>
#include <QPixmap>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QSpinBox>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTabBar>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QWidget>
#include <QtEndian>
#include <utility>
#include <functional>

namespace {
QLabel* heading(const QString& name,QWidget* parent){
    auto* label=new QLabel(name,parent);label->setObjectName(QStringLiteral("sectionHeading"));return label;
}
QLabel* note(const QString& message,QWidget* parent){
    auto* label=new QLabel(message,parent);
    label->setWordWrap(true);label->setObjectName(QStringLiteral("information"));return label;
}
QString errorText(const QJsonObject& value){return value.value(QStringLiteral("error")).toString(QStringLiteral("Unknown error"));}
// F25: one modal with two master-key fields for first setup, independent eyes.
// It never stores the master key in Settings, files, command-line arguments or logs.
static bool askMasterKey(QWidget* parent, bool setup, QString* output,
    const std::function<QString(const QString&)>& tr) {
    QDialog dialog(parent);
    dialog.setWindowTitle(tr(setup ? QStringLiteral("Configurar NEEBLES Secrets")
                               : QStringLiteral("Desbloquear NEEBLES Secrets")));
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(new QLabel(tr(setup
        ? QStringLiteral("Crea una clave maestra para vault-general (mínimo 8 caracteres).")
        : QStringLiteral("Introduce tu clave maestra existente.")), &dialog));
    auto* form = new QFormLayout();
    auto makeField = [&dialog,&tr](QLineEdit** field) -> QWidget* {
        auto* widget = new QWidget(&dialog);
        auto* row = new QHBoxLayout(widget);
        row->setContentsMargins(0, 0, 0, 0);
        *field = new QLineEdit(widget);
        (*field)->setEchoMode(QLineEdit::Password);
        (*field)->setMinimumWidth(280);
        row->addWidget(*field);
        auto* eye = new QPushButton(QStringLiteral("👁"), widget);
        eye->setCheckable(true);
        eye->setToolTip(tr(QStringLiteral("Mostrar u ocultar clave")));
        eye->setAccessibleName(tr(QStringLiteral("Mostrar u ocultar clave")));
        eye->setMaximumWidth(45);
        QObject::connect(eye, &QPushButton::toggled, widget,
            [editor=*field](bool checked) {
                editor->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
            });
        row->addWidget(eye);
        return widget;
    };
    QLineEdit* key = nullptr;
    QLineEdit* confirmation = nullptr;
    form->addRow(tr(QStringLiteral("Clave maestra:")), makeField(&key));
    if (setup) {
        form->addRow(tr(QStringLiteral("Confirmar clave:")), makeField(&confirmation));
    }
    layout->addLayout(form);
    auto* notice = new QLabel(&dialog);
    notice->setWordWrap(true);
    layout->addWidget(notice);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    layout->addWidget(buttons);
    if(auto* ok=buttons->button(QDialogButtonBox::Ok))ok->setText(tr(QStringLiteral("Aceptar")));
    if(auto* cancel=buttons->button(QDialogButtonBox::Cancel))cancel->setText(tr(QStringLiteral("Cancelar")));
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, [&]() {
        if (setup) {
            const auto bytes = key->text().toUtf8();
            if (bytes.size() < 8 || bytes.size() > 512) {
                notice->setText(tr(QStringLiteral("La clave debe tener entre 8 y 512 bytes UTF-8.")));
                return;
            }
            if (key->text() != confirmation->text()) {
                notice->setText(tr(QStringLiteral("Las claves no coinciden.")));
                return;
            }
        }
        if (key->text().contains(QChar('\n')) ||
            key->text().contains(QChar('\r')) ||
            key->text().contains(QChar('\0'))) {
            notice->setText(tr(QStringLiteral("La clave contiene caracteres no permitidos.")));
            return;
        }
        if (key->text().isEmpty()) {
            notice->setText(tr(QStringLiteral("Introduce una clave maestra.")));
            return;
        }
        *output = key->text();
        dialog.accept();
    });
    key->setFocus();
    const bool accepted = dialog.exec() == QDialog::Accepted;
    // Clear widget-owned copies before QDialog destroys them.
    key->clear();
    if (confirmation) confirmation->clear();
    if (!accepted) output->clear();
    return accepted;
}
}
MainWindow::MainWindow(QString moduleRoot,QWidget* parent):QMainWindow(parent),root_(std::move(moduleRoot)){
    setWindowTitle(QStringLiteral("N.E.E.B.L.E.S. Secrets — 1.0.4"));
    setWindowIcon(QIcon(QDir(root_).filePath(QStringLiteral("assets/neebles-secrets-icon.png"))));
    setMinimumSize(1040,650);resize(1400,850);
    setStyleSheet(QStringLiteral(R"QSS(
        QWidget { background:#09090B; color:#F5F5F5; font-size:13px; }
        QFrame#sidebar { background:#09090B; border-right:1px solid #5B21B6; }
        QFrame#panelCard { background:#10101A; border:1px solid #4C1D95; border-radius:12px; }
        QFrame#informationPanel { background:#0A1525; border:1px solid #0891B2; border-radius:10px; }
        QLabel#panelHeading {font-size:16px;font-weight:650;color:#A5F3FC;}
        QLabel#valueStatus {font-size:16px;font-weight:700;color:#34D399;}
        QScrollArea {border:0px;background:transparent;}
        QScrollArea > QWidget > QWidget { background:#09090B; }
        QGroupBox {background:#0C1020;border:1px solid #6D28D9;border-radius:9px;margin-top:12px;padding:12px; font-weight:600;}
        QGroupBox::title {subcontrol-origin:margin;left:12px;padding:0px 5px;color:#A5F3FC;}
        QListWidget {background:#0C1020;border:1px solid #4C1D95;border-radius:8px;outline:none;padding:5px;}
        QListWidget::item {border-bottom:1px solid #23173E;padding:10px;border-radius:5px;}
        QListWidget::item:selected {background:#082337;border:1px solid #22D3EE;color:#F5F3FF;}
        QPlainTextEdit {background:#09090B;border:1px solid #52525B;border-radius:6px;}
        QLabel#sectionHeading { font-size:21px; font-weight:700; color:#E9D5FF; margin:8px 0; }
        QLabel#information { color:#A1A1AA; }
        QPushButton { background:#09090B; border:1px solid #7C3AED; border-radius:6px; padding:8px 14px; }
        QPushButton:hover { background:#18181B; border-color:#A855F7; }
        QPushButton:disabled {color:#71717A;border-color:#52525B;}
        QPushButton#adminNavButton:checked {border-color:#22D3EE;border-left:3px solid #22D3EE;color:#67E8F9;font-weight:700;}
        QPushButton#unlockButton {border-color:#22D3EE;color:#67E8F9;}
        QLineEdit,QSpinBox,QComboBox {background:#09090B;border:1px solid #52525B;border-radius:5px;padding:7px;color:#F5F3FF;selection-background-color:#7C3AED;}
        QLineEdit:focus,QSpinBox:focus,QComboBox:focus {border-color:#22D3EE;}
        QTabWidget::pane {border:1px solid #52525B;background:#09090B;}
        QTabBar::tab {background:#09090B;color:#A1A1AA;padding:9px 18px;border:1px solid #52525B;border-bottom:none;}
        QTabBar::tab:selected {color:#67E8F9;border-color:#7C3AED;}
        QStatusBar {background:#09090B;color:#A78BFA;}
    )QSS"));
    auto* root=new QWidget(this);
    auto* row=new QHBoxLayout(root);row->setContentsMargins(0,0,0,0);row->setSpacing(0);
    auto* sidebar=new QFrame(root);sidebar->setObjectName(QStringLiteral("sidebar"));sidebar->setFixedWidth(260);
    auto* left=new QVBoxLayout(sidebar);left->setContentsMargins(12,12,12,12);left->setSpacing(7);
    auto* logo=new QLabel(sidebar);logo->setAlignment(Qt::AlignHCenter|Qt::AlignTop);logo->setMinimumHeight(230);
    QPixmap photo(QDir(root_).filePath(QStringLiteral("assets/neebles-secrets-logo.png")));
    if(!photo.isNull()) logo->setPixmap(photo.scaled(236,230,Qt::KeepAspectRatio,Qt::SmoothTransformation));
    left->addWidget(logo);left->addSpacing(10);
    const QStringList labels={QStringLiteral("⌂  Dashboard"),QStringLiteral("⚡  Quick Secrets"),
        QStringLiteral("▤  My Secrets"),QStringLiteral("◈  Crypto Lab"),
        QStringLiteral("⚙  Batch Generator"),QStringLiteral("▤  Batch Exporter"),
        QStringLiteral("◉  Backup & Restore")};
    for(int i=0;i<labels.size();++i){
        auto* button=new QPushButton(labels[i],sidebar);button->setObjectName(QStringLiteral("adminNavButton"));button->setCheckable(true);
        navigation_.append(button);left->addWidget(button);
        connect(button,&QPushButton::clicked,this,[this,i](){showView(i);});
    }
    left->addStretch();
    unlock_=new QPushButton(QStringLiteral("🔒  Desbloquear"),sidebar);
    unlock_->setObjectName(QStringLiteral("unlockButton"));
    unlock_->setVisible(false); // never show before vault-general exists
    left->addWidget(unlock_);
    left->addWidget(note(QStringLiteral("Secrets v1.0.4"),sidebar));
    row->addWidget(sidebar);
    auto* right=new QWidget(root);auto* rightLayout=new QVBoxLayout(right);
    auto* header=new QHBoxLayout();
    header->addWidget(note(QStringLiteral("N.E.E.B.L.E.S. Secrets"),right));
    header->addStretch();
    status_=new QLabel(QStringLiteral("Bloqueado"),right);header->addWidget(status_);
    rightLayout->addLayout(header);
    tabs_=new QTabWidget(right);tabs_->setTabsClosable(false);tabs_->setMovable(false);tabs_->setDocumentMode(true);
    views_=new QStackedWidget(tabs_);
    buildDashboard();buildQuick();buildVaults();buildCryptoLab();buildBatch();buildBatchExport();buildBackupPreview();
    tabs_->addTab(views_,QStringLiteral("Dashboard"));
    rightLayout->addWidget(tabs_,1);row->addWidget(right,1);
    setCentralWidget(root);
    connect(unlock_,&QPushButton::clicked,this,[this](){ toggleUnlock(); });
    reloadLanguage(true);
    auto* languageTimer=new QTimer(this);
    languageTimer->setInterval(2000);
    connect(languageTimer,&QTimer::timeout,this,[this](){reloadLanguage(false);});
    languageTimer->start();
    showView(0);refreshStatus();
    // Periodic status is asynchronous and has a strict deadline; a stalled
    // daemon must never block Qt's GUI thread for the IPC read timeout.
    statusProbeTimer_=new QTimer(this);
    statusProbeTimer_->setInterval(2500);
    connect(statusProbeTimer_,&QTimer::timeout,this,[this](){startStatusProbe();});
    statusProbeTimer_->start();
    // First run prompts for the ONE global master password and creates only vault-general.
    // It NEVER creates vaults on behalf of modules.
    QTimer::singleShot(0,this,[this](){
        QString error;
        const auto status=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("vault.status")}},&error);
        if(status.value(QStringLiteral("ok")).toBool() &&
           !status.value(QStringLiteral("data")).toObject().value(QStringLiteral("initialized")).toBool())
            toggleUnlock();
    });
}
MainWindow::~MainWindow(){
    if(statusProbeTimer_)statusProbeTimer_->stop();
    cancelStatusProbe();
    if(batchExportCancelFlag_)batchExportCancelFlag_->store(true);
    if(batchExportThread_ && batchExportThread_->isRunning()){
        batchExportThread_->wait(); // Worker checks cancellation between IPC batches.
    }
    if(backupCancel_)backupCancel_->store(true);
    if(backupThread_ && backupThread_->isRunning())backupThread_->wait();
    if(restoreInspectCancel_)restoreInspectCancel_->store(true);
    if(restoreInspectThread_ && restoreInspectThread_->isRunning())restoreInspectThread_->wait();
}

// Boss is the authority for module language. Secrets reads its own installed
// Settings and module catalogs; it never writes the settings file or changes
// Boss language on its own. This also covers updates while the UI is running.
void MainWindow::reloadLanguage(bool force){
    QString requested=QStringLiteral("en_US");
    QFile settings(QStringLiteral("/opt/neebles/shared/settings/local_settings_neebles-secrets.json"));
    if(settings.open(QIODevice::ReadOnly)){
        const auto json=QJsonDocument::fromJson(settings.readAll()).object();
        const auto selected=json.value(QStringLiteral("ui")).toObject().value(QStringLiteral("language")).toString();
        if(selected==QStringLiteral("es_CL") || selected==QStringLiteral("en_US"))requested=selected;
    }else{
        QFile defaults(QDir(root_).filePath(QStringLiteral("settings/default.json")));
        if(defaults.open(QIODevice::ReadOnly)){
            const auto data=QJsonDocument::fromJson(defaults.readAll()).object();
            const auto selected=data.value(QStringLiteral("ui")).toObject().value(QStringLiteral("language")).toString();
            if(selected==QStringLiteral("es_CL") || selected==QStringLiteral("en_US"))requested=selected;
        }
    }
    if(!force && requested==language_)return;
    QFile file(QDir(root_).filePath(QStringLiteral("languages/")+requested+QStringLiteral(".json")));
    if(!file.open(QIODevice::ReadOnly))return;
    const auto doc=QJsonDocument::fromJson(file.readAll());
    if(!doc.isObject())return;
    translations_=doc.object();language_=requested;
    retranslateUi();
    if(!force && status_)refreshStatus();
}
QString MainWindow::translateText(const QString& source) const{
    const QByteArray hash=QCryptographicHash::hash(source.toUtf8(),QCryptographicHash::Sha256).toHex().left(12);
    const QString key=QStringLiteral("ui.literal.")+QString::fromLatin1(hash);
    return translations_.value(key).toString(source);
}
void MainWindow::retranslateUi(){
    // Keep canonical original text only on labels and controls, never on input
    // values, clipboard contents, KDBX, process state or user-entered names.
    const auto translatable=[this](QObject* obj,const QString& current,const char* property){
        QString original=obj->property(property).toString();
        if(original.isEmpty()){
            original=current;
            obj->setProperty(property,original);
        }
        return translateText(original);
    };
    for(auto* label:findChildren<QLabel*>()){
        if(label==status_||label==dashboardService_||label==dashboardVault_||label==dashboardModules_||label==vaultMessage_)continue;
        label->setText(translatable(label,label->text(),"neebles.originalText"));
    }
    for(auto* button:findChildren<QAbstractButton*>()){
        if(button==unlock_)continue;
        button->setText(translatable(button,button->text(),"neebles.originalText"));
    }
    for(auto* line:findChildren<QLineEdit*>()){
        if(!line->placeholderText().isEmpty())
            line->setPlaceholderText(translatable(line,line->placeholderText(),"neebles.originalPlaceholder"));
    }
    for(auto* box:findChildren<QComboBox*>()){
        for(int i=0;i<box->count();++i){
            QString original=box->itemData(i,Qt::UserRole+10).toString();
            if(original.isEmpty()){
                original=box->itemText(i);box->setItemData(i,original,Qt::UserRole+10);
            }
            box->setItemText(i,translateText(original));
        }
    }
    // Dynamic labels are derived from daemon status and translated after the
    // catalog reload. No IPC is triggered solely by the catalog re-render.
    const QStringList names={QStringLiteral("Dashboard"),QStringLiteral("Quick Secrets"),
        QStringLiteral("My Secrets"),QStringLiteral("Crypto Lab"),QStringLiteral("Batch Generator"),
        QStringLiteral("Batch Exporter"),QStringLiteral("Backup & Restore")};
    const int selected=views_?views_->currentIndex():0;
    if(tabs_ && selected>=0&&selected<names.size())tabs_->setTabText(0,translateText(names[selected]));
    if(status_){
        const QString previous=status_->text();
        if(previous.contains(QStringLiteral("Offline"),Qt::CaseInsensitive) || previous.contains(QStringLiteral("Sin conexión")))
            status_->setText(translateText(QStringLiteral("● Sin conexión")));
        else if(previous.contains(QStringLiteral("Desbloqueado"),Qt::CaseInsensitive)||previous.contains(QStringLiteral("Unlocked"),Qt::CaseInsensitive))
            status_->setText(translateText(QStringLiteral("● Desbloqueado")));
        else status_->setText(translateText(QStringLiteral("● Bloqueado")));
    }
    // Do not invoke refreshStatus() here: it would read IPC simply to change UI language.
}

void MainWindow::showView(int index){
    if(index<0||index>=7)return;
    // The sidebar, dashboard shortcut and programmatic navigation share
    // this guard. Never enter My Secrets using a cached unlock state.
    if(index==2){
        refreshStatus();
        if(!personalAvailable_){
            statusBar()->showMessage(translateText(QStringLiteral("Desbloquea Secrets para acceder a My Secrets.")),4000);
            return;
        }
    }
    const QStringList names={QStringLiteral("Dashboard"),QStringLiteral("Quick Secrets"),
        QStringLiteral("My Secrets"),QStringLiteral("Crypto Lab"),
        QStringLiteral("Batch Generator"),QStringLiteral("Batch Exporter"),QStringLiteral("Backup & Restore")};
    const int previous=views_->currentIndex();
    if(previous==1 && index!=1 && generated_) generated_->clear();
    if(previous==2 && index!=2) clearPersonalEditor();
    if(previous==3 && index!=3) clearCryptoLab();
    if(previous==4 && index!=4) stopBatch(true);
    views_->setCurrentIndex(index);
    tabs_->setTabText(0,translateText(names[index]));
    for(int i=0;i<navigation_.size();++i)navigation_[i]->setChecked(i==index);
    if(index==0)refreshStatus();
    if(index==2)refreshPersonalList();
}
// Disable all entry points to My Secrets and close its view if lock or
// service loss is detected. Do not navigate through showView(): that would
// recursively issue another synchronous status request.
void MainWindow::setPersonalAvailable(bool available){
    personalAvailable_=available;
    if(navigation_.size()>2)navigation_[2]->setEnabled(available);
    if(personalShortcut_)personalShortcut_->setEnabled(available);
    if(!available){
        if(personalList_)personalList_->clear();
        clearPersonalEditor();
        if(views_ && views_->currentIndex()==2){
            views_->setCurrentIndex(0);
            tabs_->setTabText(0,translateText(QStringLiteral("Dashboard")));
            for(int i=0;i<navigation_.size();++i)
                navigation_[i]->setChecked(i==0);
        }
    }
}
void MainWindow::buildDashboard(){
    auto* scroll=new QScrollArea(views_);
    scroll->setWidgetResizable(true);
    auto* page=new QWidget(scroll);
    auto* layout=new QVBoxLayout(page);
    layout->setContentsMargins(20,16,20,18);
    layout->setSpacing(18);
    layout->addWidget(heading(QStringLiteral("Dashboard"),page));
    layout->addWidget(note(QStringLiteral("Gestiona tus bóvedas y accede a las herramientas criptográficas."),page));
    auto* banner=new QFrame(page);banner->setObjectName(QStringLiteral("informationPanel"));
    auto* bannerLayout=new QVBoxLayout(banner);
    bannerLayout->addWidget(note(QStringLiteral("Quick Secrets funciona sin desbloquear. Las operaciones de My Secrets requieren la bóveda desbloqueada."),banner));
    layout->addWidget(banner);
    auto* cards=new QGridLayout();cards->setSpacing(14);
    auto createCard=[page,cards](int index,const QString& title,const QString& detail)->QLabel*{
        auto* card=new QFrame(page);card->setObjectName(QStringLiteral("panelCard"));
        auto* column=new QVBoxLayout(card);column->setContentsMargins(16,16,16,18);column->setSpacing(9);
        auto* name=new QLabel(title,card);name->setObjectName(QStringLiteral("panelHeading"));column->addWidget(name);
        auto* explanation=note(detail,card);column->addWidget(explanation);
        auto* status=new QLabel(card);status->setObjectName(QStringLiteral("valueStatus"));column->addWidget(status);
        column->addStretch();cards->addWidget(card,0,index);
        return status;
    };
    dashboardService_=createCard(0,QStringLiteral("Estado del servicio"),QStringLiteral("Disponibilidad del motor de Secrets."));
    dashboardVault_=createCard(1,QStringLiteral("Bóveda personal"),QStringLiteral("Tus secretos personales en vault-general.kdbx."));
    dashboardModules_=createCard(2,QStringLiteral("Bóvedas de módulos"),QStringLiteral("Cada módulo solicita y utiliza únicamente su propia bóveda."));
    layout->addLayout(cards);
    layout->addWidget(heading(QStringLiteral("Accesos rápidos"),page));
    auto* shortcuts=new QGridLayout();shortcuts->setSpacing(10);
    const QStringList items={QStringLiteral("⚡  Quick Secrets"),QStringLiteral("▤  My Secrets"),
        QStringLiteral("◈  Crypto Lab"),QStringLiteral("⚙  Batch Generator"),
        QStringLiteral("▤  Batch Exporter"),QStringLiteral("◉  Backup & Restore")};
    for(int i=0;i<items.size();++i){
        auto* action=new QPushButton(items[i],page);
        action->setMinimumHeight(62);
        shortcuts->addWidget(action,i/3,i%3);
        if(i==1)personalShortcut_=action;
        connect(action,&QPushButton::clicked,this,[this,i](){showView(i+1);});
    }
    layout->addLayout(shortcuts);
    auto* refresh=new QPushButton(QStringLiteral("Actualizar estado"),page);
    layout->addWidget(refresh,0,Qt::AlignLeft);
    connect(refresh,&QPushButton::clicked,this,[this](){refreshStatus();});
    layout->addStretch();scroll->setWidget(page);views_->addWidget(scroll);
}
void MainWindow::buildQuick(){
    auto* page=new QWidget(views_);auto* layout=new QVBoxLayout(page);
    layout->addWidget(heading(QStringLiteral("Quick Secrets"),page));
    layout->addWidget(note(QStringLiteral("Genera, copia o guarda secretos. Quick Secrets funciona aunque la bóveda esté bloqueada."),page));
    auto* form=new QFormLayout();
    kind_=new QComboBox(page);
    kind_->addItem(QStringLiteral("Contraseña segura"),QStringLiteral("password"));
    kind_->addItem(QStringLiteral("Token hexadecimal"),QStringLiteral("hex"));
    kind_->addItem(QStringLiteral("Token Base64URL"),QStringLiteral("base64url"));
    kind_->addItem(QStringLiteral("Token Base64"),QStringLiteral("base64"));
    kind_->addItem(QStringLiteral("Salt aleatorio (hex)"),QStringLiteral("salt"));
    kind_->addItem(QStringLiteral("Pepper aleatorio (hex)"),QStringLiteral("pepper"));
    kind_->addItem(QStringLiteral("Clave aleatoria (hex)"),QStringLiteral("key"));
    kind_->addItem(QStringLiteral("UUID v4"),QStringLiteral("uuid"));
    length_=new QSpinBox(page);length_->setRange(8,512);length_->setValue(24);
    form->addRow(QStringLiteral("Tipo"),kind_);form->addRow(QStringLiteral("Longitud"),length_);
    layout->addLayout(form);
    uppercase_=new QCheckBox(QStringLiteral("Mayúsculas"),page);uppercase_->setChecked(true);
    lowercase_=new QCheckBox(QStringLiteral("Minúsculas"),page);lowercase_->setChecked(true);
    numbers_=new QCheckBox(QStringLiteral("Números"),page);numbers_->setChecked(true);
    symbols_=new QCheckBox(QStringLiteral("Caracteres especiales"),page);symbols_->setChecked(true);
    ambiguous_=new QCheckBox(QStringLiteral("Excluir caracteres ambiguos (0/O/1/l/I/|)"),page);
    for(auto* option:{uppercase_,lowercase_,numbers_,symbols_,ambiguous_})layout->addWidget(option);
    connect(kind_,&QComboBox::currentIndexChanged,this,[this](int){
        const QString kind=kind_->currentData().toString();
        const bool pw=kind==QStringLiteral("password");
        for(auto* option:{uppercase_,lowercase_,numbers_,symbols_,ambiguous_}) option->setVisible(pw);
        length_->setEnabled(kind!=QStringLiteral("uuid"));
        if(kind==QStringLiteral("uuid")) length_->setValue(16);
        else if(pw) { length_->setRange(8,512);length_->setValue(24); }
        else { length_->setRange(16,512);length_->setValue(32); }
    });
    auto* buttons=new QHBoxLayout();
    auto* run=new QPushButton(QStringLiteral("Generar"),page);buttons->addWidget(run);
    generated_=new QLineEdit(page);generated_->setReadOnly(true);
    generated_->setPlaceholderText(QStringLiteral("Resultado generado por Rust"));
    buttons->addWidget(generated_,1);
    copy_=new QPushButton(QStringLiteral("Copiar"),page);buttons->addWidget(copy_);
    layout->addLayout(buttons);
    save_=new QPushButton(QStringLiteral("Guardar en vault-general (requiere desbloquear)"),page);
    save_->setEnabled(false);layout->addWidget(save_,0,Qt::AlignLeft);
    connect(save_,&QPushButton::clicked,this,[this](){
        if(generated_->text().isEmpty())return;
        bool accepted=false;
        const QString title=QInputDialog::getText(this,QStringLiteral("Guardar en My Secrets"),
            QStringLiteral("Nombre del secreto"),QLineEdit::Normal,QString(),&accepted).trimmed();
        if(!accepted||title.isEmpty()||title.size()>200)return;
        const QString id=QStringLiteral("secret-")+QUuid::createUuid().toString(QUuid::WithoutBraces);
        const QJsonObject value{{QStringLiteral("name"),title},
            {QStringLiteral("type"),kind_->currentData().toString()},
            {QStringLiteral("tags"),QStringLiteral("quick")},
            {QStringLiteral("content"),generated_->text()}};
        QString error;
        const auto result=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("general.put")},
            {QStringLiteral("id"),id},{QStringLiteral("value"),value}},&error);
        if(!result.value(QStringLiteral("ok")).toBool()){
            QMessageBox::warning(this,QStringLiteral("Quick Secrets"),error.isEmpty()?errorText(result):error);
            return;
        }
        statusBar()->showMessage(QStringLiteral("Guardado cifrado en vault-general"),4000);
    });
    layout->addWidget(note(QStringLiteral("Al cambiar de pantalla se borra el resultado temporal. Copiar o guardar requiere una acción explícita."),page));
    layout->addStretch();
    connect(run,&QPushButton::clicked,this,[this](){generate();});
    connect(copy_,&QPushButton::clicked,this,[this](){
        if(!generated_->text().isEmpty()) QApplication::clipboard()->setText(generated_->text());
    });
    views_->addWidget(page);
}
void MainWindow::buildCryptoLab(){
    auto* page=new QWidget(views_);
    auto* layout=new QVBoxLayout(page);
    layout->addWidget(heading(QStringLiteral("Cryptographic Lab"),page));
    layout->addWidget(note(QStringLiteral("SHA-2, SHA-3, BLAKE2, HMAC y derivación con PBKDF2/Argon2id/scrypt ejecutados en Rust. No se guardan resultados ni claves automáticamente."),page));
    auto* form=new QFormLayout();
    labFamily_=new QComboBox(page);
    labFamily_->addItem(QStringLiteral("Hash irreversible"),QStringLiteral("hash"));
    labFamily_->addItem(QStringLiteral("HMAC con clave"),QStringLiteral("hmac"));
    labFamily_->addItem(QStringLiteral("Derivación KDF"),QStringLiteral("kdf"));
    labAlgorithm_=new QComboBox(page);
    labEncoding_=new QComboBox(page);
    labEncoding_->addItem(QStringLiteral("Hexadecimal"),QStringLiteral("hex"));
    labEncoding_->addItem(QStringLiteral("Base64"),QStringLiteral("base64"));
    labEncoding_->addItem(QStringLiteral("Base64URL"),QStringLiteral("base64url"));
    labInput_=new QLineEdit(page);
    labInput_->setMaxLength(4096);
    labInput_->setPlaceholderText(QStringLiteral("Texto o contraseña a procesar localmente"));
    labKey_=new QLineEdit(page);
    labKey_->setEchoMode(QLineEdit::Password);
    labKey_->setMaxLength(1024);
    labKey_->setPlaceholderText(QStringLiteral("Clave HMAC; no se almacena"));
    labSalt_=new QLineEdit(page);
    labSalt_->setMaxLength(128);
    labSalt_->setPlaceholderText(QStringLiteral("Salt hexadecimal opcional (vacío = aleatorio)"));
    labIterations_=new QSpinBox(page);labIterations_->setRange(10000,500000);labIterations_->setValue(100000);
    labMemory_=new QSpinBox(page);labMemory_->setRange(8192,32768);labMemory_->setValue(16384);
    labParallelism_=new QSpinBox(page);labParallelism_->setRange(1,4);labParallelism_->setValue(1);
    labBytes_=new QSpinBox(page);labBytes_->setRange(16,64);labBytes_->setValue(32);
    labScryptLogN_=new QSpinBox(page);labScryptLogN_->setRange(10,15);labScryptLogN_->setValue(14);
    form->addRow(QStringLiteral("Familia"),labFamily_);
    form->addRow(QStringLiteral("Algoritmo"),labAlgorithm_);
    form->addRow(QStringLiteral("Entrada"),labInput_);
    form->addRow(QStringLiteral("Clave HMAC"),labKey_);
    form->addRow(QStringLiteral("Salt hex"),labSalt_);
    form->addRow(QStringLiteral("Iteraciones"),labIterations_);
    form->addRow(QStringLiteral("Memoria Argon2 (KiB)"),labMemory_);
    form->addRow(QStringLiteral("Paralelismo Argon2"),labParallelism_);
    form->addRow(QStringLiteral("Costo scrypt (log₂ N)"),labScryptLogN_);
    form->addRow(QStringLiteral("Bytes de salida"),labBytes_);
    form->addRow(QStringLiteral("Formato"),labEncoding_);
    labVerify_=new QCheckBox(QStringLiteral("Verificar un resultado existente"),page);
    labExpected_=new QLineEdit(page);
    labExpected_->setMaxLength(256);
    labExpected_->setPlaceholderText(QStringLiteral("Hash/HMAC/derivación esperada en formato seleccionado"));
    form->addRow(labVerify_);
    form->addRow(QStringLiteral("Resultado esperado"),labExpected_);
    labExpected_->setVisible(false);
    layout->addLayout(form);
    labOutput_=new QLineEdit(page);
    labOutput_->setReadOnly(true);
    labOutput_->setPlaceholderText(QStringLiteral("Resultado criptográfico; no se guarda"));
    labResultSalt_=new QLineEdit(page);
    labResultSalt_->setReadOnly(true);
    labResultSalt_->setPlaceholderText(QStringLiteral("Salt usado por KDF"));
    layout->addWidget(labOutput_);
    layout->addWidget(labResultSalt_);
    auto* actions=new QHBoxLayout();
    auto* run=new QPushButton(QStringLiteral("Calcular"),page);
    auto* copy=new QPushButton(QStringLiteral("Copiar resultado"),page);
    auto* copySalt=new QPushButton(QStringLiteral("Copiar salt"),page);
    auto* clear=new QPushButton(QStringLiteral("Limpiar campos"),page);
    for(auto* action:{run,copy,copySalt,clear}) actions->addWidget(action);
    layout->addLayout(actions);
    layout->addWidget(note(QStringLiteral("Solo la interfaz de Secrets puede llamar crypto.compute. Las entradas permanecen en memoria durante la operación. No reutilices un pepper como salt público."),page));
    layout->addStretch();
    auto update=[this](){
        const QString family=labFamily_->currentData().toString();
        const bool isKdf=family==QStringLiteral("kdf");
        const bool isHmac=family==QStringLiteral("hmac");
        labAlgorithm_->clear();
        if(family==QStringLiteral("hash")){
            for(const auto& a:{"sha256","sha512","sha3-256","sha3-512","blake2b512","blake2s256"}) labAlgorithm_->addItem(QString::fromLatin1(a));
        }else if(isHmac){
            for(const auto& a:{"hmac-sha256","hmac-sha512"}) labAlgorithm_->addItem(QString::fromLatin1(a));
        }else{
            for(const auto& a:{"argon2id","pbkdf2-sha256","pbkdf2-sha512","scrypt"}) labAlgorithm_->addItem(QString::fromLatin1(a));
        }
        labKey_->setVisible(isHmac);
        labSalt_->setVisible(isKdf);
        labResultSalt_->setVisible(isKdf);
        labIterations_->setVisible(isKdf);
        labMemory_->setVisible(isKdf);
        labParallelism_->setVisible(isKdf);
        labBytes_->setVisible(isKdf);
        labScryptLogN_->setVisible(isKdf&&labAlgorithm_->currentText()==QStringLiteral("scrypt"));
        labOutput_->clear();labResultSalt_->clear();
    };
    connect(labFamily_,&QComboBox::currentIndexChanged,this,[update](int){update();});
    connect(labVerify_,&QCheckBox::toggled,this,[this,copy,copySalt](bool verify){
        labExpected_->setVisible(verify);
        labOutput_->clear();labResultSalt_->clear();
        copy->setEnabled(!verify);
        copySalt->setEnabled(!verify);
    });
    auto updateKdf=[this](){
        const bool isArgon=labAlgorithm_->currentText()==QStringLiteral("argon2id");
        const bool isScrypt=labAlgorithm_->currentText()==QStringLiteral("scrypt");
        const bool isKdf=labFamily_->currentData().toString()==QStringLiteral("kdf");
        labMemory_->setVisible(isKdf&&isArgon);
        labParallelism_->setVisible(isKdf&&isArgon);
        labScryptLogN_->setVisible(isKdf&&isScrypt);
        labIterations_->setVisible(isKdf&&!isScrypt);
        if(isArgon){labIterations_->setRange(1,3);labIterations_->setValue(2);}
        else{labIterations_->setRange(10000,500000);labIterations_->setValue(100000);}
    };
    connect(labAlgorithm_,&QComboBox::currentIndexChanged,this,[updateKdf](int){updateKdf();});
    connect(run,&QPushButton::clicked,this,[this](){
        labOutput_->clear();labResultSalt_->clear();
        const QJsonObject args{{QStringLiteral("op"),QStringLiteral("crypto.compute")},
            {QStringLiteral("family"),labFamily_->currentData().toString()},
            {QStringLiteral("algorithm"),labAlgorithm_->currentText()},
            {QStringLiteral("text"),labInput_->text()},
            {QStringLiteral("key"),labKey_->text()},
            {QStringLiteral("salt_hex"),labSalt_->text().trimmed()},
            {QStringLiteral("iterations"),labIterations_->value()},
            {QStringLiteral("memory_kib"),labMemory_->value()},
            {QStringLiteral("parallelism"),labParallelism_->value()},
            {QStringLiteral("output_bytes"),labBytes_->value()},
            {QStringLiteral("scrypt_log_n"),labScryptLogN_->value()},
            {QStringLiteral("encoding"),labEncoding_->currentData().toString()},
            {QStringLiteral("verify"),labVerify_->isChecked()},
            {QStringLiteral("expected"),labExpected_->text().trimmed()}};
        QString error;
        const auto answer=call(args,&error);
        if(!answer.value(QStringLiteral("ok")).toBool()){
            QMessageBox::warning(this,QStringLiteral("Cryptographic Lab"),
                error.isEmpty()?errorText(answer):error);
            return;
        }
        const auto result=answer.value(QStringLiteral("data")).toObject();
        if(labVerify_->isChecked()){
            labOutput_->setText(result.value(QStringLiteral("verified")).toBool()
                ?QStringLiteral("COINCIDE"):QStringLiteral("NO COINCIDE"));
            labResultSalt_->clear();
            statusBar()->showMessage(QStringLiteral("Verificación Rust terminada; no guardada"),3000);
        }else{
            labOutput_->setText(result.value(QStringLiteral("value")).toString());
            labResultSalt_->setText(result.value(QStringLiteral("salt_hex")).toString());
            statusBar()->showMessage(QStringLiteral("Cálculo Rust terminado; no guardado"),3000);
        }
    });
    connect(copy,&QPushButton::clicked,this,[this](){
        if(!labOutput_->text().isEmpty()) QApplication::clipboard()->setText(labOutput_->text());
    });
    connect(copySalt,&QPushButton::clicked,this,[this](){
        if(!labResultSalt_->text().isEmpty()) QApplication::clipboard()->setText(labResultSalt_->text());
    });
    connect(clear,&QPushButton::clicked,this,[this](){clearCryptoLab();});
    update();updateKdf();
    views_->addWidget(page);
}
void MainWindow::clearCryptoLab(){
    if(labInput_)labInput_->clear();
    if(labExpected_)labExpected_->clear();
    if(labKey_)labKey_->clear();
    if(labSalt_)labSalt_->clear();
    if(labOutput_)labOutput_->clear();
    if(labResultSalt_)labResultSalt_->clear();
}

void MainWindow::buildBatch(){
    auto* page=new QWidget(views_);
    auto* layout=new QVBoxLayout(page);
    layout->addWidget(heading(QStringLiteral("Batch Generator"),page));
    layout->addWidget(note(QStringLiteral("Genera resultados temporales mediante Rust/CSPRNG. La vista previa admite hasta 500 valores y no se guarda automáticamente."),page));
    auto* form=new QFormLayout();
    batchKind_=new QComboBox(page);
    batchKind_->addItem(QStringLiteral("Contraseñas"),QStringLiteral("password"));
    batchKind_->addItem(QStringLiteral("Tokens hex"),QStringLiteral("hex"));
    batchKind_->addItem(QStringLiteral("Tokens Base64URL"),QStringLiteral("base64url"));
    batchKind_->addItem(QStringLiteral("Tokens Base64"),QStringLiteral("base64"));
    batchKind_->addItem(QStringLiteral("UUID v4"),QStringLiteral("uuid"));
    batchKind_->addItem(QStringLiteral("Salts hex"),QStringLiteral("salt"));
    batchKind_->addItem(QStringLiteral("Peppers hex"),QStringLiteral("pepper"));
    batchKind_->addItem(QStringLiteral("Claves hex"),QStringLiteral("key"));
    batchLength_=new QSpinBox(page);batchLength_->setRange(8,512);batchLength_->setValue(32);
    batchCount_=new QSpinBox(page);batchCount_->setRange(1,500);batchCount_->setValue(25);
    form->addRow(QStringLiteral("Tipo"),batchKind_);
    form->addRow(QStringLiteral("Longitud (caracteres para passwords; bytes para tokens)"),batchLength_);
    form->addRow(QStringLiteral("Cantidad"),batchCount_);
    layout->addLayout(form);
    auto* actions=new QHBoxLayout();
    batchStart_=new QPushButton(QStringLiteral("Generar lote"),page);
    batchCancel_=new QPushButton(QStringLiteral("Cancelar"),page);
    batchCancel_->setEnabled(false);
    auto* copy=new QPushButton(QStringLiteral("Copiar resultados"),page);
    actions->addWidget(batchStart_);actions->addWidget(batchCancel_);actions->addWidget(copy);
    layout->addLayout(actions);
    batchProgress_=new QProgressBar(page);batchProgress_->setRange(0,100);batchProgress_->setValue(0);
    layout->addWidget(batchProgress_);
    batchPreview_=new QPlainTextEdit(page);batchPreview_->setReadOnly(true);
    batchPreview_->setMaximumBlockCount(500);
    batchPreview_->setPlaceholderText(QStringLiteral("Resultados efímeros; no se guardan automáticamente."));
    layout->addWidget(batchPreview_,1);
    connect(batchStart_,&QPushButton::clicked,this,[this](){
        if(batchRunning_)return;
        batchPreview_->clear();batchTotal_=batchCount_->value();batchRemaining_=batchTotal_;
        batchRunning_=true;batchStart_->setEnabled(false);batchCancel_->setEnabled(true);
        batchProgress_->setRange(0,batchTotal_);batchProgress_->setValue(0);
        QTimer::singleShot(0,this,[this](){runBatchChunk();});
    });
    connect(batchCancel_,&QPushButton::clicked,this,[this](){stopBatch(false);});
    connect(copy,&QPushButton::clicked,this,[this](){
        if(batchPreview_ && !batchPreview_->toPlainText().isEmpty())
            QApplication::clipboard()->setText(batchPreview_->toPlainText());
    });
    connect(batchKind_,&QComboBox::currentIndexChanged,this,[this](int){
        const QString kind=batchKind_->currentData().toString();
        if(kind==QStringLiteral("uuid"))batchLength_->setEnabled(false);
        else{
            batchLength_->setEnabled(true);
            batchLength_->setMinimum(kind==QStringLiteral("password")?8:16);
        }
    });
    views_->addWidget(page);
}
void MainWindow::buildBatchExport(){
    auto* page=new QWidget(views_);
    auto* layout=new QVBoxLayout(page);
    layout->setContentsMargins(22,20,22,20);
    layout->setSpacing(14);
    layout->addWidget(heading(QStringLiteral("Batch Exporter"),page));
    layout->addWidget(note(QStringLiteral("Genera y exporta hasta 100.000 resultados nuevos sin mantener el lote completo en memoria."),page));
    layout->addWidget(note(QStringLiteral("Selecciona el tipo, la longitud y el formato de salida. La exportación no modifica tu bóveda."),page));
    auto* exportControls=new QFormLayout();
    batchExportKind_=new QComboBox(page);
    for(int i=0;i<batchKind_->count();++i)
        batchExportKind_->addItem(batchKind_->itemText(i),batchKind_->itemData(i));
    batchExportKind_->setCurrentIndex(batchKind_->currentIndex());
    batchExportLength_=new QSpinBox(page);
    batchExportLength_->setRange(8,512);
    batchExportLength_->setValue(batchLength_->value());
    exportControls->addRow(QStringLiteral("Tipo"),batchExportKind_);
    exportControls->addRow(QStringLiteral("Longitud"),batchExportLength_);
    batchExportFormat_=new QComboBox(page);
    batchExportFormat_->addItem(QStringLiteral("TXT (sin cifrar)"),QStringLiteral("txt"));
    batchExportFormat_->addItem(QStringLiteral("CSV (sin cifrar)"),QStringLiteral("csv"));
    batchExportFormat_->addItem(QStringLiteral("JSON (sin cifrar)"),QStringLiteral("json"));
    batchExportFormat_->addItem(QStringLiteral("KDBX (cifrado / contraseña independiente)"),QStringLiteral("kdbx"));
    batchExportCount_=new QSpinBox(page);
    batchExportCount_->setRange(1,100000);
    batchExportCount_->setValue(1000);
    exportControls->addRow(QStringLiteral("Formato de exportación"),batchExportFormat_);
    exportControls->addRow(QStringLiteral("Cantidad (independiente de vista previa)"),batchExportCount_);
    layout->addLayout(exportControls);
    auto* exportActions=new QHBoxLayout();
    batchExportStart_=new QPushButton(QStringLiteral("Generar y exportar a archivo"),page);
    batchExportCancelButton_=new QPushButton(QStringLiteral("Cancelar exportación"),page);
    batchExportCancelButton_->setEnabled(false);
    exportActions->addWidget(batchExportStart_);
    exportActions->addWidget(batchExportCancelButton_);
    layout->addLayout(exportActions);
    batchExportProgress_=new QProgressBar(page);
    batchExportProgress_->setRange(0,100);
    batchExportProgress_->setValue(0);
    layout->addWidget(batchExportProgress_);
    layout->addWidget(note(QStringLiteral("La exportación genera un lote nuevo de 1 a 100.000 elementos. "
        "Los formatos TXT, CSV y JSON guardan contenido SIN CIFRAR únicamente con tu autorización. "
        "KDBX crea una bóveda portátil nueva con contraseña independiente; limitado a 250 elementos en esta fase."),page));
    layout->addWidget(note(QStringLiteral("Los resultados se borran al salir de esta pantalla. "
        "La copia al portapapeles es explícita. No se crean archivos ni perfiles."),page));
    connect(batchExportKind_,&QComboBox::currentIndexChanged,this,[this](int){
        const QString kind=batchExportKind_->currentData().toString();
        if(kind==QStringLiteral("uuid"))batchExportLength_->setEnabled(false);
        else{
            batchExportLength_->setEnabled(true);
            batchExportLength_->setMinimum(kind==QStringLiteral("password")?8:16);
        }
    });
    connect(batchExportStart_,&QPushButton::clicked,this,[this](){startBatchExport();});
    connect(batchExportCancelButton_,&QPushButton::clicked,this,[this](){
        if(batchExportCancelFlag_)batchExportCancelFlag_->store(true);
        batchExportCancelButton_->setEnabled(false);
        statusBar()->showMessage(QStringLiteral("Cancelando exportación…"));
    });
    layout->addStretch();
    views_->addWidget(page);
}
void MainWindow::buildBackupPreview(){
    auto* page=new QWidget(views_);
    auto* layout=new QVBoxLayout(page);
    layout->setContentsMargins(22,20,22,20);layout->setSpacing(14);
    layout->addWidget(heading(QStringLiteral("Backup & Restore"),page));
    auto* info=new QFrame(page);info->setObjectName(QStringLiteral("informationPanel"));
    auto* infoColumn=new QVBoxLayout(info);
    infoColumn->addWidget(note(QStringLiteral("Los respaldos conservan los archivos KDBX originales cifrados. La Master Key nunca se incluye."),info));
    infoColumn->addWidget(note(QStringLiteral("Guarda una copia de la Master Key por un medio independiente. Sin ella no podrás abrir estos respaldos."),info));
    infoColumn->addWidget(note(QStringLiteral("El inventario del respaldo completo contiene nombres y SHA-256 sin cifrar; el contenido KDBX permanece cifrado."),info));
    layout->addWidget(info);
    auto* actions=new QHBoxLayout();
    backupSingleButton_=new QPushButton(QStringLiteral("Respaldar una bóveda KDBX"),page);
    backupFullButton_=new QPushButton(QStringLiteral("Respaldo completo (KDBX cifrados)"),page);
    backupCancelButton_=new QPushButton(QStringLiteral("Cancelar respaldo"),page);
    backupCancelButton_->setEnabled(false);
    actions->addWidget(backupSingleButton_);actions->addWidget(backupFullButton_);
    actions->addWidget(backupCancelButton_);layout->addLayout(actions);
    backupProgress_=new QProgressBar(page);backupProgress_->setRange(0,100);backupProgress_->setValue(0);
    layout->addWidget(backupProgress_);
    auto* restoreActions=new QHBoxLayout();
    restorePrepareButton_=new QPushButton(QStringLiteral("Preparar restauración (sin sobrescribir)"),page);
    restoreCommitButton_=new QPushButton(QStringLiteral("Confirmar sobrescritura"),page);
    restoreDiscardButton_=new QPushButton(QStringLiteral("Descartar restauración"),page);
    restoreCommitButton_->setEnabled(false);restoreDiscardButton_->setEnabled(false);
    restoreActions->addWidget(restorePrepareButton_);
    restoreActions->addWidget(restoreCommitButton_);
    restoreActions->addWidget(restoreDiscardButton_);
    layout->addLayout(restoreActions);
    layout->addWidget(note(QStringLiteral("La sobrescritura exige preparar y comprobar todas las bóvedas, revisar los destinos y confirmar explícitamente."),page));
    auto* inspectRow=new QHBoxLayout();
    restoreInspectButton_=new QPushButton(QStringLiteral("Verificar archivo para restaurar (solo lectura)"),page);
    restoreInspectCancelButton_=new QPushButton(QStringLiteral("Cancelar verificación"),page);
    restoreInspectCancelButton_->setEnabled(false);
    inspectRow->addWidget(restoreInspectButton_);
    restoreCompatibilityButton_=new QPushButton(QStringLiteral("Comprobar Master Key del respaldo (sin restaurar)"),page);
    inspectRow->addWidget(restoreCompatibilityButton_);
    inspectRow->addWidget(restoreInspectCancelButton_);
    layout->addLayout(inspectRow);
    restoreInspectDetails_=new QPlainTextEdit(page);
    restoreInspectDetails_->setReadOnly(true);
    restoreInspectDetails_->setMaximumHeight(175);
    restoreInspectDetails_->setPlaceholderText(QStringLiteral("Selecciona un archivo .kdbx o .nbsbak para comprobar su integridad."));
    layout->addWidget(restoreInspectDetails_);
    layout->addWidget(note(QStringLiteral("La verificación comprueba formato y SHA-256; no demuestra que la Master Key abra el respaldo ni autoriza una sobrescritura."),page));
    layout->addWidget(note(QStringLiteral("Respaldo individual: archivo .kdbx original. Respaldo completo: paquete .nbsbak con inventario y SHA-256 por bóveda."),page));
    layout->addStretch();views_->addWidget(page);
    connect(backupSingleButton_,&QPushButton::clicked,this,[this](){startVaultBackup(false);});
    connect(backupFullButton_,&QPushButton::clicked,this,[this](){startVaultBackup(true);});
    connect(backupCancelButton_,&QPushButton::clicked,this,[this](){
        if(backupCancel_)backupCancel_->store(true);
        backupCancelButton_->setEnabled(false);
        statusBar()->showMessage(translateText(QStringLiteral("Cancelando respaldo…")));
    });
    connect(restorePrepareButton_,&QPushButton::clicked,this,[this](){prepareVaultRestore();});
    connect(restoreCommitButton_,&QPushButton::clicked,this,[this](){commitVaultRestore();});
    connect(restoreDiscardButton_,&QPushButton::clicked,this,[this](){discardVaultRestore();});
    connect(restoreInspectButton_,&QPushButton::clicked,this,[this](){inspectRestoreBackup();});
    connect(restoreCompatibilityButton_,&QPushButton::clicked,this,[this](){verifyRestoreMasterKey();});
    connect(restoreInspectCancelButton_,&QPushButton::clicked,this,[this](){
        if(restoreInspectCancel_)restoreInspectCancel_->store(true);
        restoreInspectCancelButton_->setEnabled(false);
        statusBar()->showMessage(translateText(QStringLiteral("Cancelando verificación…")));
    });
}

void MainWindow::inspectRestoreBackup(){
    if(restoreInspectThread_ && restoreInspectThread_->isRunning())return;
    const QString source=QFileDialog::getOpenFileName(this,
        translateText(QStringLiteral("Seleccionar respaldo cifrado")),QDir::homePath(),
        QStringLiteral("Respaldos (*.nbsbak *.kdbx)"));
    if(source.isEmpty())return;
    restoreInspectDetails_->clear();
    restoreInspectDetails_->setPlainText(
        translateText(QStringLiteral("Verificando formato e integridad sin extraer ni modificar bóvedas…")));
    auto cancelled=std::make_shared<std::atomic_bool>(false);
    restoreInspectCancel_=cancelled;
    restoreInspectButton_->setEnabled(false);
    restoreCompatibilityButton_->setEnabled(false);
    restoreInspectCancelButton_->setEnabled(true);
    backupProgress_->setValue(0);
    QThread* worker=QThread::create([this,source,cancelled](){
        const auto result=BackupIpc::inspectRestoreBackup(source,cancelled.get(),
            [this](int value){
                QMetaObject::invokeMethod(this,[this,value](){
                    if(backupProgress_)backupProgress_->setValue(value);
                },Qt::QueuedConnection);
            });
        QMetaObject::invokeMethod(this,[this,result](){
            if(!restoreInspectDetails_)return;
            if(!result.ok){
                restoreInspectDetails_->setPlainText(
                    translateText(QStringLiteral("Verificación fallida: "))+translateText(result.error));
                return;
            }
            QStringList items;
            items << translateText(QStringLiteral("Formato: "))+result.mode;
            items << translateText(QStringLiteral("Bóvedas verificadas: "))+QString::number(result.names.size());
            items << translateText(QStringLiteral("Tamaño cifrado (bytes): "))+QString::number(result.bytes);
            for(int i=0;i<result.names.size();++i){
                items << QStringLiteral("• %1 — SHA-256: %2").arg(result.names.at(i),result.hashes.at(i));
            }
            items << translateText(QStringLiteral("Integridad de archivo correcta. Master Key y restauración aún no comprobadas."));
            restoreInspectDetails_->setPlainText(items.join(QLatin1Char('\n')));
            if(backupProgress_)backupProgress_->setValue(100);
        },Qt::QueuedConnection);
    });
    restoreInspectThread_=worker;
    connect(worker,&QThread::finished,this,[this,worker](){
        if(restoreInspectButton_)restoreInspectButton_->setEnabled(true);
        if(restoreCompatibilityButton_)restoreCompatibilityButton_->setEnabled(true);
        if(restoreInspectCancelButton_)restoreInspectCancelButton_->setEnabled(false);
        restoreInspectCancel_.reset();
        if(restoreInspectThread_==worker)restoreInspectThread_.clear();
        worker->deleteLater();
    });
    worker->start();
}

void MainWindow::verifyRestoreMasterKey(){
    if(restoreInspectThread_ && restoreInspectThread_->isRunning())return;
    const QString source=QFileDialog::getOpenFileName(this,
        translateText(QStringLiteral("Seleccionar respaldo cifrado")),QDir::homePath(),
        QStringLiteral("Respaldos (*.nbsbak *.kdbx)"));
    if(source.isEmpty())return;
    QString target;
    if(source.endsWith(QStringLiteral(".kdbx"),Qt::CaseInsensitive)){
        QString error;
        QStringList choices=BackupIpc::catalog(
            [this](const QJsonObject& req,QString* e){return call(req,e);},&error);
        if(!choices.contains(QStringLiteral("vault-general.kdbx")))
            choices.prepend(QStringLiteral("vault-general.kdbx"));
        bool accepted=false;
        target=QInputDialog::getItem(this,
            translateText(QStringLiteral("Seleccionar bóveda de destino")),
            translateText(QStringLiteral("¿Qué bóveda se validará contra este respaldo? (no será sobrescrita)")),
            choices,0,false,&accepted);
        if(!accepted||target.isEmpty())return;
    }
    auto cancelled=std::make_shared<std::atomic_bool>(false);
    restoreInspectCancel_=cancelled;
    restoreInspectButton_->setEnabled(false);
    restoreCompatibilityButton_->setEnabled(false);
    restoreInspectCancelButton_->setEnabled(true);
    restoreInspectDetails_->setPlainText(translateText(QStringLiteral(
        "Copiando KDBX cifrado a staging privado y validando la Master Key. Ninguna bóveda será reemplazada.")));
    backupProgress_->setValue(0);
    QThread* worker=QThread::create([this,source,target,cancelled](){
        const auto result=BackupIpc::verifyRestoreMasterKey(
            [this](const QJsonObject& req,QString* e){return call(req,e);},
            source,target,cancelled.get(),[this](int n){
                QMetaObject::invokeMethod(this,[this,n](){
                    if(backupProgress_)backupProgress_->setValue(n);
                },Qt::QueuedConnection);
            });
        QMetaObject::invokeMethod(this,[this,result](){
            if(result.ok){
                restoreInspectDetails_->setPlainText(translateText(QStringLiteral(
                    "Master Key compatible con %1 bóveda(s). Los originales permanecen intactos; todavía no se ha restaurado.")).arg(result.count));
                backupProgress_->setValue(100);
            }else{
                restoreInspectDetails_->setPlainText(translateText(QStringLiteral("Validación de clave fallida: "))+translateText(result.error));
            }
        },Qt::QueuedConnection);
    });
    restoreInspectThread_=worker;
    connect(worker,&QThread::finished,this,[this,worker](){
        if(restoreInspectButton_)restoreInspectButton_->setEnabled(true);
        if(restoreCompatibilityButton_)restoreCompatibilityButton_->setEnabled(true);
        if(restoreInspectCancelButton_)restoreInspectCancelButton_->setEnabled(false);
        restoreInspectCancel_.reset();
        if(restoreInspectThread_==worker)restoreInspectThread_.clear();
        worker->deleteLater();
    });
    worker->start();
}

void MainWindow::discardVaultRestore(){
    if(restoreInspectThread_ && restoreInspectThread_->isRunning())return;
    QString error;
    const auto result=BackupIpc::discardPreparedRestore(
        [this](const QJsonObject& req,QString* e){return call(req,e);});
    restoreConfirmation_.clear();restorePreparedNames_.clear();
    if(restoreCommitButton_)restoreCommitButton_->setEnabled(false);
    if(restoreDiscardButton_)restoreDiscardButton_->setEnabled(false);
    if(restoreInspectButton_)restoreInspectButton_->setEnabled(true);
    if(restoreCompatibilityButton_)restoreCompatibilityButton_->setEnabled(true);
    if(restoreInspectDetails_)restoreInspectDetails_->setPlainText(translateText(
        result.ok?QStringLiteral("Restauración preparada descartada. No se reemplazó ninguna bóveda.")
                 :QStringLiteral("No se pudo descartar restauración: "))+(result.ok?QString():translateText(result.error)));
}
void MainWindow::prepareVaultRestore(){
    if(restoreInspectThread_ && restoreInspectThread_->isRunning())return;
    if(!restoreConfirmation_.isEmpty())discardVaultRestore();
    const QString source=QFileDialog::getOpenFileName(this,
        translateText(QStringLiteral("Seleccionar respaldo cifrado")),QDir::homePath(),
        QStringLiteral("Respaldos (*.nbsbak *.kdbx)"));
    if(source.isEmpty())return;
    QString target;
    if(source.endsWith(QStringLiteral(".kdbx"),Qt::CaseInsensitive)){
        QString error;
        QStringList names=BackupIpc::catalog([this](const QJsonObject& req,QString* e){return call(req,e);},&error);
        if(!names.contains(QStringLiteral("vault-general.kdbx")))names.prepend(QStringLiteral("vault-general.kdbx"));
        bool accepted=false;
        target=QInputDialog::getItem(this,translateText(QStringLiteral("Seleccionar bóveda de destino")),
            translateText(QStringLiteral("Selecciona el destino que será SOBRESCRITO al confirmar.")),names,0,false,&accepted);
        if(!accepted||target.isEmpty())return;
    }
    auto cancelled=std::make_shared<std::atomic_bool>(false);
    restoreInspectCancel_=cancelled;
    restoreInspectButton_->setEnabled(false);
    restoreCompatibilityButton_->setEnabled(false);
    restorePrepareButton_->setEnabled(false);
    restoreInspectCancelButton_->setEnabled(true);
    restoreCommitButton_->setEnabled(false);
    restoreDiscardButton_->setEnabled(false);
    restoreInspectDetails_->setPlainText(translateText(QStringLiteral(
        "Preparando archivos cifrados y verificando la Master Key. Aún no se sobrescribe nada.")));
    backupProgress_->setValue(0);
    QThread* worker=QThread::create([this,source,target,cancelled](){
        const auto result=BackupIpc::verifyRestoreMasterKey(
            [this](const QJsonObject& req,QString* e){return call(req,e);},
            source,target,cancelled.get(),[this](int n){
                QMetaObject::invokeMethod(this,[this,n](){if(backupProgress_)backupProgress_->setValue(n);},Qt::QueuedConnection);
            },true);
        QMetaObject::invokeMethod(this,[this,result](){
            if(!restoreInspectDetails_)return;
            if(result.ok && !result.confirmation.isEmpty() && !result.names.isEmpty()){
                restoreConfirmation_=result.confirmation;
                restorePreparedNames_=result.names;
                restoreCommitButton_->setEnabled(true);
                restoreDiscardButton_->setEnabled(true);
                restoreInspectDetails_->setPlainText(
                    translateText(QStringLiteral("Preparadas y validadas %1 bóveda(s). NO sobrescritas. Destinos a reemplazar:"))
                        .arg(result.count)+QStringLiteral("\n• ")+result.names.join(QStringLiteral("\n• ")));
                backupProgress_->setValue(100);
            }else{
                restoreConfirmation_.clear();restorePreparedNames_.clear();
                restoreInspectDetails_->setPlainText(translateText(QStringLiteral("Preparación fallida: "))+translateText(result.error));
            }
        },Qt::QueuedConnection);
    });
    restoreInspectThread_=worker;
    connect(worker,&QThread::finished,this,[this,worker](){
        const bool pending=!restoreConfirmation_.isEmpty();
        restoreInspectButton_->setEnabled(!pending);
        restoreCompatibilityButton_->setEnabled(!pending);
        restorePrepareButton_->setEnabled(true);
        restoreInspectCancelButton_->setEnabled(false);
        restoreInspectCancel_.reset();
        if(restoreInspectThread_==worker)restoreInspectThread_.clear();
        worker->deleteLater();
    });
    worker->start();
}
void MainWindow::commitVaultRestore(){
    if(restoreInspectThread_ && restoreInspectThread_->isRunning())return;
    if(restoreConfirmation_.size()!=32 || restorePreparedNames_.isEmpty())return;
    const QString message=translateText(QStringLiteral(
        "Esta operación SOBRESCRIBIRÁ las siguientes bóvedas cifradas. No fusionará registros. ¿Confirmas?"))
        +QStringLiteral("\n\n• ")+restorePreparedNames_.join(QStringLiteral("\n• "));
    if(QMessageBox::warning(this,translateText(QStringLiteral("Confirmar restauración con sobrescritura")),
        message,QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
    const QString confirmation=restoreConfirmation_;
    restoreCommitButton_->setEnabled(false);restoreDiscardButton_->setEnabled(false);
    restorePrepareButton_->setEnabled(false);restoreInspectButton_->setEnabled(false);
    restoreCompatibilityButton_->setEnabled(false);
    restoreInspectDetails_->setPlainText(translateText(QStringLiteral(
        "Aplicando transacción de restauración. No cierres Secrets durante esta operación.")));
    QThread* worker=QThread::create([this,confirmation](){
        const auto result=BackupIpc::commitPreparedRestore(
            [this](const QJsonObject& req,QString* e){return call(req,e);},confirmation);
        QMetaObject::invokeMethod(this,[this,result](){
            restoreConfirmation_.clear();restorePreparedNames_.clear();
            if(result.ok){
                restoreInspectDetails_->setPlainText(translateText(QStringLiteral(
                    "Restauración completada: %1 bóveda(s) sobrescritas. Secrets quedó bloqueado; desbloquea con tu Master Key."))
                    .arg(result.count));
            }else{
                restoreInspectDetails_->setPlainText(translateText(QStringLiteral(
                    "Error de restauración. Revisa el estado de Secrets antes de intentar otra operación: "))+translateText(result.error));
            }
            refreshStatus();
        },Qt::QueuedConnection);
    });
    restoreInspectThread_=worker;
    connect(worker,&QThread::finished,this,[this,worker](){
        restorePrepareButton_->setEnabled(true);restoreInspectButton_->setEnabled(true);
        restoreCompatibilityButton_->setEnabled(true);
        if(restoreInspectThread_==worker)restoreInspectThread_.clear();
        worker->deleteLater();
    });
    worker->start();
}

void MainWindow::startVaultBackup(bool complete,const QString& fixedName){
    if(backupThread_ && backupThread_->isRunning())return;
    QString catalogError;
    const QStringList choices=BackupIpc::catalog(
        [this](const QJsonObject& req,QString* error){return call(req,error);},&catalogError);
    if(choices.isEmpty()){
        QMessageBox::warning(this,translateText(QStringLiteral("Backup & Restore")),
            translateText(QStringLiteral("No se encontraron bóvedas KDBX válidas o el directorio es inaccesible.")));
        return;
    }
    QStringList names;
    if(complete) names=choices;
    else if(!fixedName.isEmpty()){
        if(!choices.contains(fixedName)){
            QMessageBox::warning(this,translateText(QStringLiteral("Backup & Restore")),
                translateText(QStringLiteral("No se encontró la bóveda seleccionada.")));
            return;
        }
        names<<fixedName;
    }else{
        bool accepted=false;
        const QString selected=QInputDialog::getItem(this,
            translateText(QStringLiteral("Seleccionar bóveda")),
            translateText(QStringLiteral("Bóveda que deseas respaldar:")),choices,0,false,&accepted);
        if(!accepted || selected.isEmpty())return;
        names<<selected;
    }
    const QString extension=complete?QStringLiteral("nbsbak"):QStringLiteral("kdbx");
    const QString suggestion=complete?QStringLiteral("neebles-secrets-completo.nbsbak")
        :names.first();
    const QString target=QFileDialog::getSaveFileName(this,
        translateText(QStringLiteral("Guardar respaldo cifrado")),
        QDir::home().filePath(suggestion),
        QStringLiteral("*.%1").arg(extension));
    if(target.isEmpty())return;
    if(!target.endsWith(QStringLiteral(".")+extension,Qt::CaseInsensitive)){
        QMessageBox::warning(this,translateText(QStringLiteral("Backup & Restore")),
            translateText(QStringLiteral("Utiliza la extensión del formato seleccionado.")));
        return;
    }
    const bool overwriting=QFileInfo::exists(target);
    if(overwriting && QMessageBox::question(this,
         translateText(QStringLiteral("Sobrescribir respaldo")),
         translateText(QStringLiteral("El destino ya existe. ¿Deseas reemplazar únicamente ese respaldo? Las bóvedas originales no se modificarán.")),
         QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
    const QString confirmation=complete?
        QStringLiteral("Se copiarán %1 bóvedas CIFRADAS a un paquete de recuperación. La Master Key no se incluirá. ¿Continuar?").arg(names.size()):
        QStringLiteral("Se copiará el KDBX original cifrado sin modificar la bóveda. ¿Continuar?");
    if(QMessageBox::question(this,translateText(QStringLiteral("Confirmar respaldo")),
        translateText(confirmation),QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
    auto cancelled=std::make_shared<std::atomic_bool>(false);
    backupCancel_=cancelled;
    backupProgress_->setValue(0);
    backupSingleButton_->setEnabled(false);backupFullButton_->setEnabled(false);
    backupCancelButton_->setEnabled(true);
    QThread* worker=QThread::create([this,names,target,complete,cancelled](){
        const auto result=BackupIpc::exportEncrypted(
            [this](const QJsonObject& req,QString* error){return call(req,error);},
            complete,complete?QString():names.first(),target,cancelled.get(),
            [this](int current){
                QMetaObject::invokeMethod(this,[this,current](){
                    if(backupProgress_)backupProgress_->setValue(current);
                },Qt::QueuedConnection);
            });
        QMetaObject::invokeMethod(this,[this,result](){
            if(result.ok){
                statusBar()->showMessage(translateText(QStringLiteral("Respaldo cifrado creado y verificado.")),7000);
                if(backupProgress_)backupProgress_->setValue(100);
            }else{
                QMessageBox::warning(this,translateText(QStringLiteral("Backup & Restore")),
                    translateText(QStringLiteral("El respaldo no se completó: "))+translateText(result.error));
            }
        },Qt::QueuedConnection);
    });
    backupThread_=worker;
    connect(worker,&QThread::finished,this,[this,worker](){
        backupSingleButton_->setEnabled(true);backupFullButton_->setEnabled(true);
        backupCancelButton_->setEnabled(false);backupCancel_.reset();
        if(backupThread_==worker)backupThread_.clear();
        worker->deleteLater();
    });
    worker->start();
}
void MainWindow::startBatchExport(){
    if(batchExportThread_ && batchExportThread_->isRunning())return;
    if(batchExportCancelFlag_)batchExportCancelFlag_.reset();
    const QString format=batchExportFormat_->currentData().toString();
    const QString kind=batchExportKind_->currentData().toString();
    const int length=batchExportLength_->value();
    const int total=batchExportCount_->value();
    if(format==QStringLiteral("kdbx")){startPortableKdbxExport();return;}
    if(total<1 || total>100000 || (format!=QStringLiteral("txt") &&
        format!=QStringLiteral("csv") && format!=QStringLiteral("json")))return;
    const QString warning=QStringLiteral(
        "Se generarán %1 secretos NUEVOS y se guardarán SIN CIFRAR. "
        "Un archivo TXT/CSV/JSON no protege las contraseñas, claves ni peppers. "
        "¿Autorizas expresamente esta exportación?").arg(total);
    if(QMessageBox::warning(this,QStringLiteral("Exportación sin cifrar"),warning,
        QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
    const QString target=QFileDialog::getSaveFileName(this,QStringLiteral("Destino del lote"),
        QDir::homePath()+QStringLiteral("/neebles-secrets-batch.")+format,
        QStringLiteral("Archivos (*.%1)").arg(format));
    if(target.isEmpty())return;
    // File replacement is explicit. QSaveFile writes to a sibling temporary file.
    if(QFileInfo(target).isSymLink()){
        QMessageBox::warning(this,QStringLiteral("Exportar"),
            QStringLiteral("No se permite exportar sobre un enlace simbólico."));
        return;
    }
    if(QFileInfo::exists(target) && QMessageBox::question(this,QStringLiteral("Sobrescribir archivo"),
        QStringLiteral("El archivo ya existe. ¿Sobrescribirlo de forma atómica?"),
        QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
    auto cancel=std::make_shared<std::atomic_bool>(false);
    batchExportCancelFlag_=cancel;
    batchExportStart_->setEnabled(false);
    batchExportCancelButton_->setEnabled(true);
    batchExportProgress_->setValue(0);
    // Keep UI responsive while the separate worker does bounded IPC, without
    // caching the entire plaintext batch or writing any content to Qt Settings.
    QThread* worker=QThread::create([this,cancel,target,format,kind,length,total](){
        QString message;
        bool success=false;
        int generated=0;
        QSaveFile file(target);
        file.setDirectWriteFallback(false);
        const auto abort=[&file](){file.cancelWriting();};
        if(!file.open(QIODevice::WriteOnly)){
            message=QStringLiteral("No se pudo crear el temporal de exportación: %1").arg(file.errorString());
        }else if(!file.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner)){
            abort();message=QStringLiteral("No se pudieron establecer permisos privados 0600.");
        }else{
            const auto write=[&file](const QByteArray& bytes)->bool{
                return file.write(bytes)==bytes.size();
            };
            bool valid=true;
            if(format==QStringLiteral("csv"))valid=write("index,kind,value\n");
            if(format==QStringLiteral("json"))valid=write("{\"schema\":\"neebles-secrets-batch-v1\",\"records\":[\n");
            while(valid && !cancel->load() && generated<total){
                const int count=qMin(total-generated,8);
                const QJsonObject req{{QStringLiteral("op"),QStringLiteral("batch.generate")},
                    {QStringLiteral("kind"),kind},{QStringLiteral("length"),length},
                    {QStringLiteral("count"),count}};
                QString error;
                const auto response=call(req,&error);
                if(!response.value(QStringLiteral("ok")).toBool()){
                    message=error.isEmpty()?errorText(response):error;valid=false;break;
                }
                const auto items=response.value(QStringLiteral("data")).toObject()
                    .value(QStringLiteral("values")).toArray();
                if(items.size()!=count){message=QStringLiteral("Respuesta de lote incompleta");valid=false;break;}
                for(const auto& item:items){
                    if(cancel->load())break;
                    if(!item.isString()){
                        message=QStringLiteral("Formato IPC inválido");valid=false;break;
                    }
                    const QString value=item.toString();
                    const int index=generated+1;
                    QByteArray bytes;
                    if(format==QStringLiteral("txt")){
                        if(value.contains(QLatin1Char('\n')) || value.contains(QLatin1Char('\r'))){
                            message=QStringLiteral("Valor multilinea no exportable a TXT");valid=false;break;
                        }
                        bytes=value.toUtf8()+"\n";
                    }else if(format==QStringLiteral("csv")){
                        // RFC4180 quoting; defend spreadsheet formula injection.
                        QString safe=value;
                        if(!safe.isEmpty() && QStringLiteral("=+-@\t\r\n").contains(safe[0]))
                            safe.prepend(QLatin1Char('\''));
                        safe.replace(QLatin1Char('"'),QStringLiteral("\"\""));
                        const QString line=QStringLiteral("%1,%2,\"%3\"\n").arg(index).arg(kind,safe);
                        bytes=line.toUtf8();
                    }else{
                        const auto json=QJsonDocument(QJsonObject{{QStringLiteral("index"),index},
                            {QStringLiteral("kind"),kind},{QStringLiteral("value"),value}})
                            .toJson(QJsonDocument::Compact);
                        bytes=QByteArray(generated ? ",\n" : "")+json;
                    }
                    if(!write(bytes)){
                        message=QStringLiteral("Falló la escritura del archivo temporal");valid=false;break;
                    }
                    ++generated;
                }
                const int percent=generated*100/total;
                if(generated==total || generated%(qMax(1,total/100))<8){
                    QMetaObject::invokeMethod(this,[this,percent](){
                        if(batchExportProgress_)batchExportProgress_->setValue(percent);
                    },Qt::QueuedConnection);
                }
            }
            if(valid && !cancel->load() && generated==total){
                if(format==QStringLiteral("json"))valid=write("\n]}\n");
                if(valid && file.commit()){
                    success=true;
                    message=QStringLiteral("%1 resultados exportados. Archivo SIN CIFRAR.").arg(total);
                }else if(valid){message=QStringLiteral("No se pudo confirmar el archivo de exportación");}
            }
            if(!success)abort();
        }
        if(cancel->load() && !success)message=QStringLiteral("Exportación cancelada; se descartó el temporal.");
        const bool ok=success;
        QMetaObject::invokeMethod(this,[this,ok,message](){
            if(ok)statusBar()->showMessage(message,7000);
            else QMessageBox::warning(this,QStringLiteral("Batch Exporter"),message);
        },Qt::QueuedConnection);
    });
    worker->setParent(this);
    batchExportThread_=worker;
    connect(worker,&QThread::finished,this,[this,worker](){
        batchExportStart_->setEnabled(true);
        batchExportCancelButton_->setEnabled(false);
        if(batchExportThread_==worker)batchExportThread_.clear();
        batchExportCancelFlag_.reset();
        worker->deleteLater();
    });
    worker->start();
}

void MainWindow::startPortableKdbxExport(){
    if(batchExportThread_ && batchExportThread_->isRunning())return;
    const int total=batchExportCount_->value();
    if(total<1||total>250){
        QMessageBox::warning(this,QStringLiteral("KDBX"),
            translateText(QStringLiteral("La exportación KDBX admite hasta 250 resultados por operación en esta fase.")));
        return;
    }
    bool accepted=false;
    QString key=QInputDialog::getText(this,translateText(QStringLiteral("Contraseña KDBX independiente")),
        translateText(QStringLiteral("Crea la contraseña de la nueva bóveda KDBX (mínimo 12 bytes).")),
        QLineEdit::Password,QString(),&accepted);
    if(!accepted)return;
    QString verify=QInputDialog::getText(this,translateText(QStringLiteral("Confirmar contraseña KDBX")),
        translateText(QStringLiteral("Repite la contraseña independiente de exportación.")),
        QLineEdit::Password,QString(),&accepted);
    if(!accepted)return;
    if(key!=verify||key.toUtf8().size()<12||key.toUtf8().size()>512 ||
       key.contains(QLatin1Char('\n'))||key.contains(QLatin1Char('\r'))){
        QMessageBox::warning(this,QStringLiteral("KDBX"),
            translateText(QStringLiteral("Las contraseñas no coinciden o incumplen la política.")));return;
    }
    verify.clear();
    const QString destination=QFileDialog::getSaveFileName(this,translateText(QStringLiteral("Exportar KDBX cifrada")),
        QDir::homePath()+QStringLiteral("/neebles-secrets-export.kdbx"),
        QStringLiteral("KeePassXC (*.kdbx)"));
    if(destination.isEmpty())return;
    if(QFileInfo(destination).isSymLink()){
        QMessageBox::warning(this,QStringLiteral("KDBX"),translateText(QStringLiteral("No se admiten enlaces simbólicos.")));return;
    }
    if(QFileInfo::exists(destination)&&QMessageBox::question(this,translateText(QStringLiteral("Sobrescribir KDBX")),
        translateText(QStringLiteral("Se reemplazará el archivo de exportación seleccionado, nunca vault-general.")),
        QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
    auto cancel=std::make_shared<std::atomic_bool>(false);
    batchExportCancelFlag_=cancel;
    batchExportStart_->setEnabled(false);
    batchExportCancelButton_->setEnabled(true);
    batchExportProgress_->setValue(0);
    const QString kind=batchExportKind_->currentData().toString();
    const int length=batchExportLength_->value();
    QThread* worker=QThread::create([this,cancel,destination,kind,length,total,key](){
        const auto result=PortableExportIpc::run(
            [this](const QJsonObject& request,QString* error){return call(request,error);},
            kind,length,total,key,destination,cancel.get(),
            [this](int n){QMetaObject::invokeMethod(this,[this,n](){
                if(batchExportProgress_)batchExportProgress_->setValue(n);
            },Qt::QueuedConnection);});
        const QString message=result.ok
            ?QStringLiteral("KDBX cifrada exportada: %1 entradas.").arg(result.entries)
            :result.error;
        QMetaObject::invokeMethod(this,[this,message,success=result.ok](){
            if(success)statusBar()->showMessage(translateText(message),7000);
            else QMessageBox::warning(this,translateText(QStringLiteral("Batch Exporter KDBX")),translateText(message));
        },Qt::QueuedConnection);
    });
    worker->setParent(this);
    batchExportThread_=worker;
    connect(worker,&QThread::finished,this,[this,worker](){
        batchExportStart_->setEnabled(true);
        batchExportCancelButton_->setEnabled(false);
        if(batchExportThread_==worker)batchExportThread_.clear();
        batchExportCancelFlag_.reset();
        worker->deleteLater();
    });
    worker->start();
}

void MainWindow::stopBatch(bool clearOutput){
    batchRunning_=false;batchRemaining_=0;
    if(batchStart_)batchStart_->setEnabled(true);
    if(batchCancel_)batchCancel_->setEnabled(false);
    if(clearOutput && batchPreview_)batchPreview_->clear();
    if(clearOutput && batchProgress_)batchProgress_->setValue(0);
}
void MainWindow::runBatchChunk(){
    if(!batchRunning_ || batchRemaining_<=0)return;
    const int count=qMin(batchRemaining_,8);
    const QJsonObject args{{QStringLiteral("op"),QStringLiteral("batch.generate")},
        {QStringLiteral("kind"),batchKind_->currentData().toString()},
        {QStringLiteral("length"),batchLength_->value()},
        {QStringLiteral("count"),count}};
    QString error;
    const auto response=call(args,&error);
    if(!response.value(QStringLiteral("ok")).toBool()){
        stopBatch(false);
        QMessageBox::warning(this,QStringLiteral("Batch Generator"),
            error.isEmpty()?errorText(response):error);
        return;
    }
    const auto values=response.value(QStringLiteral("data")).toObject()
        .value(QStringLiteral("values")).toArray();
    if(values.size()!=count){
        stopBatch(false);
        QMessageBox::warning(this,QStringLiteral("Batch Generator"),
            QStringLiteral("Respuesta de lote incompleta"));
        return;
    }
    for(const auto& value:values)batchPreview_->appendPlainText(value.toString());
    batchRemaining_-=count;
    batchProgress_->setValue(batchTotal_-batchRemaining_);
    if(batchRemaining_==0){
        stopBatch(false);
        statusBar()->showMessage(QStringLiteral("Lote generado en memoria; no guardado"),4000);
    }else{
        // Process UI events between bounded IPC calls, permitting explicit cancel.
        QTimer::singleShot(0,this,[this](){runBatchChunk();});
    }
}

void MainWindow::buildVaults(){
    auto* page=new QWidget(views_);
    auto* layout=new QVBoxLayout(page);
    layout->setContentsMargins(20,16,20,18);
    layout->setSpacing(12);
    layout->addWidget(heading(QStringLiteral("My Secrets"),page));
    vaultMessage_=note(QStringLiteral("Tus secretos personales están cifrados en vault-general.kdbx. Se requiere desbloqueo para acceder a ellos."),page);
    layout->addWidget(vaultMessage_);
    auto* toolbar=new QHBoxLayout();
    auto* fresh=new QPushButton(QStringLiteral("+ Nuevo secreto"),page);
    auto* reload=new QPushButton(QStringLiteral("Actualizar lista"),page);
    auto* exportNotice=new QPushButton(QStringLiteral("Exportar a KDBX"),page);
    exportNotice->setText(QStringLiteral("Respaldar vault-general.kdbx"));
    exportNotice->setToolTip(QStringLiteral("Copia el KDBX personal original cifrado; no exporta un secreto individual."));
    connect(exportNotice,&QPushButton::clicked,this,[this](){
        startVaultBackup(false,QStringLiteral("vault-general.kdbx"));
    });
    toolbar->addWidget(fresh);toolbar->addWidget(reload);toolbar->addWidget(exportNotice);
    toolbar->addStretch();
    layout->addLayout(toolbar);
    auto* body=new QHBoxLayout();body->setSpacing(12);
    auto* listCard=new QFrame(page);listCard->setObjectName(QStringLiteral("panelCard"));
    auto* left=new QVBoxLayout(listCard);
    personalFilter_=new QLineEdit(listCard);
    personalFilter_->setPlaceholderText(QStringLiteral("Buscar secretos por nombre o identificador"));
    personalList_=new QListWidget(listCard);
    left->addWidget(personalFilter_);left->addWidget(personalList_,1);
    body->addWidget(listCard,4);
    auto* editorCard=new QFrame(page);editorCard->setObjectName(QStringLiteral("panelCard"));
    auto* right=new QVBoxLayout(editorCard);
    right->setContentsMargins(14,14,14,14);
    auto* form=new QFormLayout();
    personalName_=new QLineEdit(editorCard);personalName_->setMaxLength(200);
    personalType_=new QComboBox(editorCard);
    personalType_->addItem(QStringLiteral("Contraseña"),QStringLiteral("password"));
    personalType_->addItem(QStringLiteral("Token"),QStringLiteral("token"));
    personalType_->addItem(QStringLiteral("Clave"),QStringLiteral("key"));
    personalType_->addItem(QStringLiteral("Hash / derivación"),QStringLiteral("hash"));
    personalType_->addItem(QStringLiteral("Nota secreta"),QStringLiteral("note"));
    personalType_->addItem(QStringLiteral("Pepper"),QStringLiteral("pepper"));
    personalTags_=new QLineEdit(editorCard);personalTags_->setMaxLength(500);
    personalTags_->setPlaceholderText(QStringLiteral("Etiquetas separadas por comas"));
    personalContent_=new QLineEdit(editorCard);
    personalContent_->setEchoMode(QLineEdit::Password);
    personalContent_->setPlaceholderText(QStringLiteral("Contenido protegido (máx. 4096 caracteres)"));
    personalReveal_=new QCheckBox(QStringLiteral("Revelar"),editorCard);
    form->addRow(QStringLiteral("Nombre"),personalName_);
    form->addRow(QStringLiteral("Categoría"),personalType_);
    form->addRow(QStringLiteral("Etiquetas"),personalTags_);
    form->addRow(QStringLiteral("Secreto / contenido"),personalContent_);
    right->addLayout(form);right->addWidget(personalReveal_);
    auto* actions=new QHBoxLayout();
    personalEdit_=new QPushButton(QStringLiteral("Editar"),editorCard);
    personalSave_=new QPushButton(QStringLiteral("Guardar cambios"),editorCard);
    auto* copy=new QPushButton(QStringLiteral("Copiar"),editorCard);
    auto* erase=new QPushButton(QStringLiteral("Eliminar"),editorCard);
    for(auto* b:{personalEdit_,personalSave_,copy,erase})actions->addWidget(b);
    right->addLayout(actions);
    right->addWidget(note(QStringLiteral("Copiar envía el secreto al portapapeles local. Revelar es temporal y los cambios se guardan solo al confirmar."),editorCard));
    right->addStretch();
    body->addWidget(editorCard,6);
    layout->addLayout(body,1);
    connect(reload,&QPushButton::clicked,this,[this](){refreshPersonalList();});
    connect(personalFilter_,&QLineEdit::textChanged,this,[this](const QString& term){
        for(int i=0;i<personalList_->count();++i){
            auto* item=personalList_->item(i);
            item->setHidden(!item->text().contains(term,Qt::CaseInsensitive) &&
                !item->data(Qt::UserRole).toString().contains(term,Qt::CaseInsensitive));
        }
    });
    connect(personalList_,&QListWidget::currentItemChanged,this,
        [this](QListWidgetItem* item,QListWidgetItem*){openPersonalItem(item);});
    connect(fresh,&QPushButton::clicked,this,[this](){
        personalList_->clearSelection();personalList_->setCurrentItem(nullptr);
        clearPersonalEditor();setPersonalEditing(true);personalName_->setFocus();
    });
    connect(personalReveal_,&QCheckBox::toggled,this,[this](bool checked){
        personalContent_->setEchoMode(checked?QLineEdit::Normal:QLineEdit::Password);
    });
    connect(personalEdit_,&QPushButton::clicked,this,[this](){
        if(personalId_.isEmpty())return;
        setPersonalEditing(true);personalName_->setFocus();
    });
    connect(personalSave_,&QPushButton::clicked,this,[this](){savePersonalItem();});
    connect(erase,&QPushButton::clicked,this,[this](){deletePersonalItem();});
    connect(copy,&QPushButton::clicked,this,[this](){
        if(personalContent_->text().isEmpty())return;
        QApplication::clipboard()->setText(personalContent_->text());
        statusBar()->showMessage(translateText(QStringLiteral("Copiado al portapapeles")),3000);
    });
    setPersonalEditing(false);
    views_->addWidget(page);
}
void MainWindow::setPersonalEditing(bool enabled){
    if(personalName_)personalName_->setReadOnly(!enabled);
    if(personalTags_)personalTags_->setReadOnly(!enabled);
    if(personalContent_)personalContent_->setReadOnly(!enabled);
    if(personalType_)personalType_->setEnabled(enabled);
    if(personalSave_)personalSave_->setEnabled(enabled);
    if(personalEdit_)personalEdit_->setEnabled(!enabled&&!personalId_.isEmpty());
}
void MainWindow::clearPersonalEditor(){
    personalId_.clear();
    if(personalName_)personalName_->clear();
    if(personalTags_)personalTags_->clear();
    if(personalContent_){personalContent_->clear();personalContent_->setEchoMode(QLineEdit::Password);}
    if(personalType_)personalType_->setCurrentIndex(0);
    if(personalReveal_)personalReveal_->setChecked(false);
    setPersonalEditing(false);
}
void MainWindow::refreshPersonalList(){
    if(!personalList_)return;
    clearPersonalEditor();personalList_->clear();
    QString error;
    const auto status=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("vault.status")}},&error);
    if(!status.value(QStringLiteral("ok")).toBool() ||
       status.value(QStringLiteral("data")).toObject().value(QStringLiteral("locked")).toBool())return;
    const auto result=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("general.list")}},&error);
    if(!result.value(QStringLiteral("ok")).toBool()){
        QMessageBox::warning(this,QStringLiteral("My Secrets"),error.isEmpty()?errorText(result):error);
        return;
    }
    const auto ids=result.value(QStringLiteral("data")).toObject().value(QStringLiteral("ids")).toArray();
    for(const auto& id:ids){
        auto* item=new QListWidgetItem(id.toString(),personalList_);
        item->setData(Qt::UserRole,id.toString());
    }
}
void MainWindow::openPersonalItem(QListWidgetItem* item){
    clearPersonalEditor();
    if(!item)return;
    const QString id=item->data(Qt::UserRole).toString();
    QString error;
    const auto result=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("general.get")},
                                   {QStringLiteral("id"),id}},&error);
    if(!result.value(QStringLiteral("ok")).toBool()){
        QMessageBox::warning(this,QStringLiteral("My Secrets"),error.isEmpty()?errorText(result):error);
        return;
    }
    const auto value=result.value(QStringLiteral("data")).toObject().value(QStringLiteral("value")).toObject();
    personalId_=id;
    personalName_->setText(value.value(QStringLiteral("name")).toString());
    personalTags_->setText(value.value(QStringLiteral("tags")).toString());
    personalContent_->setText(value.value(QStringLiteral("content")).toString());
    const int index=personalType_->findData(value.value(QStringLiteral("type")).toString());
    personalType_->setCurrentIndex(index>=0?index:0);
    if(!personalName_->text().isEmpty())item->setText(personalName_->text());
    setPersonalEditing(false);
}
void MainWindow::savePersonalItem(){
    const QString name=personalName_->text().trimmed();
    if(name.isEmpty() || personalContent_->text().isEmpty() || personalContent_->text().size()>4096){
        QMessageBox::warning(this,QStringLiteral("My Secrets"),QStringLiteral("Introduce nombre y valor (máximo 4096 caracteres)."));
        return;
    }
    const bool update=!personalId_.isEmpty();
    const QString id=update?personalId_:
        QStringLiteral("secret-")+QUuid::createUuid().toString(QUuid::WithoutBraces);
    const QJsonObject value{{QStringLiteral("name"),name},
        {QStringLiteral("type"),personalType_->currentData().toString()},
        {QStringLiteral("tags"),personalTags_->text()},
        {QStringLiteral("content"),personalContent_->text()}};
    if(QJsonDocument(value).toJson(QJsonDocument::Compact).size()>8192){
        QMessageBox::warning(this,QStringLiteral("My Secrets"),QStringLiteral("El registro supera el límite cifrado de 8 KiB."));
        return;
    }
    QString error;
    const auto result=call(QJsonObject{{QStringLiteral("op"),update?QStringLiteral("general.update"):QStringLiteral("general.put")},
                       {QStringLiteral("id"),id},{QStringLiteral("value"),value}},&error);
    if(!result.value(QStringLiteral("ok")).toBool()){
        QMessageBox::warning(this,QStringLiteral("My Secrets"),error.isEmpty()?errorText(result):error);
        return;
    }
    refreshPersonalList();
    for(int i=0;i<personalList_->count();++i){
        auto* item=personalList_->item(i);
        if(item->data(Qt::UserRole).toString()==id){personalList_->setCurrentItem(item);break;}
    }
    statusBar()->showMessage(QStringLiteral("Registro cifrado guardado en vault-general"),4000);
}
void MainWindow::deletePersonalItem(){
    if(personalId_.isEmpty())return;
    if(QMessageBox::question(this,QStringLiteral("Eliminar secreto"),
        QStringLiteral("¿Eliminar definitivamente este registro de vault-general?"))!=QMessageBox::Yes)return;
    QString error;
    const auto result=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("general.delete")},
                                   {QStringLiteral("id"),personalId_}},&error);
    if(!result.value(QStringLiteral("ok")).toBool()){
        QMessageBox::warning(this,QStringLiteral("My Secrets"),error.isEmpty()?errorText(result):error);
        return;
    }
    refreshPersonalList();
}
QJsonObject MainWindow::call(const QJsonObject& request,QString* error){
    const QString root=qEnvironmentVariable("XDG_RUNTIME_DIR");
    if(root.isEmpty()||!QDir::isAbsolutePath(root)){
        if(error)*error=QStringLiteral("XDG_RUNTIME_DIR no está definido.");
        return {};
    }
    QLocalSocket sock;
    sock.connectToServer(QDir(root).filePath(QStringLiteral("neebles-secrets/secrets.sock")));
    if(!sock.waitForConnected(1200)){
        if(error)*error=QStringLiteral("Backend Rust no disponible: %1").arg(sock.errorString());
        return {};
    }
    const QByteArray payload=QJsonDocument(request).toJson(QJsonDocument::Compact);
    if(payload.isEmpty()||payload.size()>16384){if(error)*error=QStringLiteral("Solicitud IPC demasiado grande");return {};}
    QByteArray frame(4,0);
    qToBigEndian<quint32>(static_cast<quint32>(payload.size()),reinterpret_cast<uchar*>(frame.data()));
    frame.append(payload);
    if(sock.write(frame)!=frame.size()||!sock.waitForBytesWritten(3000)){
        if(error) *error=QStringLiteral("Falló el envío IPC");
        return {};
    }
    auto take=[&sock](int n)->QByteArray{
        QByteArray out;
        while(out.size()<n){
            if(sock.bytesAvailable()<=0&&!sock.waitForReadyRead(45000))return {};
            out.append(sock.read(n-out.size()));
        }
        return out;
    };
    const QByteArray size=take(4);
    if(size.size()!=4){if(error)*error=QStringLiteral("Respuesta IPC incompleta");return {};}
    const quint32 length=qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(size.constData()));
    if(length==0||length>16384){if(error)*error=QStringLiteral("Respuesta IPC fuera de rango");return {};}
    const QByteArray response=take(static_cast<int>(length));
    if(response.size()!=static_cast<int>(length)){if(error)*error=QStringLiteral("Respuesta IPC truncada");return {};}
    QJsonParseError parse;
    const QJsonDocument json=QJsonDocument::fromJson(response,&parse);
    if(parse.error!=QJsonParseError::NoError||!json.isObject()){
        if(error) *error=QStringLiteral("Respuesta IPC inválida");
        return {};
    }
    return json.object();
}
void MainWindow::generate(){
    generated_->clear();
    QJsonObject request{{QStringLiteral("op"),QStringLiteral("quick.generate")},
        {QStringLiteral("kind"),kind_->currentData().toString()},
        {QStringLiteral("length"),length_->value()},
        {QStringLiteral("uppercase"),uppercase_->isChecked()},
        {QStringLiteral("lowercase"),lowercase_->isChecked()},
        {QStringLiteral("numbers"),numbers_->isChecked()},
        {QStringLiteral("symbols"),symbols_->isChecked()},
        {QStringLiteral("exclude_ambiguous"),ambiguous_->isChecked()}};
    QString error;const auto response=call(request,&error);
    if(response.isEmpty()) { QMessageBox::warning(this,QStringLiteral("Quick Secrets"),error);return; }
    if(!response.value(QStringLiteral("ok")).toBool()){
        QMessageBox::warning(this,QStringLiteral("Quick Secrets"),errorText(response));return;
    }
    const QString value=response.value(QStringLiteral("data")).toObject().value(QStringLiteral("value")).toString();
    if(value.isEmpty()){QMessageBox::warning(this,QStringLiteral("Quick Secrets"),QStringLiteral("Rust devolvió un resultado vacío"));return;}
    generated_->setText(value);
    statusBar()->showMessage(QStringLiteral("Valor generado localmente (no guardado)"),4000);
}
void MainWindow::toggleUnlock(){
    QString error;
    const auto status=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("vault.status")}},&error);
    if(!status.value(QStringLiteral("ok")).toBool()){
        QMessageBox::warning(this,QStringLiteral("Secrets"),error.isEmpty()?errorText(status):error);return;
    }
    const auto data=status.value(QStringLiteral("data")).toObject();
    if(!data.value(QStringLiteral("locked")).toBool()){
        const auto locked=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("vault.lock")}},&error);
        if(!locked.value(QStringLiteral("ok")).toBool())
            QMessageBox::warning(this,QStringLiteral("Secrets"),error.isEmpty()?errorText(locked):error);
        refreshStatus();return;
    }
    const bool setup=!data.value(QStringLiteral("initialized")).toBool();
    QString password;
    if(!askMasterKey(this,setup,&password,[this](const QString& text){return translateText(text); })){
        password.fill(QChar('\0'));
        return; // Cancel: no vault created. Next Open prompts again.
    }
    QJsonObject request{{QStringLiteral("op"),setup?QStringLiteral("vault.setup"):QStringLiteral("vault.unlock")},
                        {QStringLiteral("password"),password}};
    password.fill(QChar('\0'));
    const auto result=call(request,&error);
    request.insert(QStringLiteral("password"),QString());
    if(!result.value(QStringLiteral("ok")).toBool())
        QMessageBox::warning(this,QStringLiteral("Secrets"),error.isEmpty()?errorText(result):error);
    refreshStatus();
    if(result.value(QStringLiteral("ok")).toBool())refreshPersonalList();
}
// The synchronous path is used for deliberate user actions/navigation only.
// Cancel any earlier asynchronous response before applying the fresh result.
void MainWindow::refreshStatus(){
    cancelStatusProbe();
    QString error;
    const auto result=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("vault.status")}},&error);
    applyStatusResult(result,error);
}

void MainWindow::cancelStatusProbe(){
    if(!statusProbeSocket_)return;
    QLocalSocket* socket=statusProbeSocket_.data();
    statusProbeSocket_=nullptr;
    statusProbeBuffer_.clear();
    QObject::disconnect(socket,nullptr,this,nullptr);
    socket->abort();
    socket->deleteLater();
}

void MainWindow::finishStatusProbe(QLocalSocket* socket,const QJsonObject& response,const QString& error){
    if(statusProbeSocket_.data()!=socket)return; // late/stale reply
    cancelStatusProbe();
    applyStatusResult(response,error);
}

void MainWindow::startStatusProbe(){
    if(statusProbeSocket_)return; // only one in-flight request
    const QString runtime=qEnvironmentVariable("XDG_RUNTIME_DIR");
    if(runtime.isEmpty()||!QDir::isAbsolutePath(runtime)){
        applyStatusResult({},QStringLiteral("XDG_RUNTIME_DIR no está definido."));
        return;
    }
    const QByteArray payload=QJsonDocument(QJsonObject{
        {QStringLiteral("op"),QStringLiteral("vault.status")}
    }).toJson(QJsonDocument::Compact);
    QByteArray frame(4,'\0');
    qToBigEndian<quint32>(static_cast<quint32>(payload.size()),
                          reinterpret_cast<uchar*>(frame.data()));
    frame.append(payload);
    auto* socket=new QLocalSocket(this);
    statusProbeSocket_=socket;
    statusProbeBuffer_.clear();
    connect(socket,&QLocalSocket::connected,this,[this,socket,frame](){
        if(statusProbeSocket_.data()!=socket)return;
        if(socket->write(frame)!=frame.size()){
            finishStatusProbe(socket,{},QStringLiteral("No se pudo enviar vault.status"));
        }else socket->flush();
    });
    connect(socket,&QLocalSocket::readyRead,this,[this,socket](){
        if(statusProbeSocket_.data()!=socket)return;
        statusProbeBuffer_.append(socket->readAll());
        if(statusProbeBuffer_.size()>16388){
            finishStatusProbe(socket,{},QStringLiteral("Respuesta IPC excede límite"));
            return;
        }
        if(statusProbeBuffer_.size()<4)return;
        const auto* bytes=reinterpret_cast<const uchar*>(statusProbeBuffer_.constData());
        const quint32 length=qFromBigEndian<quint32>(bytes);
        if(length==0||length>16384){
            finishStatusProbe(socket,{},QStringLiteral("Longitud IPC inválida"));
            return;
        }
        if(statusProbeBuffer_.size()<4+static_cast<int>(length))return;
        if(statusProbeBuffer_.size()!=4+static_cast<int>(length)){
            finishStatusProbe(socket,{},QStringLiteral("Respuesta IPC con datos extra"));
            return;
        }
        QJsonParseError parse;
        const auto doc=QJsonDocument::fromJson(statusProbeBuffer_.mid(4),&parse);
        if(parse.error!=QJsonParseError::NoError||!doc.isObject()){
            finishStatusProbe(socket,{},QStringLiteral("JSON IPC inválido"));
            return;
        }
        const auto result=doc.object();
        const auto data=result.value(QStringLiteral("data")).toObject();
        if(!result.value(QStringLiteral("ok")).isBool() ||
           (result.value(QStringLiteral("ok")).toBool() &&
            (!data.value(QStringLiteral("initialized")).isBool() ||
             !data.value(QStringLiteral("locked")).isBool()))){
            finishStatusProbe(socket,{},QStringLiteral("Estado IPC incompleto"));
            return;
        }
        finishStatusProbe(socket,result,QString());
    });
    connect(socket,&QLocalSocket::errorOccurred,this,[this,socket](QLocalSocket::LocalSocketError){
        if(statusProbeSocket_.data()==socket)
            finishStatusProbe(socket,{},QStringLiteral("Backend Rust no disponible"));
    });
    connect(socket,&QLocalSocket::disconnected,this,[this,socket](){
        if(statusProbeSocket_.data()==socket)
            finishStatusProbe(socket,{},QStringLiteral("Backend desconectado antes de responder"));
    });
    QTimer::singleShot(3000,socket,[this,socket](){
        if(statusProbeSocket_.data()==socket)
            finishStatusProbe(socket,{},QStringLiteral("Tiempo de espera agotado en vault.status"));
    });
    socket->connectToServer(QDir(runtime).filePath(QStringLiteral("neebles-secrets/secrets.sock")));
}

// Both synchronous and asynchronous results share exactly one UI state handler.
void MainWindow::applyStatusResult(const QJsonObject& result,const QString& error){
    const QJsonObject data=result.value(QStringLiteral("data")).toObject();
    const bool valid=result.value(QStringLiteral("ok")).toBool() &&
        data.value(QStringLiteral("initialized")).isBool() &&
        data.value(QStringLiteral("locked")).isBool();
    if(!valid){
        status_->setText(translateText(QStringLiteral("● Sin conexión")));unlock_->setEnabled(false);unlock_->setVisible(false);
        if(dashboardService_)dashboardService_->setText(translateText(QStringLiteral("Sin conexión")));
        if(dashboardVault_)dashboardVault_->setText(translateText(QStringLiteral("No disponible")));
        if(dashboardModules_)dashboardModules_->setText(translateText(QStringLiteral("No disponible")));
        if(save_)save_->setEnabled(false);
        if(vaultMessage_)vaultMessage_->setText(QStringLiteral("Backend desconectado. Los Vaults no están disponibles."));
        setPersonalAvailable(false);
        statusBar()->showMessage(error.isEmpty()?QStringLiteral("Backend desconectado"):error);
        return;
    }
    const bool initialized=data.value(QStringLiteral("initialized")).toBool();
    const bool locked=data.value(QStringLiteral("locked")).toBool();
    status_->setText(translateText(locked?QStringLiteral("● Bloqueado"):QStringLiteral("● Desbloqueado")));
    if(dashboardService_)dashboardService_->setText(translateText(QStringLiteral("● Activo")));
    if(dashboardVault_)dashboardVault_->setText(translateText(!initialized?QStringLiteral("Configuración pendiente"):
        (locked?QStringLiteral("Bloqueado"):QStringLiteral("Desbloqueado"))));
    if(dashboardModules_)dashboardModules_->setText(translateText(QStringLiteral("Administradas bajo demanda")));
    unlock_->setEnabled(initialized);
    unlock_->setVisible(initialized);
    if(save_)save_->setEnabled(initialized&&!locked);
    unlock_->setText(translateText(locked?QStringLiteral("🔒  Desbloquear"):QStringLiteral("🔓  Bloquear")));
    setPersonalAvailable(initialized&&!locked);
    if(!initialized||locked){
        restoreConfirmation_.clear();restorePreparedNames_.clear();
        if(restoreCommitButton_)restoreCommitButton_->setEnabled(false);
        if(restoreDiscardButton_)restoreDiscardButton_->setEnabled(false);
    }
    if(vaultMessage_)vaultMessage_->setText(!initialized?
        QStringLiteral("Configuración inicial pendiente. Solo se creará vault-general.kdbx."):
        (locked?QStringLiteral("Vaults bloqueados. Los módulos no pueden crear ni leer sus Vaults."):
                QStringLiteral("Desbloqueado. Los módulos pueden solicitar por IPC sus propios Vaults. No hay creación manual aquí.")));
    statusBar()->showMessage(initialized?QStringLiteral("Backend Rust conectado · KeePass inicializado"):
                          QStringLiteral("Debe configurar la contraseña maestra general"),3500);
}
