#include "MainWindow.h"
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QFormLayout>
#include <QFrame>
#include <QHBoxLayout>
#include <QIcon>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QDialog>
#include <QDialogButtonBox>
#include <QTimer>
#include <QLocalSocket>
#include <QMessageBox>
#include <QPixmap>
#include <QPushButton>
#include <QSpinBox>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTabBar>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QWidget>
#include <QtEndian>
#include <utility>

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
static bool askMasterKey(QWidget* parent, bool setup, QString* output) {
    QDialog dialog(parent);
    dialog.setWindowTitle(setup ? QStringLiteral("Configurar NEEBLES Secrets")
                               : QStringLiteral("Desbloquear NEEBLES Secrets"));
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(new QLabel(setup
        ? QStringLiteral("Crea una clave maestra para vault-general (mínimo 8 caracteres).")
        : QStringLiteral("Introduce tu clave maestra existente."), &dialog));
    auto* form = new QFormLayout();
    auto makeField = [&dialog](QLineEdit** field) -> QWidget* {
        auto* widget = new QWidget(&dialog);
        auto* row = new QHBoxLayout(widget);
        row->setContentsMargins(0, 0, 0, 0);
        *field = new QLineEdit(widget);
        (*field)->setEchoMode(QLineEdit::Password);
        (*field)->setMinimumWidth(280);
        row->addWidget(*field);
        auto* eye = new QPushButton(QStringLiteral("👁"), widget);
        eye->setCheckable(true);
        eye->setToolTip(QStringLiteral("Mostrar u ocultar clave"));
        eye->setAccessibleName(QStringLiteral("Mostrar u ocultar clave"));
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
    form->addRow(QStringLiteral("Clave maestra:"), makeField(&key));
    if (setup) {
        form->addRow(QStringLiteral("Confirmar clave:"), makeField(&confirmation));
    }
    layout->addLayout(form);
    auto* notice = new QLabel(&dialog);
    notice->setWordWrap(true);
    layout->addWidget(notice);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    layout->addWidget(buttons);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, [&]() {
        if (setup) {
            const auto bytes = key->text().toUtf8();
            if (bytes.size() < 8 || bytes.size() > 512) {
                notice->setText(QStringLiteral("La clave debe tener entre 8 y 512 bytes UTF-8."));
                return;
            }
            if (key->text() != confirmation->text()) {
                notice->setText(QStringLiteral("Las claves no coinciden."));
                return;
            }
        }
        if (key->text().contains(QChar('\n')) ||
            key->text().contains(QChar('\r')) ||
            key->text().contains(QChar('\0'))) {
            notice->setText(QStringLiteral("La clave contiene caracteres no permitidos."));
            return;
        }
        if (key->text().isEmpty()) {
            notice->setText(QStringLiteral("Introduce una clave maestra."));
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
    setWindowTitle(QStringLiteral("N.E.E.B.L.E.S. Secrets — 1.0.2"));
    setWindowIcon(QIcon(QDir(root_).filePath(QStringLiteral("assets/neebles-secrets-icon.png"))));
    setMinimumSize(900,570);resize(1240,780);
    setStyleSheet(QStringLiteral(R"QSS(
        QWidget { background:#09090B; color:#F5F5F5; font-size:13px; }
        QFrame#sidebar { background:#09090B; border-right:1px solid #5B21B6; }
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
    auto* sidebar=new QFrame(root);sidebar->setObjectName(QStringLiteral("sidebar"));sidebar->setFixedWidth(235);
    auto* left=new QVBoxLayout(sidebar);left->setContentsMargins(14,14,14,14);
    auto* logo=new QLabel(sidebar);logo->setAlignment(Qt::AlignLeft|Qt::AlignVCenter);
    QPixmap photo(QDir(root_).filePath(QStringLiteral("assets/neebles-secrets-logo.png")));
    if(!photo.isNull()) logo->setPixmap(photo.scaled(142,88,Qt::KeepAspectRatio,Qt::SmoothTransformation));
    left->addWidget(logo);left->addSpacing(24);
    const QStringList labels={QStringLiteral("◈  Dashboard"),QStringLiteral("⚡  Quick Secrets"),QStringLiteral("▤  My Secrets")};
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
    left->addWidget(note(QStringLiteral("Secrets v1.0.2"),sidebar));
    row->addWidget(sidebar);
    auto* right=new QWidget(root);auto* rightLayout=new QVBoxLayout(right);
    auto* header=new QHBoxLayout();
    header->addWidget(note(QStringLiteral("N.E.E.B.L.E.S. Secrets"),right));
    header->addStretch();
    status_=new QLabel(QStringLiteral("Locked"),right);header->addWidget(status_);
    rightLayout->addLayout(header);
    tabs_=new QTabWidget(right);tabs_->setTabsClosable(false);tabs_->setMovable(false);tabs_->setDocumentMode(true);
    views_=new QStackedWidget(tabs_);
    buildDashboard();buildQuick();buildVaults();
    tabs_->addTab(views_,QStringLiteral("Dashboard"));
    rightLayout->addWidget(tabs_,1);row->addWidget(right,1);
    setCentralWidget(root);
    connect(unlock_,&QPushButton::clicked,this,[this](){ toggleUnlock(); });
    showView(0);refreshStatus();
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
void MainWindow::showView(int index){
    if(index<0||index>=3)return;
    const QStringList names={QStringLiteral("Dashboard"),QStringLiteral("Quick Secrets"),QStringLiteral("My Secrets")};
    if(views_->currentIndex()==1 && index!=1 && generated_) generated_->clear();
    views_->setCurrentIndex(index);tabs_->setTabText(0,names[index]);
    for(int i=0;i<navigation_.size();++i)navigation_[i]->setChecked(i==index);
    if(index==0||index==2) refreshStatus();
}
void MainWindow::buildDashboard(){
    auto* page=new QWidget(views_);auto* layout=new QVBoxLayout(page);
    layout->addWidget(heading(QStringLiteral("Dashboard"),page));
    layout->addWidget(note(QStringLiteral("NEEBLES Secrets — Backend Rust / Socket Unix / Vaults dinámicos"),page));
    layout->addSpacing(25);
    layout->addWidget(note(QStringLiteral("Quick Secrets funciona sin desbloquear. Los Vaults se crean únicamente a petición de cada módulo y solo si Secrets está desbloqueado."),page));
    auto* refresh=new QPushButton(QStringLiteral("Actualizar estado del servicio"),page);
    layout->addWidget(refresh,0,Qt::AlignLeft);
    connect(refresh,&QPushButton::clicked,this,[this](){refreshStatus();});
    layout->addStretch();views_->addWidget(page);
}
void MainWindow::buildQuick(){
    auto* page=new QWidget(views_);auto* layout=new QVBoxLayout(page);
    layout->addWidget(heading(QStringLiteral("Quick Secrets"),page));
    layout->addWidget(note(QStringLiteral("Generación temporal; los resultados no se guardan."),page));
    auto* form=new QFormLayout();
    kind_=new QComboBox(page);
    kind_->addItem(QStringLiteral("Contraseña segura"),QStringLiteral("password"));
    kind_->addItem(QStringLiteral("Token hexadecimal"),QStringLiteral("hex"));
    kind_->addItem(QStringLiteral("Token Base64URL"),QStringLiteral("base64url"));
    kind_->addItem(QStringLiteral("UUID v4"),QStringLiteral("uuid"));
    length_=new QSpinBox(page);length_->setRange(8,128);length_->setValue(24);
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
        else if(pw) { length_->setRange(8,128);length_->setValue(24); }
        else { length_->setRange(16,128);length_->setValue(32); }
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
    layout->addWidget(note(QStringLiteral("Al salir de Quick Secrets, el resultado desaparece de esta interfaz. El portapapeles es administrado por el escritorio."),page));
    layout->addStretch();
    connect(run,&QPushButton::clicked,this,[this](){generate();});
    connect(copy_,&QPushButton::clicked,this,[this](){
        if(!generated_->text().isEmpty()) QApplication::clipboard()->setText(generated_->text());
    });
    views_->addWidget(page);
}
void MainWindow::buildVaults(){
    auto* page=new QWidget(views_);auto* layout=new QVBoxLayout(page);
    layout->addWidget(heading(QStringLiteral("My Secrets"),page));
    vaultMessage_=note(QStringLiteral("Los Vaults requieren desbloqueo desde esta interfaz. Cada módulo pide su propia bóveda por IPC."),page);
    layout->addWidget(vaultMessage_);
    layout->addWidget(note(QStringLiteral("Ubicación futura: ~/.local/share/neebles-secrets/vaults/\n"
      "vault-general.kdbx\nvault-<modulo>.kdbx"),page));
    layout->addStretch();views_->addWidget(page);
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
        if(error)*error=QStringLiteral("Falló el envío IPC");return {};
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
        if(error)*error=QStringLiteral("Respuesta IPC inválida");return {};
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
    if(!askMasterKey(this,setup,&password)){
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
}
void MainWindow::refreshStatus(){
    QString error;const auto result=call(QJsonObject{{QStringLiteral("op"),QStringLiteral("vault.status")}},&error);
    if(result.isEmpty()||!result.value(QStringLiteral("ok")).toBool()){
        status_->setText(QStringLiteral("● Offline"));unlock_->setEnabled(false);unlock_->setVisible(false);
        if(vaultMessage_)vaultMessage_->setText(QStringLiteral("Backend desconectado. Los Vaults no están disponibles."));
        statusBar()->showMessage(error.isEmpty()?QStringLiteral("Backend desconectado"):error);
        return;
    }
    const auto data=result.value(QStringLiteral("data")).toObject();
    const bool initialized=data.value(QStringLiteral("initialized")).toBool();
    const bool locked=data.value(QStringLiteral("locked")).toBool();
    status_->setText(locked?QStringLiteral("● Locked"):QStringLiteral("● Unlocked"));
    unlock_->setEnabled(initialized);
    unlock_->setVisible(initialized);
    unlock_->setText(locked?QStringLiteral("🔒  Desbloquear"):QStringLiteral("🔓  Bloquear"));
    if(vaultMessage_)vaultMessage_->setText(!initialized?
        QStringLiteral("Configuración inicial pendiente. Solo se creará vault-general.kdbx."):
        (locked?QStringLiteral("Vaults bloqueados. Los módulos no pueden crear ni leer sus Vaults."):
                QStringLiteral("Desbloqueado. Los módulos pueden solicitar por IPC sus propios Vaults. No hay creación manual aquí.")));
    statusBar()->showMessage(initialized?QStringLiteral("Backend Rust conectado · KeePass inicializado"):
                          QStringLiteral("Debe configurar la contraseña maestra general"),3500);
}
