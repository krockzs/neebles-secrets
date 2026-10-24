#pragma once
#include <QMainWindow>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPointer>
#include <atomic>
#include <memory>
#include <QJsonObject>
#include <QByteArray>
#include <QStringList>
#include <QVector>
class QCheckBox;
class QComboBox;
class QLineEdit;
class QListWidget;
class QListWidgetItem;
class QLabel;
class QPushButton;
class QSpinBox;
class QStackedWidget;
class QTabWidget;
class QThread;
class QLocalSocket;
class QTimer;

class MainWindow final:public QMainWindow {
public:
    explicit MainWindow(QString moduleRoot,QWidget* parent=nullptr);
    ~MainWindow() override;
private:
    void showView(int index);
    void setPersonalAvailable(bool available);
    void startStatusProbe();
    void cancelStatusProbe();
    void finishStatusProbe(QLocalSocket* socket,const QJsonObject& response,const QString& error);
    void applyStatusResult(const QJsonObject& result,const QString& error);
    void buildDashboard();
    void buildQuick();
    void buildCryptoLab();
    void clearCryptoLab();
    void buildBatch();
    void buildBatchExport();
    void buildBackupPreview();
    void startVaultBackup(bool complete,const QString& fixedName=QString());
    void inspectRestoreBackup();
    void verifyRestoreMasterKey();
    void prepareVaultRestore();
    void commitVaultRestore();
    void discardVaultRestore();
    void setPersonalEditing(bool enabled);
    void reloadLanguage(bool force);
    void retranslateUi();
    QString translateText(const QString& source) const;
    void runBatchChunk();
    void stopBatch(bool clearOutput);
    void startBatchExport();
    void startPortableKdbxExport();
    void buildVaults();
    void generate();
    void refreshStatus();
    void toggleUnlock();
    void refreshPersonalList();
    void clearPersonalEditor();
    void openPersonalItem(QListWidgetItem* item);
    void savePersonalItem();
    void deletePersonalItem();
    QJsonObject call(const QJsonObject& request,QString* error=nullptr);
    QString root_;
    QString language_;
    QJsonObject translations_;
    QLabel* dashboardService_=nullptr;
    QLabel* dashboardVault_=nullptr;
    QLabel* dashboardModules_=nullptr;
    QTabWidget* tabs_=nullptr;
    QStackedWidget* views_=nullptr;
    QVector<QPushButton*> navigation_;
    QPushButton* personalShortcut_=nullptr;
    bool personalAvailable_=false;
    // Event-driven, bounded status observation. Never poll via synchronous call().
    QPointer<QLocalSocket> statusProbeSocket_;
    QByteArray statusProbeBuffer_;
    QTimer* statusProbeTimer_=nullptr;
    QPushButton* unlock_=nullptr;
    QLabel* status_=nullptr;
    QLabel* vaultMessage_=nullptr;
    QComboBox* kind_=nullptr;
    QSpinBox* length_=nullptr;
    QCheckBox* uppercase_=nullptr;
    QCheckBox* lowercase_=nullptr;
    QCheckBox* numbers_=nullptr;
    QCheckBox* symbols_=nullptr;
    QCheckBox* ambiguous_=nullptr;
    QLineEdit* generated_=nullptr;
    QPushButton* copy_=nullptr;
    QPushButton* save_=nullptr;
    QComboBox* labFamily_=nullptr;
    QComboBox* labAlgorithm_=nullptr;
    QComboBox* labEncoding_=nullptr;
    QCheckBox* labVerify_=nullptr;
    QLineEdit* labExpected_=nullptr;
    QLineEdit* labInput_=nullptr;
    QLineEdit* labKey_=nullptr;
    QLineEdit* labSalt_=nullptr;
    QLineEdit* labOutput_=nullptr;
    QLineEdit* labResultSalt_=nullptr;
    QSpinBox* labIterations_=nullptr;
    QSpinBox* labMemory_=nullptr;
    QSpinBox* labParallelism_=nullptr;
    QSpinBox* labBytes_=nullptr;
    QSpinBox* labScryptLogN_=nullptr;
    QComboBox* batchKind_=nullptr;
    QSpinBox* batchLength_=nullptr;
    QSpinBox* batchCount_=nullptr;
    QPlainTextEdit* batchPreview_=nullptr;
    QProgressBar* batchProgress_=nullptr;
    QComboBox* batchExportFormat_=nullptr;
    QComboBox* batchExportKind_=nullptr;
    QSpinBox* batchExportLength_=nullptr;
    QSpinBox* batchExportCount_=nullptr;
    QPushButton* batchExportStart_=nullptr;
    QPushButton* batchExportCancelButton_=nullptr;
    QProgressBar* batchExportProgress_=nullptr;
    QPointer<QThread> batchExportThread_;
    QPointer<QThread> backupThread_;
    QPointer<QThread> restoreInspectThread_;
    std::shared_ptr<std::atomic_bool> restoreInspectCancel_;
    QPushButton* restorePrepareButton_=nullptr;
    QPushButton* restoreCommitButton_=nullptr;
    QPushButton* restoreDiscardButton_=nullptr;
    QString restoreConfirmation_;
    QStringList restorePreparedNames_;
    QPushButton* restoreInspectButton_=nullptr;
    QPushButton* restoreCompatibilityButton_=nullptr;
    QPushButton* restoreInspectCancelButton_=nullptr;
    QPlainTextEdit* restoreInspectDetails_=nullptr;
    std::shared_ptr<std::atomic_bool> backupCancel_;
    QPushButton* backupSingleButton_=nullptr;
    QPushButton* backupFullButton_=nullptr;
    QPushButton* backupCancelButton_=nullptr;
    QProgressBar* backupProgress_=nullptr;
    std::shared_ptr<std::atomic_bool> batchExportCancelFlag_;
    QPushButton* batchStart_=nullptr;
    QPushButton* batchCancel_=nullptr;
    int batchRemaining_=0;
    int batchTotal_=0;
    bool batchRunning_=false;
    QListWidget* personalList_=nullptr;
    QLineEdit* personalFilter_=nullptr;
    QLineEdit* personalName_=nullptr;
    QLineEdit* personalTags_=nullptr;
    QLineEdit* personalContent_=nullptr;
    QComboBox* personalType_=nullptr;
    QCheckBox* personalReveal_=nullptr;
    QPushButton* personalSave_=nullptr;
    QPushButton* personalEdit_=nullptr;
    QString personalId_;
};
