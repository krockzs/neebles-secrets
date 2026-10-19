#pragma once
#include <QMainWindow>
#include <QJsonObject>
#include <QVector>
class QCheckBox;
class QComboBox;
class QLineEdit;
class QLabel;
class QPushButton;
class QSpinBox;
class QStackedWidget;
class QTabWidget;

class MainWindow final:public QMainWindow {
public:
    explicit MainWindow(QString moduleRoot,QWidget* parent=nullptr);
private:
    void showView(int index);
    void buildDashboard();
    void buildQuick();
    void buildVaults();
    void generate();
    void refreshStatus();
    void toggleUnlock();
    QJsonObject call(const QJsonObject& request,QString* error=nullptr);
    QString root_;
    QTabWidget* tabs_=nullptr;
    QStackedWidget* views_=nullptr;
    QVector<QPushButton*> navigation_;
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
};
