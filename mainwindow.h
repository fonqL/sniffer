#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "charts.h"
#include <QMainWindow>
#include <QStandardItemModel>
#include <QTimer>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow* ui;
    QLabel* textEdit;
    uint device_choose;
    bool stop;
    bool hadClear;
    bool hadDetails;

    bool openFile;
    QString fileName;
    device_list devices;
    std::unique_ptr<device> dev;
    std::vector<std::vector<std::any>> packets;
    QStandardItemModel* model;
    QStandardItemModel* t_model;
    Count count;
    std::vector<Count_time> count_t;

    std::vector<int> show_result;

    const int MAXSHOW = 20;

    //i为packets中packet的下标
    void addRow(int i);
    void showDetails(int i);
    void showRow(int i);
    QString catch_filt;
    QString show_filt;
    bool catch_f;
    bool show_f;

    /*---------------------显示过滤器的一些声明-------------------*/
    bool is_a_sentence(QString fil);
    bool is_a_filter(std::string filter);
    std::vector<int> catched_filter(std::string s);
    std::vector<int> analyse_filter(std::string filter);
    std::vector<std::string> split_and(std::string filter);
    std::vector<std::string> split_or(std::string filter);
    std::vector<int> complex_or(std::vector<std::vector<int>> temp);
    std::vector<int> complex_and(std::vector<std::vector<int>> temp);
    std::vector<int> fixed_result(std::vector<int> temp);
    /*------------------------------------------------------------*/
};
#endif // MAINWINDOW_H
