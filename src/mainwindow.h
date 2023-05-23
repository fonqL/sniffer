#pragma once

#include "ProxyVector.h"
#include "analysis.h"
#include "device.h"
#include <QMainWindow>

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
    // 挂到qt对象树上，不用析构
    class QLabel* textEdit;
    uint device_choose;
    bool stop;
    bool hadClear;
    bool hadDetails;
    QDateTime time_record;

    QString fileName;
    device_list devices;
    std::unique_ptr<device> dev;
    ProxyVector packets;
    // 挂到qt对象树上，不用析构
    class CustomItemModel* model;
    // 挂到qt对象树上，不用析构
    class QStandardItemModel* t_model;
    Count count;
    std::vector<Count_time> count_t;

    std::vector<int> show_result;

    static constexpr int MAXSHOW = 100;

    //i为packets中packet的下标
    void addRow(pack x);
    void showRow(size_t i);
    void showRow(size_t i, const pack& x);
    void showDetails(int i);
    QString catch_filt;
    QString show_filt;
    bool catch_f;
    bool show_f;

    // /*---------------------显示过滤器的一些声明-------------------*/
    // bool is_a_sentence(const QString& fil);
    // bool is_a_filter(const std::string& filter);
    // std::vector<int> catched_filter(const std::string& s);
    // std::vector<int> analyse_filter(const std::string& filter);
    // std::vector<std::string> split_and(const std::string& filter);
    // std::vector<std::string> split_or(const std::string& filter);
    // std::vector<int> complex_or(std::vector<std::vector<int>>& temp);
    // std::vector<int> complex_and(std::vector<std::vector<int>>& temp);
    // std::vector<int> fixed_result(const ProxyIntVector& temp);
    // /*------------------------------------------------------------*/

    void timerUpdate();
    void countUpdate(QDateTime t);
};
