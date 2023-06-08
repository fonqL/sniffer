#pragma once

#include "ProxyVector.h"
#include "analysis.h"
#include "device.h"
#include "filter.h"
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
    // todo 解决析构问题
    // 挂到qt对象树上，不用析构
    // 因为无法在qtdesign里往statusbar添加部件所以必须在这添加。。
    class QLabel* textEdit;
    uint device_choose;
    QTimer* timer;
    QDateTime time_record;

    QString fileName;
    device_list devices;
    // 延迟初始化，相当于optional，所以用unique_ptr而不是值
    std::unique_ptr<device> dev;
    ProxyVector packets;
    // 挂到qt对象树上，不用析构
    class CustomItemModel* model;
    // 挂到qt对象树上，不用析构
    class QStandardItemModel* tr_model;
    Count count;
    std::vector<Count_time> count_t;

    std::vector<size_t> shows;

    static constexpr size_t MAXSHOW = 100;
    static constexpr size_t SAMPLE_INTERVAL = 300; // 单位：秒

    //i均为底层packets中的下标
    void pushRow(size_t i);
    void pushRow(size_t i, const pack& x);
    void showDetails(int i);

    void handleShow(const pack& x);

    void setMaxPage(uint m);

    // 更新包的统计数据，idx也是底层packets下标
    void updStat(size_t idx, const pack& x);

    QString catch_filter;
    std::unique_ptr<ExprAST> show_filter;

    void genSample(QDateTime t);

    void jump();
    void applyShowFilter();

    void startCapture();
    void stopCapture();
    void capture();

    void reset();
};
