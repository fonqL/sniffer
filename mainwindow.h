#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QDateTime>
#include <QStandardItemModel>
#include "analysis.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

struct Count{
    std::vector<int> ipv4_c;
    std::vector<int> ipv6_c;
    std::vector<int> arp_c;
    std::vector<int> other_c;
    std::vector<int> icmp_c;
    std::vector<int> tcp_c;
    std::vector<int> udp_c;
    std::vector<int> other_header_c;
    std::vector<int> dns_c;
    std::vector<int> other_app_c;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    uint device_choose;
    bool stop;
    bool hadClear;
    bool hadDetails;
    device* dev;
    std::vector<std::vector<std::any> > *packets;
    QStandardItemModel *model;
    QStandardItemModel *t_model;
    Count count;
    //i为packets中packet的下标
    void addRow(int i);
    void showDetails(int i);
};
#endif // MAINWINDOW_H
