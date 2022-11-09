#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "charts.h"
#include <QMainWindow>
#include <QTimer>
#include <QDateTime>
#include <QStandardItemModel>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

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
    void showRow(int i);
    QString catch_filt;
    QString show_filt;
    bool catch_f;
    bool show_f;
};
#endif // MAINWINDOW_H
