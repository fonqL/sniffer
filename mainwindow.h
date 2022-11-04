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
    device* dev;
    std::vector<std::vector<std::any> > *packets;
    QStandardItemModel *model;
};
#endif // MAINWINDOW_H
