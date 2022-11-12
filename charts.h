#pragma once

#include "analysis.h"
#include <QDialog>
#include <QtCharts>

QT_BEGIN_NAMESPACE
namespace Ui { class Dialog; }
QT_END_NAMESPACE


class charts : public QDialog{
    Q_OBJECT

public:
    charts(QWidget *parent = nullptr);
    ~charts();
    void setCount(std::vector<Count_time> c);

private:
    Ui::Dialog *ui;
    std::unique_ptr<QChart> chart;
    std::vector<Count_time> count_t;
};