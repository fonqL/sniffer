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
    void setCount(Count c);

private:
    Ui::Dialog *ui;
    int ipv4;
    int ipv6;
    int arp;
    int other;
    int icmp;
    int tcp;
    int udp;
    int other_h;
    int dns;
    int other_a;
};