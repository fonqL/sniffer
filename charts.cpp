#include "charts.h"
#include "./ui_charts.h"

void charts::setCount(Count c){
    this->ipv4 = c.ipv4_c.size();
    this->ipv6 = c.ipv6_c.size();
    this->arp = c.arp_c.size();
    this->other = c.other_c.size();
    this->icmp = c.icmp_c.size();
    this->tcp = c.tcp_c.size();
    this->udp = c.udp_c.size();
    this->other_h = c.other_header_c.size();
    this->dns = c.dns_c.size();
    this->other_h = c.other_app_c.size();
}

charts::charts(QWidget* parent)
    : QDialog(parent), ui(new Ui::Dialog) {
    ui->setupUi(this);

    

}

charts::~charts() {
    delete ui;
}