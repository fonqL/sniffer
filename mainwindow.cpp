#include "mainwindow.h"
#include "./ui_mainwindow.h"

void MainWindow::showRow(int i){
    analysis *ana = new analysis(this->packets->at(i));
    this->model->appendRow(
        QList<QStandardItem *>()
            << new QStandardItem(QString::number(i+1))
            << new QStandardItem(ana->time)
            << new QStandardItem(ana->header)
            << new QStandardItem(ana->srcIp)
            << new QStandardItem(ana->desIp)
            << new QStandardItem(ana->len)
        //  << new QStandardItem()
    );
}

void MainWindow::addRow(int i){
    
    analysis *ana = new analysis(this->packets->at(i));
    if(ana->type=="IPv4"){
        this->count.ipv4_c.push_back(i);
    }
    else if(ana->type=="IPv6"){
        this->count.ipv6_c.push_back(i);
    }
    else if(ana->type=="ARP"){
        this->count.arp_c.push_back(i);
    } 
    else if(ana->type=="other"){
        this->count.other_c.push_back(i);
    }

    if(ana->header=="icmp"){
        this->count.icmp_c.push_back(i);
    }
    else if(ana->header=="tcp"){
        this->count.tcp_c.push_back(i);
    }
    else if(ana->header=="udp"){
        this->count.udp_c.push_back(i);
    }
    else if(ana->header=="other"){
        this->count.other_header_c.push_back(i);
    }

    if(ana->app=="dns"){
        this->count.dns_c.push_back(i);
    }
    else if(ana->app=="other"){
        this->count.other_app_c.push_back(i);
    }
    this->showRow(i);
}

void MainWindow::showDetails(int i){

    if(i>=this->packets->size()){
        return;
    }
    

    QStandardItemModel* model = new QStandardItemModel(ui->treeView);

    this->t_model = model;
    this->hadDetails = true;
    model->setHorizontalHeaderLabels(QStringList()<<("第"+QString::number(i+1)+"个包"));

    QStandardItem* eth_d = new QStandardItem("以太头");
    model->appendRow(eth_d);
    analysis *ana = new analysis(this->packets->at(i));
    eth_d->appendRow(new QStandardItem("类型: "+ana->type));
    eth_d->appendRow(new QStandardItem("源mac: "+ana->srcMac));
    eth_d->appendRow(new QStandardItem("目的mac: "+ana->desMac));
    ui->data->setText(ana->rawdata);

    if(ana->type=="IPv4"){
        QStandardItem* ip_d = new QStandardItem("IP包头");
        model->appendRow(ip_d);
        ip_d->appendRow(new QStandardItem("版本: 4"));
        ip_d->appendRow(new QStandardItem("源ip: "+ana->srcIp));
        ip_d->appendRow(new QStandardItem("目的ip: "+ana->desIp));
        ip_d->appendRow(new QStandardItem("长度: "+ana->len));
        ip_d->appendRow(new QStandardItem("tos: " + QString::asprintf("0X%02x",ana->ipv4.ds)));
        ip_d->appendRow(new QStandardItem("ttl: "+QString::asprintf("0X%02x",ana->ipv4.ttl)));
        QStandardItem* flag = new QStandardItem("flag");
        flag->appendRow(new QStandardItem("id: "+QString::asprintf("%d",(int)ana->ipv4.id)));
        flag->appendRow(new QStandardItem("DF: "+QString::asprintf("%d",(int)ana->ipv4.df)));
        flag->appendRow(new QStandardItem("MF: "+QString::asprintf("%d",(int)ana->ipv4.mf)));
        flag->appendRow(new QStandardItem("offset: "+QString::asprintf("%d",(int)ana->ipv4.offset)));
        ip_d->appendRow(flag);

        ip_d->appendRow(new QStandardItem("校验和: "+QString::asprintf("%d",(int)ana->ipv4.checksum)));
    }
    else if(ana->type=="ARP"){
        QStandardItem* arp_d = new QStandardItem("ARP包");
        model->appendRow(arp_d);
        QString arp_type="unknown";
        if((int)ana->arp.op==1){
            arp_type = "request";
        }
        else if((int)ana->arp.op==2){
            arp_type = "reply";
        }
        arp_d->appendRow(new QStandardItem("类型: "+arp_type));

        arp_d->appendRow(new QStandardItem("源ip: "+ana->srcIp));

        char *buf = (char *)malloc(80 * sizeof(char));
        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", ana->arp.src_mac[0], ana->arp.src_mac[1], 
        ana->arp.src_mac[2], ana->arp.src_mac[3], ana->arp.src_mac[4], ana->arp.src_mac[5]);
        arp_d->appendRow(new QStandardItem("源mac: "+QString(QLatin1String(buf))));

        arp_d->appendRow(new QStandardItem("目的ip: "+ana->desIp));

        buf = (char *)malloc(80 * sizeof(char));
        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", ana->arp.dst_mac[0], ana->arp.dst_mac[1], 
        ana->arp.dst_mac[2], ana->arp.dst_mac[3], ana->arp.dst_mac[4], ana->arp.dst_mac[5]);
        arp_d->appendRow(new QStandardItem("目的mac: "+QString(QLatin1String(buf))));

    }
    else if(ana->type=="IPv6"){
        QStandardItem* ip_d = new QStandardItem("IP包头");
        model->appendRow(ip_d);
        ip_d->appendRow(new QStandardItem("版本: 6"));
        ip_d->appendRow(new QStandardItem("源ip: "+ana->srcIp));
        ip_d->appendRow(new QStandardItem("目的ip: "+ana->desIp));
        ip_d->appendRow(new QStandardItem("净荷长度: "+ana->len));
        ip_d->appendRow(new QStandardItem("流量类别: " + QString::asprintf("0X%x",ana->ipv6.traffic_class)));
        ip_d->appendRow(new QStandardItem("流标签: " + QString::asprintf("0X%x",ana->ipv6.flow_label)));
        ip_d->appendRow(new QStandardItem("下一报头: " + QString::asprintf("0X%x",ana->ipv6.next_header)));
        ip_d->appendRow(new QStandardItem("跳数限制: " + QString::asprintf("%u",ana->ipv6.hop_limit)));
        
    }

    if(ana->header=="icmp"){
            QStandardItem* icmp_d = new QStandardItem("icmp");
            model->appendRow(icmp_d);

            int type = (int)ana->icmp.type, code = (int)ana->icmp.code;
            QString msg = "";

            if(type==0&&code==0){
                msg = "回应应答";
            }
            else if(type==3&&code==0){
                msg = "网络不可达";
            }
            else if(type==3&&code==1){
                msg = "主机不可达";
            }
            else if(type==5&&code==1){
                msg = "为主机重定向数据包";
            }
            else if(type==8&&code==0){
                msg = "回应";
            }
            else if(type==11&&code==0){
                msg = "超时";
            }
            else{
                msg = "其他";
            }

            icmp_d->appendRow(new QStandardItem("type: "+QString::asprintf("%d", type)));
            icmp_d->appendRow(new QStandardItem("code: "+QString::asprintf("%d", code)));
            icmp_d->appendRow(new QStandardItem("校验和: "+QString::asprintf("%d",(int)ana->icmp.checksum)));
            icmp_d->appendRow(new QStandardItem("含义: "+msg));
        }
    else if(ana->header=="tcp"){
        QStandardItem* tcp_d = new QStandardItem("tcp");
        model->appendRow(tcp_d);
        tcp_d->appendRow(new QStandardItem("长度: "+QString::asprintf("%d", ana->tcp.header_len)));
        tcp_d->appendRow(new QStandardItem("源端口: "+QString::asprintf("%d", ana->tcp.src)));
        tcp_d->appendRow(new QStandardItem("目的端口: "+QString::asprintf("%d", ana->tcp.dst)));
        tcp_d->appendRow(new QStandardItem(
            QString::asprintf("seq: 0x%x  ack: 0x%x", ana->tcp.seq, ana->tcp.ack)
        ));
        QStandardItem* flags = new QStandardItem("flags");
        tcp_d->appendRow(flags);
        flags->appendRow(new QStandardItem("fin: "+QString::asprintf("%d", ana->tcp.flags.fin)));
        flags->appendRow(new QStandardItem("syn: "+QString::asprintf("%d", ana->tcp.flags.syn)));
        flags->appendRow(new QStandardItem("rst: "+QString::asprintf("%d", ana->tcp.flags.rst)));
        flags->appendRow(new QStandardItem("psh: "+QString::asprintf("%d", ana->tcp.flags.psh)));
        flags->appendRow(new QStandardItem("ack: "+QString::asprintf("%d", ana->tcp.flags.ack)));
        flags->appendRow(new QStandardItem("urg: "+QString::asprintf("%d", ana->tcp.flags.urg)));
        flags->appendRow(new QStandardItem("ece: "+QString::asprintf("%d", ana->tcp.flags.ece)));
        flags->appendRow(new QStandardItem("cwr: "+QString::asprintf("%d", ana->tcp.flags.cwr)));

        tcp_d->appendRow(new QStandardItem("窗口尺寸: "+QString::asprintf("%d", ana->tcp.window_size)));
        tcp_d->appendRow(new QStandardItem("校验和: "+QString::asprintf("%d", ana->tcp.checksum)));
        tcp_d->appendRow(new QStandardItem("紧急指针: "+QString::asprintf("%d", ana->tcp.urgent_ptr)));
    }
    else if(ana->header=="udp"){
        QStandardItem* udp_d = new QStandardItem("udp");
        model->appendRow(udp_d);
        udp_d->appendRow(new QStandardItem("源端口: "+QString::asprintf("%d", ana->udp.src)));
        udp_d->appendRow(new QStandardItem("目的端口: "+QString::asprintf("%d", ana->udp.dst)));
        udp_d->appendRow(new QStandardItem("长度: "+QString::asprintf("%d", ana->udp.len)));
        udp_d->appendRow(new QStandardItem("校验和: "+QString::asprintf("%d", ana->udp.checksum)));
    }

    if(ana->app=="dns"){
        QStandardItem* dns_d = new QStandardItem("dns");
        model->appendRow(dns_d);
        dns_d->appendRow(new QStandardItem("事物id: "+QString::asprintf("%d", ana->dns.id)));
        dns_d->appendRow(new QStandardItem("问题计数: "+QString::asprintf("%d", ana->dns.questions)));
        dns_d->appendRow(new QStandardItem("回答资源记录数: "+QString::asprintf("%d", ana->dns.answer_rrs)));
        dns_d->appendRow(new QStandardItem("权威名称服务器计数: "+QString::asprintf("%d", ana->dns.authority_rrs)));
        dns_d->appendRow(new QStandardItem("附加资源记录数: "+QString::asprintf("%d", ana->dns.additional_rrs)));
        QStandardItem* flags = new QStandardItem("flags");
        dns_d->appendRow(flags);
        
        QString msg = "";
        if((int)ana->dns.flags.qr==0)
            msg = "查询请求";
        else
            msg = "响应";
        flags->appendRow(new QStandardItem("QR: "+QString::asprintf("%d ", ana->dns.flags.qr)+ msg));
        
        if((int)ana->dns.flags.opcode==0)
            msg = "标准查询";
        else if((int)ana->dns.flags.opcode==1)
            msg = "反向查询";
        else if((int)ana->dns.flags.opcode==2)
            msg = "服务器状态请求";
        flags->appendRow(new QStandardItem("opcode: "+QString::asprintf("%d ", ana->dns.flags.opcode)+ msg));
        
        if((int)ana->dns.flags.aa==0)
            msg = "非权威服务器";
        else if((int)ana->dns.flags.aa==1)
            msg = "权威服务器";
        flags->appendRow(new QStandardItem("AA: "+QString::asprintf("%d ", ana->dns.flags.aa)+ msg));
        
        if((int)ana->dns.flags.tc==0)
            msg = "未截断";
        else if((int)ana->dns.flags.tc==1)
            msg = "已截断";
        flags->appendRow(new QStandardItem("TC: "+QString::asprintf("%d ", ana->dns.flags.tc)+ msg));
        
        flags->appendRow(new QStandardItem("RD: "+QString::asprintf("%d ", ana->dns.flags.rd)));

        if((int)ana->dns.flags.ra==0)
            msg = "不支持递归查询";
        else if((int)ana->dns.flags.ra==1)
            msg = "支持递归查询";
        flags->appendRow(new QStandardItem("RA: "+QString::asprintf("%d ", ana->dns.flags.ra)+ msg));

        if((int)ana->dns.flags.rcode == 0)
            msg = "无错误";
        else if((int)ana->dns.flags.rcode == 1)
            msg = "格式错误";
        else if((int)ana->dns.flags.rcode == 2)
            msg = "服务器失败";
        else if((int)ana->dns.flags.rcode == 3)
            msg = "名字错误";
        else if((int)ana->dns.flags.rcode == 4)
            msg = "类型不支持";
        else if((int)ana->dns.flags.rcode == 5)
            msg = "拒绝应答";
        flags->appendRow(new QStandardItem("rcode: "+QString::asprintf("%d ", ana->dns.flags.rcode)+ msg));
    }

    ui->treeView->setModel(model);

}

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);
    device_list devices;
    auto x = devices.to_strings();
    // 显示网卡
    for (uint i = 0; i < x.size(); i++) {
        ui->comboBox->addItem(x[i]);
    }
    // 选中的下标,做成主页面类的成员变量了,因为lamda表达式传值很麻烦，后面用到也可以用这个办法（引用传值屁用没有
    // 点击开始抓包按钮后可以用这个值
    this->device_choose = 0;
    this->stop = true;
    this->hadClear = true;
    this->hadDetails = false;
    this->packets = new std::vector< std::vector<std::any> >();
    this->model = new QStandardItemModel(this);

    model->setHorizontalHeaderLabels(QStringList()<<"序号"<<"时间"<<"协议"<<"源ip"<<"目的ip"<<"长度");
    ui->tableView->setModel(this->model);
    ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    connect(ui->comboBox, &QComboBox::currentIndexChanged, this, [this]() {
        this->device_choose = (uint)ui->comboBox->currentIndex();
    });

    //点击查看包详细内容
    connect(ui->tableView, &QTableView::clicked, this, [this](){
        int row = ui-> tableView ->currentIndex().row();
        QModelIndex index1 = this->model->index(row, 0);
        QString id = this->model->data(index1).toString();
        int i = id.toInt();
        this->showDetails(i-1);
    });

    this->catch_filt = "";
    this->show_filt = "";
    this->catch_f = false;
    this->show_f = false;

    //抓包过滤
    connect(ui->pushButton_4, &QPushButton::clicked, this, [=](){
        this->catch_f = true;
        this->catch_filt = ui->lineEdit->text();
    });

    QTimer* timer = new QTimer(this);
    connect(timer, &QTimer::timeout, [this]()mutable {
        // device_list devices;
        //设置过滤规则

        std::vector<std::any> packet = this->dev->try_get();

        if (packet.size() > 0) {
            //处理info...
            this->packets->push_back(packet);

            int index = this->packets->size();

            //在这里进行过滤
            if(true){
                this->addRow(index-1);
                ui->tableView->scrollToBottom();
            }
            

        } else {
            
        }

        ui->textEdit->setText(QString::asprintf(
            "ipv4: %d  ipv6: %d  arp: %d  other %d\nicmp: %d  tcp: %d  udp %d  other %d\ndns: %d  other: %d",
            this->count.ipv4_c.size(),this->count.ipv6_c.size(),this->count.arp_c.size(),this->count.other_c.size(),
            this->count.icmp_c.size(),this->count.tcp_c.size(),this->count.udp_c.size(),this->count.other_header_c.size(),
            this->count.dns_c.size(),this->count.other_app_c.size()
        ));

    });
    //开启线程
    connect(ui->pushButton_2, &QPushButton::clicked, this, [=, devices = std::move(devices)]()mutable {
        if(this->stop){
            this->stop = false;
            this->dev = new device(devices.open(this->device_choose));
            if(this->catch_f){
                bool error = this->dev->set_filter(this->catch_filt.toStdString());
            } 
            this->dev->start_capture();
            timer->start(50);
            this->hadClear = false;
        }    
    });

    //结束抓包
    connect(ui->pushButton, &QPushButton::clicked, this, [=]() {
        if(!this->stop){
            this->stop = true;
            timer->stop();
            this->dev->stop();
            delete this->dev;
        }
        
    });

    //显示统计图
    connect(ui->pushButton_6, &QPushButton::clicked, this, [=](){
        charts *ch = new charts();
        ch->setCount(this->count);
        ch->show();
    });

    //清空
    connect(ui->pushButton_5, &QPushButton::clicked, this, [=](){
        if(this->stop&&!this->hadClear){
            this->packets->clear();
            this->model->clear();
            model->setHorizontalHeaderLabels(QStringList()<<"序号"<<"时间"<<"协议"<<"源ip"<<"目的ip"<<"长度");

            this->count.ipv4_c.clear();
            this->count.ipv6_c.clear();
            this->count.arp_c.clear();
            this->count.other_c.clear();
            this->count.icmp_c.clear();
            this->count.tcp_c.clear();
            this->count.udp_c.clear();
            this->count.other_header_c.clear();
            this->count.dns_c.clear();
            this->count.other_app_c.clear();

            ui->textEdit->clear();
            ui->data->clear();
            if(this->hadDetails){
                this->t_model->clear();
            }
            this->hadClear = true;
            this->hadDetails = false;
        }
    });

}

MainWindow::~MainWindow() {
    delete this->packets;
    delete ui;
}
