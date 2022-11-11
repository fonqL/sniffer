#include "mainwindow.h"
#include "./ui_mainwindow.h"

/*----------显示过滤器的一些声明&函数定义--------*/
std::regex _empty(" ");//去除空格
std::regex _and(" and ");//关键字符
std::regex _or(" or ");
std::regex _bigger(">");//运算符
std::regex _smaller("<");
std::regex _big_or_eq(">=");
std::regex _small_or_eq("<=");
std::regex _equal("==");
std::regex _not_eq("!=");

void MainWindow::showRow(int i){
    if(this->model->rowCount()>(this->MAXSHOW-1)){
        this->model->removeRow(this->model->rowCount()-this->MAXSHOW);
    }

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
    this->openFile = false;
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
    ui->spinBox->setRange(1, 1);

    //显示过滤
    connect(ui->pushButton_3, &QPushButton::clicked, this, [=](){
        if(this->stop){
            if(!this->hadClear){
                this->model->clear();
                this->model->setHorizontalHeaderLabels(QStringList()<<"序号"<<"时间"<<"协议"<<"源ip"<<"目的ip"<<"长度");
                ui->data->clear();
                if(this->hadDetails){
                    this->t_model->clear();
                }
                this->hadDetails = false;
                this->show_filt = ui->lineEdit->text();
                this->show_f = true;

                //-------------------这里开始 hh
                if (is_a_sentence(this->show_filt)){//判断语法
                    show_result = catched_filter(this->show_filt.toStdString());
                    if (show_result.size() != 0) {
                        for (int i = 0;i < show_result.size();i++)
                            showRow(show_result[i]);
                        int max = show_result.size()/this->MAXSHOW;
                        max += show_result.size()%this->MAXSHOW?1:0;

                        ui->spinBox->setRange(1, max);
                        ui->spinBox->setValue(max);
                        ui->label_2->setText(QString::asprintf("共%d页", max));
                    }
                    else {
                        //过滤结果为空
                    }
                }
                else {
                    //报错：语法错误
                }
            }
        }
    });

    //抓包过滤
    connect(ui->pushButton_4, &QPushButton::clicked, this, [=](){
        this->catch_f = true;
        this->catch_filt = ui->lineEdit->text();
    });

    //清除过滤
    connect(ui->pushButton_7, &QPushButton::clicked, this, [=](){
        this->catch_f = false;
        this->catch_filt = "";
        this->show_f = false;
        this->show_filt = "";
        ui->lineEdit->clear();
        if(this->packets->size()>0){
            for (int i = this->packets->size()-this->MAXSHOW;i < this->packets->size();i++){
                if(i>=0){
                    showRow(i);
                }
            }
                
            int max = this->packets->size()/this->MAXSHOW;
            max += this->packets->size()%this->MAXSHOW?1:0;

            ui->spinBox->setRange(1, max);
            ui->spinBox->setValue(max);
            ui->label_2->setText(QString::asprintf("共%d页", max));
        }     
    });

    //保存 fq
    connect(ui->pushButton_8, &QPushButton::clicked, this, [=](){
        if(this->stop){//停止抓包后才能保存



        }
    });

    //打开  fq
    connect(ui->pushButton_9, &QPushButton::clicked, this, [=](){
        if(this->hadClear){//清空抓包界面才能打开
            
            this->openFile = true;

            //this->fileName获取文件名

        }
    });

    QTimer* timer = new QTimer(this);
    connect(timer, &QTimer::timeout, [this]()mutable {

        std::vector<std::any> packet = this->dev->try_get();

        if (packet.size() > 0) {
            //处理info...
            this->packets->push_back(packet);

            int index = this->packets->size();

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

    // 用于记录时间下包数量
    QTimer* timer_record = new QTimer(this);
    connect(timer_record, &QTimer::timeout, [this]()mutable {

        if(this->packets->size()>0){
            Count_time c_t;
            c_t.time = QDateTime::currentDateTime();
            c_t.arp = this->count.arp_c.size();
            c_t.ipv4 = this->count.ipv4_c.size();
            c_t.ipv6 = this->count.ipv6_c.size();
            c_t.other = this->count.other_c.size();
            c_t.icmp = this->count.icmp_c.size();
            c_t.tcp = this->count.tcp_c.size();
            c_t.udp = this->count.udp_c.size();
            c_t.other_h = this->count.other_header_c.size();
            c_t.dns = this->count.dns_c.size();
            c_t.other_a = this->count.other_app_c.size();
            this->count_t.push_back(c_t);
        }
    });

    //开启线程
    connect(ui->pushButton_2, &QPushButton::clicked, this, [=, devices = std::move(devices)]()mutable {
        if(this->stop){
            if(!this->openFile){
                this->stop = false;
                this->dev = new device(devices.open(this->device_choose));
                if(this->catch_f){
                    bool error = this->dev->set_filter(this->catch_filt.toStdString());
                } 
                this->dev->start_capture();
            }
            else{
                //fq
                //this->dev = 


            }
            timer->start(10);
            timer_record->start(1000);
            this->hadClear = false;
        }    
    });

    //结束抓包
    connect(ui->pushButton, &QPushButton::clicked, this, [=]() {
        if(!this->stop){
            this->stop = true;
            timer->stop();
            timer_record->stop();
            this->dev->stop();
            delete this->dev;

            int max = this->packets->size()/this->MAXSHOW;
            max += this->packets->size()%this->MAXSHOW?1:0;

            ui->spinBox->setRange(1, max);
            ui->label_2->setText(QString::asprintf("共%d页", max));
        }
        
    });

    //跳转
    connect(ui->pushButton_10, &QPushButton::clicked, this, [=](){
        if(this->stop){
            if(!this->hadClear){
                this->model->clear();
                model->setHorizontalHeaderLabels(QStringList()<<"序号"<<"时间"<<"协议"<<"源ip"<<"目的ip"<<"长度");
                for(int i = (ui->spinBox->value()-1)*this->MAXSHOW; i<ui->spinBox->value()*this->MAXSHOW; i++){
                    if(i<this->packets->size()){
                        if(this->show_f){
                            this->showRow(show_result[i]);
                        }
                        else{
                            this->showRow(i);
                        }
                    }                   
                }
            }
        }
    });

    //显示统计图
    connect(ui->pushButton_6, &QPushButton::clicked, this, [=](){
        if(this->stop){
            charts *ch = new charts();
            ch->setCount(this->count_t);
            ch->show();
        }
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

            this->count_t.clear();

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


/*-----------------------------------------------------------------*/
/*
    --ip、port仅支持==运算
    --各种包的len支持>、<=等运算符
    --多条件只允许只含有and/or,例如：
        tcp and dns and ip=0.0.0.0 √
        udp or tcp or !ipv4        √
        tcp and ipv4 or !dns       ×
        (真要搞这个太复杂了，懒得搞了)
    --值匹配：
        ip|ip.dst|ip.src|port
        tcp.port|tcp.dst|tcp.src
        udp.port|udp.dst|udp.src
        len|ipv4.len|.....|tcp.len
*/
//判断是不是一个合法的过滤语句
bool MainWindow::is_a_sentence(QString fil)
{
    std::string filter = fil.toStdString();
    if (std::regex_match(filter, std::regex(" *")))//空语句	
        return false;
    else if (std::regex_search(filter, _and))//and语句
    {
        std::vector<std::string> filt = split_and(filter);
        for (int i = 0;i < filt.size();i++)
        {
            if (is_a_filter(filt[i]) == false)
                return false;
        }
        return true;
    }
    else if (std::regex_search(filter, _or))//or语句
    {
        std::vector<std::string> filt = split_or(filter);
        for (uint i = 0;i < filt.size();i++)
        {
            if (is_a_filter(filt[i]) == false)
                return false;
        }
        return true;
    }
    else //单子句
    {
        return is_a_filter(filter);
    }
    //false报错：请输入正确的过滤语句
}

//判断子句有没有语法问题
bool MainWindow::is_a_filter(std::string filter)
{
    //端口范围：0-65535，超出会报错
    //ip范围：0.0.0.0--255.255.255.255
    if (std::regex_match(filter, std::regex(" *arp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *tcp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *udp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *icmp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *dns *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *ipv4 *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *ipv6 *", std::regex::icase)))
        return true;

    else if (std::regex_match(filter, std::regex("^ *ip\\.dst *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ip\\.src *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ip *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.dst *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.src *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.dst *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.src *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;

    //长度==
    else if (std::regex_match(filter, std::regex("^ *len *== *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *== *[1-9][0-9]* *$")))//arp包长度，下面同理
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *== *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *== *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *== *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *== *[1-9][0-9]* *$")))
        return true;

    //长度>=
    else if (std::regex_match(filter, std::regex("^ *len *>= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *>= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *>= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *>= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *>= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *>= *[1-9][0-9]* *$")))
        return true;

    //长度<=
    else if (std::regex_match(filter, std::regex("^ *len *<= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *<= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *<= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *<= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *<= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *<= *[1-9][0-9]* *$")))
        return true;

    //长度>
    else if (std::regex_match(filter, std::regex("^ *len *> *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *> *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *> *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *> *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *> *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *> *[1-9][0-9]* *$")))
        return true;

    //长度<
    else if (std::regex_match(filter, std::regex("^ *len *< *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *< *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *< *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *< *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *< *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *< *[1-9][0-9]* *$")))
        return true;

    //值不等,例如：ip != 0.0.0.0
    else if (std::regex_match(filter, std::regex("^ *ip\\.dst *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ip\\.src *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ip *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.dst *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.src *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.dst *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.src *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *len *!= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *!= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *!= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *!= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *!= *[1-9][0-9]* *$")))
        return true;
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *!= *[1-9][0-9]* *$")))
        return true;

    //不看某协议,例如： !dns
    if (std::regex_match(filter, std::regex(" *!arp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *!tcp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *!udp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *!icmp *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *!dns *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *!ipv4 *", std::regex::icase)))
        return true;
    else if (std::regex_match(filter, std::regex(" *!ipv6 *", std::regex::icase)))
        return true;

    else
        return false;
}

//过滤抓到的包,结果返回的出口
std::vector<int> MainWindow::catched_filter(std::string s)
{
    if (std::regex_search(s, _and))//and语句
    {
        std::vector <std::vector<int>> temp;
        std::vector<std::string> filt = split_and(s);
        //分析子句，将结果存入temp
        for (int i = 0;i < filt.size();i++)
        {
            temp.push_back(analyse_filter(filt[i]));
        }
        return complex_and(temp);
    }
    else if (std::regex_search(s, _or))//or语句
    {
        std::vector <std::vector<int>> temp;
        std::vector<std::string> filt = split_or(s);
        for (int i = 0;i < filt.size();i++)
        {
            temp.push_back(analyse_filter(filt[i]));
        }
        return complex_or(temp);
    }
    //单子句直接丢进analyse_filter()就能得出结果了
    else return analyse_filter(s);
}

//分析子句,返回一个索引容器
std::vector<int> MainWindow::analyse_filter(std::string filter)
{
    //预处理，将运算符后面的值提取出来存入set_data
    std::vector<std::string> temp_data;
    std::string set_data;
    std::vector<int> results;
    if ((std::regex_search(filter, _equal)))// ==
    {
        std::sregex_token_iterator beg(filter.begin(), filter.end(), _equal, -1);
        std::sregex_token_iterator end;
        for (; beg != end; beg++)
        {
            temp_data.push_back(beg->str());
        }
        if (temp_data.size() == 2) {
            set_data = std::regex_replace(temp_data[1], _empty, "");

        }
    }
    else if ((std::regex_search(filter, _big_or_eq)))// >=
    {
        std::sregex_token_iterator beg(filter.begin(), filter.end(), _big_or_eq, -1);
        std::sregex_token_iterator end;
        for (; beg != end; beg++)
        {
            temp_data.push_back(beg->str());
        }
        if (temp_data.size() == 2) {
            set_data = std::regex_replace(temp_data[1], _empty, "");

        }
    }
    else if ((std::regex_search(filter, _small_or_eq)))// <=
    {
        std::sregex_token_iterator beg(filter.begin(), filter.end(), _small_or_eq, -1);
        std::sregex_token_iterator end;
        for (; beg != end; beg++)
        {
            temp_data.push_back(beg->str());
        }
        if (temp_data.size() == 2) {
            set_data = std::regex_replace(temp_data[1], _empty, "");

        }
    }
    else if ((std::regex_search(filter, _smaller)))// <
    {
        std::sregex_token_iterator beg(filter.begin(), filter.end(), _smaller, -1);
        std::sregex_token_iterator end;
        for (; beg != end; beg++)
        {
            temp_data.push_back(beg->str());
        }
        if (temp_data.size() == 2) {
            set_data = std::regex_replace(temp_data[1], _empty, "");

        }
    }
    else if ((std::regex_search(filter, _bigger)))// >
    {
        std::sregex_token_iterator beg(filter.begin(), filter.end(), _bigger, -1);
        std::sregex_token_iterator end;
        for (; beg != end; beg++)
        {
            temp_data.push_back(beg->str());
        }
        if (temp_data.size() == 2) {
            set_data = std::regex_replace(temp_data[1], _empty, "");

        }
    }
    else if ((std::regex_search(filter, _not_eq)))
    {
        std::sregex_token_iterator beg(filter.begin(), filter.end(), _not_eq, -1);
        std::sregex_token_iterator end;
        for (; beg != end; beg++)
        {
            temp_data.push_back(beg->str());
        }
        if (temp_data.size() == 2) {
            set_data = std::regex_replace(temp_data[1], _empty, "");

        }
    }

    //按协议
    if (std::regex_match(filter, std::regex(" *arp *", std::regex::icase)))//arp协议
        return	this->count.arp_c;
    else if (std::regex_match(filter, std::regex(" *tcp *", std::regex::icase)))
        return this->count.tcp_c;
    else if (std::regex_match(filter, std::regex(" *udp *", std::regex::icase)))
        return this->count.udp_c;
    else if (regex_match(filter, std::regex(" *icmp *", std::regex::icase)))
        return this->count.icmp_c;
    else if (regex_match(filter, std::regex(" *dns *", std::regex::icase)))
        return this->count.dns_c;
    else if (regex_match(filter, std::regex(" *ipv4 *", std::regex::icase)))
        return this->count.ipv4_c;
    else if (std::regex_match(filter, std::regex(" *ipv6 *", std::regex::icase)))
        return this->count.ipv6_c;//下面是取反
    else if (std::regex_match(filter, std::regex(" *!arp *", std::regex::icase)))
        return	fixed_result(this->count.arp_c);
    else if (std::regex_match(filter, std::regex(" *!tcp *", std::regex::icase)))
        return fixed_result(this->count.tcp_c);
    else if (std::regex_match(filter, std::regex(" *!udp *", std::regex::icase)))
        return fixed_result(this->count.udp_c);
    else if (regex_match(filter, std::regex(" *!icmp *", std::regex::icase)))
        return fixed_result(this->count.icmp_c);
    else if (regex_match(filter, std::regex(" *!dns *", std::regex::icase)))
        return fixed_result(this->count.dns_c);
    else if (regex_match(filter, std::regex(" *!ipv4 *", std::regex::icase)))
        return fixed_result(this->count.ipv4_c);
    else if (std::regex_match(filter, std::regex(" *!ipv6 *", std::regex::icase)))
        return fixed_result(this->count.ipv6_c);

    //源、目的IP地址
    else if (std::regex_match(filter, std::regex("^ *ip *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            std::string saved1 = std::regex_replace(aaa->srcIp.toStdString(), _empty, "");
            std::string saved2 = std::regex_replace(aaa->desIp.toStdString(), _empty, "");
            if ((saved1 == set_data) || (saved2 == set_data))
                results.push_back(i);
        }
        return results;
    }
    //目的ip地址
    else if (std::regex_match(filter, std::regex("^ *ip\\.dst *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            std::string saved = std::regex_replace(aaa->desIp.toStdString(), _empty, "");
            if (saved == set_data)
                results.push_back(i);
        }
        return results;
    }
    //源ip地址
    else if (std::regex_match(filter, std::regex("^ *ip\\.src *== *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            std::string saved = std::regex_replace(aaa->srcIp.toStdString(), _empty, "");
            if (saved == set_data)
                results.push_back(i);
        }
        return results;
    }

    //TCP目的端口
    else if (std::regex_match(filter, std::regex("^ *tcp\\.dst *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->tcp.dst;
            uint16_t trans;//把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans == saved)
                results.push_back(i);
        }
        return results;
    }
    //TCP源端口
    else if (std::regex_match(filter, std::regex("^ *tcp\\.src *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->tcp.src;
            uint16_t trans;//把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans == saved)
                results.push_back(i);
        }
        return results;
    }
    //TCP源、目的端口
    else if (std::regex_match(filter, std::regex("^ *tcp\\.port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {

        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->tcp.dst;
            uint16_t saved2 = aaa->tcp.src;
            uint16_t trans;
            //使用stringstream 把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans == saved1) || (trans == saved2))
                results.push_back(i);
        }
        return results;
    }

    //UDP目的端口
    else if (std::regex_match(filter, std::regex("^ *udp\\.dst *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->udp.dst;
            uint16_t trans;//把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans == saved)
                results.push_back(i);
        }
        return results;
    }
    //UDP源端口
    else if (std::regex_match(filter, std::regex("^ *udp\\.src *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->udp.src;
            uint16_t trans;//把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans == saved)
                results.push_back(i);
        }
        return results;
    }
    //UDP源、目的端口
    else if (std::regex_match(filter, std::regex("^ *udp\\.port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->udp.dst;
            uint16_t saved2 = aaa->udp.src;
            uint16_t trans;
            //使用stringstream 把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans == saved1) || (trans == saved2))
                results.push_back(i);
        }
        return results;
    }

    //所有端口
    else if (std::regex_match(filter, std::regex("^ *port *== *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->udp.dst;
            uint16_t saved2 = aaa->udp.src;
            uint16_t trans;
            //使用stringstream 把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans == saved1) || (trans == saved2))
                results.push_back(i);
        }
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->tcp.dst;
            uint16_t saved2 = aaa->tcp.src;
            uint16_t trans;
            //使用stringstream 把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans == saved1) || (trans == saved2))
                results.push_back(i);
        }
        return results;
    }

    //长度限制
    //长度==
    else if (std::regex_match(filter, std::regex("^ *len *== *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved == trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *== *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.arp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved == trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *== *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv4_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved == trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *== *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv6_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved == trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *== *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->tcp.header_len);
            if (saved == trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *== *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->udp.len);
            if (saved == trans)
                results.push_back(i);
        }
        return results;
    }
    //长度>=
    else if (std::regex_match(filter, std::regex("^ *len *>= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved >= trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *>= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.arp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved >= trans)
                results.push_back(count.arp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *>= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv4_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved >= trans)
                results.push_back(count.ipv4_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *>= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv6_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved >= trans)
                results.push_back(count.ipv6_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *>= *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->tcp.header_len);
            if (saved >= trans)
                results.push_back(count.tcp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *>= *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->udp.len);
            if (saved >= trans)
                results.push_back(count.udp_c[i]);
        }
        return results;
    }
    //长度<=
    else if (std::regex_match(filter, std::regex("^ *len *<= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved <= trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *<= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.arp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved <= trans)
                results.push_back(count.arp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *<= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv4_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved <= trans)
                results.push_back(count.ipv4_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *<= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv6_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved <= trans)
                results.push_back(count.ipv6_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *<= *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->tcp.header_len);
            if (saved <= trans)
                results.push_back(count.tcp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *<= *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->udp.len);
            if (saved <= trans)
                results.push_back(count.udp_c[i]);
        }
        return results;
    }
    //长度<
    else if (std::regex_match(filter, std::regex("^ *len *< *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved < trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *< *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.arp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved < trans)
                results.push_back(count.arp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *< *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv4_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved < trans)
                results.push_back(count.ipv4_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *< *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv6_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved < trans)
                results.push_back(count.ipv6_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *< *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->tcp.header_len);
            if (saved < trans)
                results.push_back(count.tcp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *< *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->udp.len);
            if (saved < trans)
                results.push_back(count.udp_c[i]);
        }
        return results;
    }
    //长度>
    else if (std::regex_match(filter, std::regex("^ *len *> *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved > trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *> *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.arp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved > trans)
                results.push_back(count.arp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *> *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv4_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved > trans)
                results.push_back(count.ipv4_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *> *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv6_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved > trans)
                results.push_back(count.ipv6_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *> *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->tcp.header_len);
            if (saved > trans)
                results.push_back(count.tcp_c[i]);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *> *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->udp.len);
            if (saved > trans)
                results.push_back(count.udp_c[i]);
        }
        return results;
    }

    //各种不等关系!=
    else if (std::regex_match(filter, std::regex("^ *ip *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            std::string saved1 = std::regex_replace(aaa->srcIp.toStdString(), _empty, "");
            std::string saved2 = std::regex_replace(aaa->desIp.toStdString(), _empty, "");
            if ((saved1 != set_data) && (saved2 != set_data))
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ip\\.dst *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            std::string saved = std::regex_replace(aaa->desIp.toStdString(), _empty, "");
            if (saved != set_data)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ip\\.src *!= *((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3} *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            std::string saved = std::regex_replace(aaa->srcIp.toStdString(), _empty, "");
            if (saved != set_data)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.dst *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->tcp.dst;
            uint16_t trans;//把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans != saved)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.src *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->tcp.src;
            uint16_t trans;//把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans != saved)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {

        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->tcp.dst;
            uint16_t saved2 = aaa->tcp.src;
            uint16_t trans;
            //使用stringstream 把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans != saved1) && (trans != saved2))
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.dst *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->udp.dst;
            uint16_t trans;//把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans != saved)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.src *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved = aaa->udp.src;
            uint16_t trans;//把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if (trans != saved)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->udp.dst;
            uint16_t saved2 = aaa->udp.src;
            uint16_t trans;
            //使用stringstream 把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans != saved1) && (trans != saved2))
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *port *!= *((6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])|[0-5]?\\d{0,4}) *$")))
    {
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->udp.dst;
            uint16_t saved2 = aaa->udp.src;
            uint16_t trans;
            //使用stringstream 把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans != saved1) && (trans != saved2))
                results.push_back(i);
        }
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            uint16_t saved1 = aaa->tcp.dst;
            uint16_t saved2 = aaa->tcp.src;
            uint16_t trans;
            //使用stringstream 把set_data 转成uint16_t
            std::stringstream stream(set_data);
            stream >> trans;
            if ((trans != saved1) && (trans != saved2))
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *len *!= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->packets->size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved != trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *arp\\.len *!= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.arp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved != trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv4\\.len *!= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv4_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved != trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *ipv6\\.len *!= *[1-9][0-9]* *$")))
    {
        for (int i = 0;i < this->count.ipv6_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = aaa->len.toInt();
            int trans = std::stoi(set_data.c_str());
            if (saved != trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *tcp\\.len *!= *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.tcp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->tcp.header_len);
            if (saved != trans)
                results.push_back(i);
        }
        return results;
    }
    else if (std::regex_match(filter, std::regex("^ *udp\\.len *!= *[1-9][0-9]* *$")))
    {
        int trans = std::stoi(set_data, 0, 10);
        for (int i = 0;i < this->count.udp_c.size();i++)
        {
            analysis* aaa = new analysis(this->packets->at(i));
            int saved = int(aaa->udp.len);
            if (saved != trans)
                results.push_back(i);
        }
        return results;
    }
    else
    {
        //改一下，返回空vector
        std::vector<int> not_found;
        return not_found;
    }
}

//分割and语句
std::vector<std::string> MainWindow::split_and(std::string filter)
{
    std::vector <std::string>filt;
    std::sregex_token_iterator beg(filter.begin(), filter.end(), _and, -1);
    std::sregex_token_iterator end; //结束标志
    for (; beg != end; beg++)
    {
        filt.push_back(beg->str());
    }
    return filt;
}

//分割or语句
std::vector<std::string> MainWindow::split_or(std::string filter)
{
    std::vector <std::string>fff;
    std::sregex_token_iterator beg(filter.begin(), filter.end(), _or, -1);
    std::sregex_token_iterator end; //结束标志
    for (; beg != end; beg++)
    {
        fff.push_back(beg->str());
    }
    return fff;
}

//求并集
std::vector<int> MainWindow::complex_or(std::vector<std::vector<int>>temp)
{
    std::vector<int> results;
    std::vector<int> to_delete;

    for (int i = 0;i < temp.size();i++)
        if (temp[i].size() == 0)
            to_delete.push_back(i);
    //删除空的索引组
    if (to_delete.size() != 0)
    {
        for (int i = 0;i < to_delete.size();i++)
            temp.push_back(temp[to_delete[i]]);
    }
    //如果temp还有东西，说明过滤出东西来了
    //用第一个索引组初始化
    if (temp.size() != 0)
    {
        for (int i = 0;i < temp[0].size();i++)
            results.push_back(temp[0][i]);
    }
    else return results;//返回一个空索引
    //对temp中逐一判断：
    //第i个索引组里的第j个元素 是否 在results中
    for (int i = 1;i < temp.size();i++)
    {
        for (int j = 0;j < temp[i].size();j++)
        {
            bool exits = false;//标志某索引不在results中	
            for (int x = 0;x < results.size();x++)
            {
                if (temp[i][j] == results[x])
                {
                    exits = true;//已经存在索引
                    break;
                }
            }
            if (!exits)
            {
                results.push_back(temp[i][j]);
            }
            //不存在索引，就将这个索引存入results
        }
    }
    return results;
}

//求交集
std::vector<int> MainWindow::complex_and(std::vector<std::vector<int>>temp)
{
    std::vector<int> results;
    std::vector<int> to_delete;
    for (int i = 0;i < temp.size();i++)
        if (temp[i].size() == 0)
            to_delete.push_back(i);
    //删除空的索引组
    if (to_delete.size() != 0)
    {
        for (int i = 0;i < to_delete.size();i++)
            temp.push_back(temp[to_delete[i]]);
    }
    //如果temp还有东西，说明过滤出东西来了
    //过滤结果为空，返回一个空索引
    if (temp.size() == 0)return results;

    int min_length = temp[0].size();//索引长度最小值的初始化
    int min_index = 0;//最小索引组的位置
    int pass = 0;//交集元素个数
    int deleted = 0;//不符合条件的个数
    //找出索引最少的组
    for (int i = 1;i < temp.size();i++)
        if (temp[i].size() < min_length)
        {
            min_length = temp[i].size();
            min_index = i;
        }
    for (int x = 0;x < min_length;x++)
    {
        bool exist = false;
        for (int y = 0;y < temp.size();y++)
        {
            if (y == min_index)continue;//跳过最少的那个组
            exist = false;
            //逐一判断，是否为其他索引组的交集元素
            for (int z = 0;z < temp[y].size();z++)
            {
                if (temp[min_index][x] == temp[y][z])
                {
                    exist = true;
                    //是该索引组的交集元素
                    break;
                }
            }
        }
        //判断temp[min_index][x]是否为所有组的交集元素
        if (exist)
        {
            results.push_back(temp[min_index][x]);
            pass++;
        }
        else deleted++;

        if (pass + deleted >= min_length)break;
        //temp[min_index]中的元素都符合/都不符合
    }
    return results;
}

//求补集
std::vector<int> MainWindow::fixed_result(std::vector<int>temp)
{
    std::vector<int> results;
    bool exist = false;
    for (int i = 0;i < this->packets->size();i++)
    {
        exist = false;
        for (int j = 0;j < temp.size();j++)
            if (i == temp[j])
            {
                exist = true;
                break;
            }
        if (!exist)results.push_back(i);
    }
    return results;
}
/*----END-------------------------------------------------------------------------------------*/