#include "mainwindow.h"
#include "./ui_mainwindow.h"

void MainWindow::addRow(int i){
    
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

void MainWindow::showDetails(int i){

    if(i>=this->packets->size()){
        return;
    }

    QStandardItemModel* model = new QStandardItemModel(ui->treeView);

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
        QString arp_type;
        arp_d->appendRow(new QStandardItem("类型: "));
        arp_d->appendRow(new QStandardItem("hardware: "+QString::asprintf("%d",(int)ana->arp.hardware_type)));

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
    this->packets = new std::vector< std::vector<std::any> >();
    this->model = new QStandardItemModel(this);

    model->setHorizontalHeaderLabels(QStringList()<<"序号"<<"时间"<<"协议"<<"源ip"<<"目的ip"<<"长度");
    ui->tableView->setModel(this->model);
    ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    connect(ui->comboBox, &QComboBox::currentIndexChanged, this, [this]() {
        this->device_choose = (uint)ui->comboBox->currentIndex();
    });

    //最顶部的那个label和button是用来测试输出的，到时候再删掉
    connect(ui->pushButton_text, &QPushButton::clicked, this, [=]() {
        ui->label_text->setText(x[this->device_choose]);
    });

    //点击查看包详细内容
    connect(ui->tableView, &QTableView::clicked, this, [this](){
        int row = ui-> tableView ->currentIndex().row();
        QModelIndex index1 = this->model->index(row, 0);
        QString id = this->model->data(index1).toString();
        int i = id.toInt();
        this->showDetails(i-1);
        ui->label_text->setText(id);
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
            //处理以太帧...
            //  //第一项肯定是以太头
        } else {
            
        }
    });
    //开启线程
    connect(ui->pushButton_2, &QPushButton::clicked, this, [=, devices = std::move(devices)]()mutable {
        this->dev = new device(devices.open(this->device_choose));
        this->dev->start_capture();
        timer->start(50);
    });

    connect(ui->pushButton, &QPushButton::clicked, this, [=]() {
        timer->stop();
        this->dev->stop();
        delete this->dev;
    });

}

MainWindow::~MainWindow() {
    delete this->packets;
    delete ui;
}
