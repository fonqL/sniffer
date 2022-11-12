#include "mainwindow.h"
#include "./ui_mainwindow.h"

void MainWindow::showRow(int i) {
    analysis ana(this->packets.at(i));
    showRow(i, ana);
}

void MainWindow::showRow(int i, const analysis& ana) {
    if (this->model->rowCount() > (this->MAXSHOW - 1)) {
        this->model->removeRow(this->model->rowCount() - this->MAXSHOW);
    }
    this->model->appendRow({
        new QStandardItem(QString::number(i + 1)),
        new QStandardItem(ana.time),
        new QStandardItem(ana.header),
        new QStandardItem(ana.srcIp),
        new QStandardItem(ana.desIp),
        new QStandardItem(ana.len),
        // new QStandardItem()
    });
}

void MainWindow::addRow(int i) {
    analysis ana(this->packets.at(i));
    if (ana.type == "IPv4") {
        this->count.ipv4_c.push_back(i);
    } else if (ana.type == "IPv6") {
        this->count.ipv6_c.push_back(i);
    } else if (ana.type == "ARP") {
        this->count.arp_c.push_back(i);
    } else if (ana.type == "other") {
        this->count.other_c.push_back(i);
    }

    if (ana.header == "icmp") {
        this->count.icmp_c.push_back(i);
    } else if (ana.header == "tcp") {
        this->count.tcp_c.push_back(i);
    } else if (ana.header == "udp") {
        this->count.udp_c.push_back(i);
    } else if (ana.header == "other") {
        this->count.other_header_c.push_back(i);
    }

    if (ana.app == "dns") {
        this->count.dns_c.push_back(i);
    } else if (ana.app == "other") {
        this->count.other_app_c.push_back(i);
    }
    this->showRow(i, ana);
}

void MainWindow::showDetails(int i) {
    if (i >= this->packets.size()) {
        return;
    }

    QStandardItemModel* model = new QStandardItemModel(ui->treeView);

    this->t_model = model;
    this->hadDetails = true;
    model->setHorizontalHeaderLabels(QStringList() << ("第" + QString::number(i + 1) + "个包"));

    QStandardItem* eth_d = new QStandardItem("以太头");
    model->appendRow(eth_d);
    analysis ana(this->packets.at(i));
    eth_d->appendRow(new QStandardItem("类型: " + ana.type));
    eth_d->appendRow(new QStandardItem("源mac: " + ana.srcMac));
    eth_d->appendRow(new QStandardItem("目的mac: " + ana.desMac));
    ui->data->setText(ana.rawdata);

    if (ana.type == "IPv4") {
        QStandardItem* ip_d = new QStandardItem("IP包头");
        model->appendRow(ip_d);
        ip_d->appendRow(new QStandardItem("版本: 4"));
        ip_d->appendRow(new QStandardItem("源ip: " + ana.srcIp));
        ip_d->appendRow(new QStandardItem("目的ip: " + ana.desIp));
        ip_d->appendRow(new QStandardItem("长度: " + ana.len));
        ip_d->appendRow(new QStandardItem("tos: " + QString::asprintf("0X%02x", ana.ipv4.ds)));
        ip_d->appendRow(new QStandardItem("ttl: " + QString::asprintf("0X%02x", ana.ipv4.ttl)));
        QStandardItem* flag = new QStandardItem("flag");
        flag->appendRow(new QStandardItem("id: " + QString::asprintf("%d", (int)ana.ipv4.id)));
        flag->appendRow(new QStandardItem("DF: " + QString::asprintf("%d", (int)ana.ipv4.df)));
        flag->appendRow(new QStandardItem("MF: " + QString::asprintf("%d", (int)ana.ipv4.mf)));
        flag->appendRow(new QStandardItem("offset: " + QString::asprintf("%d", (int)ana.ipv4.offset)));
        ip_d->appendRow(flag);

        ip_d->appendRow(new QStandardItem("校验和: " + QString::asprintf("%d", (int)ana.ipv4.checksum)));
    } else if (ana.type == "ARP") {
        QStandardItem* arp_d = new QStandardItem("ARP包");
        model->appendRow(arp_d);
        QString arp_type = "unknown";
        if ((int)ana.arp.op == 1) {
            arp_type = "request";
        } else if ((int)ana.arp.op == 2) {
            arp_type = "reply";
        }
        arp_d->appendRow(new QStandardItem("类型: " + arp_type));

        arp_d->appendRow(new QStandardItem("源ip: " + ana.srcIp));

        char* buf = (char*)malloc(80 * sizeof(char));
        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", ana.arp.src_mac[0], ana.arp.src_mac[1],
                ana.arp.src_mac[2], ana.arp.src_mac[3], ana.arp.src_mac[4], ana.arp.src_mac[5]);
        arp_d->appendRow(new QStandardItem("源mac: " + QString(QLatin1String(buf))));

        arp_d->appendRow(new QStandardItem("目的ip: " + ana.desIp));

        buf = (char*)malloc(80 * sizeof(char));
        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", ana.arp.dst_mac[0], ana.arp.dst_mac[1],
                ana.arp.dst_mac[2], ana.arp.dst_mac[3], ana.arp.dst_mac[4], ana.arp.dst_mac[5]);
        arp_d->appendRow(new QStandardItem("目的mac: " + QString(QLatin1String(buf))));

    } else if (ana.type == "IPv6") {
        QStandardItem* ip_d = new QStandardItem("IP包头");
        model->appendRow(ip_d);
        ip_d->appendRow(new QStandardItem("版本: 6"));
        ip_d->appendRow(new QStandardItem("源ip: " + ana.srcIp));
        ip_d->appendRow(new QStandardItem("目的ip: " + ana.desIp));
        ip_d->appendRow(new QStandardItem("净荷长度: " + ana.len));
        ip_d->appendRow(new QStandardItem("流量类别: " + QString::asprintf("0X%x", ana.ipv6.traffic_class)));
        ip_d->appendRow(new QStandardItem("流标签: " + QString::asprintf("0X%x", ana.ipv6.flow_label)));
        ip_d->appendRow(new QStandardItem("下一报头: " + QString::asprintf("0X%x", ana.ipv6.next_header)));
        ip_d->appendRow(new QStandardItem("跳数限制: " + QString::asprintf("%u", ana.ipv6.hop_limit)));
    }

    if (ana.header == "icmp") {
        QStandardItem* icmp_d = new QStandardItem("icmp");
        model->appendRow(icmp_d);

        int type = (int)ana.icmp.type, code = (int)ana.icmp.code;
        QString msg = "";

        if (type == 0 && code == 0) {
            msg = "回应应答";
        } else if (type == 3 && code == 0) {
            msg = "网络不可达";
        } else if (type == 3 && code == 1) {
            msg = "主机不可达";
        } else if (type == 5 && code == 1) {
            msg = "为主机重定向数据包";
        } else if (type == 8 && code == 0) {
            msg = "回应";
        } else if (type == 11 && code == 0) {
            msg = "超时";
        } else {
            msg = "其他";
        }

        icmp_d->appendRow(new QStandardItem("type: " + QString::asprintf("%d", type)));
        icmp_d->appendRow(new QStandardItem("code: " + QString::asprintf("%d", code)));
        icmp_d->appendRow(new QStandardItem("校验和: " + QString::asprintf("%d", (int)ana.icmp.checksum)));
        icmp_d->appendRow(new QStandardItem("含义: " + msg));
    } else if (ana.header == "tcp") {
        QStandardItem* tcp_d = new QStandardItem("tcp");
        model->appendRow(tcp_d);
        tcp_d->appendRow(new QStandardItem("长度: " + QString::asprintf("%d", ana.tcp.header_len)));
        tcp_d->appendRow(new QStandardItem("源端口: " + QString::asprintf("%d", ana.tcp.src)));
        tcp_d->appendRow(new QStandardItem("目的端口: " + QString::asprintf("%d", ana.tcp.dst)));
        tcp_d->appendRow(new QStandardItem(
            QString::asprintf("seq: 0x%x  ack: 0x%x", ana.tcp.seq, ana.tcp.ack)));
        QStandardItem* flags = new QStandardItem("flags");
        tcp_d->appendRow(flags);
        flags->appendRow(new QStandardItem("fin: " + QString::asprintf("%d", ana.tcp.flags.fin)));
        flags->appendRow(new QStandardItem("syn: " + QString::asprintf("%d", ana.tcp.flags.syn)));
        flags->appendRow(new QStandardItem("rst: " + QString::asprintf("%d", ana.tcp.flags.rst)));
        flags->appendRow(new QStandardItem("psh: " + QString::asprintf("%d", ana.tcp.flags.psh)));
        flags->appendRow(new QStandardItem("ack: " + QString::asprintf("%d", ana.tcp.flags.ack)));
        flags->appendRow(new QStandardItem("urg: " + QString::asprintf("%d", ana.tcp.flags.urg)));
        flags->appendRow(new QStandardItem("ece: " + QString::asprintf("%d", ana.tcp.flags.ece)));
        flags->appendRow(new QStandardItem("cwr: " + QString::asprintf("%d", ana.tcp.flags.cwr)));

        tcp_d->appendRow(new QStandardItem("窗口尺寸: " + QString::asprintf("%d", ana.tcp.window_size)));
        tcp_d->appendRow(new QStandardItem("校验和: " + QString::asprintf("%d", ana.tcp.checksum)));
        tcp_d->appendRow(new QStandardItem("紧急指针: " + QString::asprintf("%d", ana.tcp.urgent_ptr)));
    } else if (ana.header == "udp") {
        QStandardItem* udp_d = new QStandardItem("udp");
        model->appendRow(udp_d);
        udp_d->appendRow(new QStandardItem("源端口: " + QString::asprintf("%d", ana.udp.src)));
        udp_d->appendRow(new QStandardItem("目的端口: " + QString::asprintf("%d", ana.udp.dst)));
        udp_d->appendRow(new QStandardItem("长度: " + QString::asprintf("%d", ana.udp.len)));
        udp_d->appendRow(new QStandardItem("校验和: " + QString::asprintf("%d", ana.udp.checksum)));
    }

    if (ana.app == "dns") {
        QStandardItem* dns_d = new QStandardItem("dns");
        model->appendRow(dns_d);
        dns_d->appendRow(new QStandardItem("事物id: " + QString::asprintf("%d", ana.dns.id)));
        dns_d->appendRow(new QStandardItem("问题计数: " + QString::asprintf("%d", ana.dns.questions)));
        dns_d->appendRow(new QStandardItem("回答资源记录数: " + QString::asprintf("%d", ana.dns.answer_rrs)));
        dns_d->appendRow(new QStandardItem("权威名称服务器计数: " + QString::asprintf("%d", ana.dns.authority_rrs)));
        dns_d->appendRow(new QStandardItem("附加资源记录数: " + QString::asprintf("%d", ana.dns.additional_rrs)));
        QStandardItem* flags = new QStandardItem("flags");
        dns_d->appendRow(flags);

        QString msg = "";
        if ((int)ana.dns.flags.qr == 0)
            msg = "查询请求";
        else
            msg = "响应";
        flags->appendRow(new QStandardItem("QR: " + QString::asprintf("%d ", ana.dns.flags.qr) + msg));

        if ((int)ana.dns.flags.opcode == 0)
            msg = "标准查询";
        else if ((int)ana.dns.flags.opcode == 1)
            msg = "反向查询";
        else if ((int)ana.dns.flags.opcode == 2)
            msg = "服务器状态请求";
        flags->appendRow(new QStandardItem("opcode: " + QString::asprintf("%d ", ana.dns.flags.opcode) + msg));

        if ((int)ana.dns.flags.aa == 0)
            msg = "非权威服务器";
        else if ((int)ana.dns.flags.aa == 1)
            msg = "权威服务器";
        flags->appendRow(new QStandardItem("AA: " + QString::asprintf("%d ", ana.dns.flags.aa) + msg));

        if ((int)ana.dns.flags.tc == 0)
            msg = "未截断";
        else if ((int)ana.dns.flags.tc == 1)
            msg = "已截断";
        flags->appendRow(new QStandardItem("TC: " + QString::asprintf("%d ", ana.dns.flags.tc) + msg));

        flags->appendRow(new QStandardItem("RD: " + QString::asprintf("%d ", ana.dns.flags.rd)));

        if ((int)ana.dns.flags.ra == 0)
            msg = "不支持递归查询";
        else if ((int)ana.dns.flags.ra == 1)
            msg = "支持递归查询";
        flags->appendRow(new QStandardItem("RA: " + QString::asprintf("%d ", ana.dns.flags.ra) + msg));

        if ((int)ana.dns.flags.rcode == 0)
            msg = "无错误";
        else if ((int)ana.dns.flags.rcode == 1)
            msg = "格式错误";
        else if ((int)ana.dns.flags.rcode == 2)
            msg = "服务器失败";
        else if ((int)ana.dns.flags.rcode == 3)
            msg = "名字错误";
        else if ((int)ana.dns.flags.rcode == 4)
            msg = "类型不支持";
        else if ((int)ana.dns.flags.rcode == 5)
            msg = "拒绝应答";
        flags->appendRow(new QStandardItem("rcode: " + QString::asprintf("%d ", ana.dns.flags.rcode) + msg));
    }

    ui->treeView->setModel(model);
}

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::MainWindow()) {
    ui->setupUi(this);
    textEdit = new QLabel(this);
    this->statusBar()->addWidget(textEdit);
    // 显示网卡
    for (auto& item: devices.to_strings()) {
        ui->comboBox->addItem(item);
    }
    // 选中的下标,做成主页面类的成员变量了,因为lamda表达式传值很麻烦，后面用到也可以用这个办法（引用传值屁用没有
    // 点击开始抓包按钮后可以用这个值
    this->device_choose = 0;
    this->stop = true;
    this->hadClear = true;
    this->hadDetails = false;
    this->model = new QStandardItemModel(this);

    model->setHorizontalHeaderLabels({
        "序号",
        "时间",
        "协议",
        "源ip",
        "目的ip",
        "长度",
    });
    ui->tableView->setModel(this->model);
    ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    this->device_choose = 0;
    connect(ui->comboBox, &QComboBox::currentIndexChanged, this, [this]() {
        this->device_choose = (uint)ui->comboBox->currentIndex();
    });

    //点击查看包详细内容
    connect(ui->tableView, &QTableView::clicked, this, [this](const QModelIndex& index) {
        QModelIndex index1 = this->model->index(index.row(), 0);
        QString id = this->model->data(index1).toString();
        this->showDetails(id.toInt() - 1);
    });

    this->catch_filt = "";
    this->show_filt = "";
    this->catch_f = false;
    this->show_f = false;
    ui->spinBox->setRange(1, 1);

    //原 清除过滤按钮
    auto clearFilter = [this]() {
        this->catch_f = false;
        this->catch_filt = "";
        this->show_f = false;
        this->show_filt = "";
        ui->lineEdit->clear();

        if (this->packets.size() > 0) {
            for (int i = std::max(this->packets.size() - this->MAXSHOW, 0uLL); i < this->packets.size(); i++) {
                showRow(i);
            }
            int max = this->packets.size() / this->MAXSHOW;
            max += this->packets.size() % this->MAXSHOW ? 1 : 0;

            ui->spinBox->setRange(1, max);
            ui->spinBox->setValue(max);
            ui->label_2->setText(QString::asprintf("共%d页", max));
        }
    };

    connect(ui->radioButton, &QRadioButton::toggled, this, [this](bool checked) {
        if (checked)
            ui->radioButton->setText("显示过滤");
        else
            ui->radioButton->setText("捕获过滤");
    });

    //过滤
    connect(ui->lineEdit, &QLineEdit::returnPressed, this, [this, clearFilter = std::move(clearFilter)]() {
        if (ui->radioButton->isChecked()) {
            if (!this->stop)
                return;
            if (this->hadClear)
                return;
            this->model->clear();
            this->model->setHorizontalHeaderLabels({
                "序号",
                "时间",
                "协议",
                "源ip",
                "目的ip",
                "长度",
            });
            ui->data->clear();
            if (this->hadDetails) {
                this->t_model->clear();
            }
            this->hadDetails = false;
            this->show_filt = ui->lineEdit->text();
            this->show_f = true;

            if (this->show_filt.trimmed().isEmpty())
                clearFilter();

            //-------------------这里开始 hh
            if (is_a_sentence(this->show_filt)) { //判断语法
                show_result = catched_filter(this->show_filt.toStdString());
                if (show_result.size() != 0) {
                    for (int i = 0; i < show_result.size(); i++)
                        showRow(show_result[i]);
                    int max = show_result.size() / this->MAXSHOW;
                    max += show_result.size() % this->MAXSHOW ? 1 : 0;

                    ui->spinBox->setRange(1, max);
                    ui->spinBox->setValue(max);
                    ui->label_2->setText(QString::asprintf("共%d页", max));
                } else {
                    //过滤结果为空
                }
            } else {
                //报错：语法错误
            }
        } else {
            this->catch_f = true;
            this->catch_filt = ui->lineEdit->text();
        }
    });

    //保存 fq
    connect(ui->pushButton_8, &QPushButton::clicked, this, [this]() {
        if (this->stop) { //停止抓包后才能保存
            QString dest_path = QFileDialog::getSaveFileName(this, "保存文件", QDir::homePath() + "/Desktop", "Mycap Files(*.mycap)");
            if (dest_path.isNull()) return;
            if (QFile::exists(dest_path)) {
                bool e = QFile::remove(dest_path);
                if (!e) QMessageBox::critical(this, "保存文件", "失败: QFile::remove");
            }
            bool e = QFile::copy(DEFAULT_FILENAME, dest_path);
            if (!e) QMessageBox::critical(this, "保存文件", "失败: QFile::copy");
        }
    });

    //打开  fq
    connect(ui->pushButton_9, &QPushButton::clicked, this, [this]() {
        if (this->hadClear) { //清空抓包界面才能打开
            this->fileName = QFileDialog::getOpenFileName(this, "打开文件", QDir::homePath() + "/Desktop", "Mycap Files(*.mycap)");
            if (this->fileName.isNull()) return;
            ui->comboBox->addItem(this->fileName);
            ui->comboBox->setCurrentIndex(ui->comboBox->count() - 1);
        }
    });

    QTimer* timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &MainWindow::timerUpdate);

    // 用于记录时间下包数量
    QTimer* timer_record = new QTimer(this);
    connect(timer_record, &QTimer::timeout, [this]() {
        if (this->packets.size() > 0) {
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
    connect(ui->pushButton_2, &QPushButton::clicked, this, [this, timer, timer_record]() {
        if (this->stop) {
            ui->radioButton->setChecked(true);
            if (this->device_choose < devices.size()) {
                this->stop = false;
                this->dev = std::make_unique<device>(devices.open(this->device_choose));
                if (this->catch_f) {
                    bool error = this->dev->set_filter(this->catch_filt.toStdString());
                    if (!error) QMessageBox::critical(this, "捕获过滤器", "set_filter错误。请检查过滤器语法");
                }
                this->dev->start_capture();
            } else {
                //fq
                this->stop = false;
                this->dev = std::make_unique<device>(open_file(this->fileName));
                this->dev->start_capture();
            }
            timer->start(100);
            timer_record->start(1000);
            this->hadClear = false;
        }
    });

    //结束抓包
    connect(ui->pushButton, &QPushButton::clicked, this, [this, timer, timer_record]() {
        if (!this->stop) {
            this->stop = true;
            timer->stop();
            timer_record->stop();
            this->dev->stop();
            timerUpdate();
            int max = this->packets.size() / this->MAXSHOW;
            max += this->packets.size() % this->MAXSHOW ? 1 : 0;

            ui->spinBox->setRange(1, max);
            ui->label_2->setText(QString::asprintf("共%d页", max));

            ui->radioButton->setCheckable(false);
        }
    });

    //跳转
    connect(ui->pushButton_10, &QPushButton::clicked, this, [this]() {
        if (this->stop) {
            if (!this->hadClear) {
                this->model->clear();
                model->setHorizontalHeaderLabels({
                    "序号",
                    "时间",
                    "协议",
                    "源ip",
                    "目的ip",
                    "长度",
                });
                for (int i = (ui->spinBox->value() - 1) * this->MAXSHOW; i < ui->spinBox->value() * this->MAXSHOW; i++) {
                    if (i < this->packets.size()) {
                        if (this->show_f) {
                            if (i < show_result.size())
                                this->showRow(show_result[i]);
                        } else {
                            this->showRow(i);
                        }
                    }
                }
            }
        }
    });

    //显示统计图
    connect(ui->pushButton_6, &QPushButton::clicked, this, [this]() {
        if (this->stop) {
            charts* ch = new charts(this);
            ch->setCount(this->count_t);
            ch->show();
        }
    });

    //清空
    connect(ui->pushButton_5, &QPushButton::clicked, this, [this]() {
        if (this->stop && !this->hadClear) {
            this->packets.clear();
            this->model->clear();
            model->setHorizontalHeaderLabels({
                "序号",
                "时间",
                "协议",
                "源ip",
                "目的ip",
                "长度",
            });

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

            this->textEdit->clear();
            ui->data->clear();
            if (this->hadDetails) {
                this->t_model->clear();
            }
            this->hadClear = true;
            this->hadDetails = false;
        }
    });
}

void MainWindow::timerUpdate() {
    auto tmp_packets = this->dev->get_all();
    if (tmp_packets.empty())
        return;
    this->packets.reserve(this->packets.size() + tmp_packets.size());

    for (auto& packet: tmp_packets) { //处理info...
        this->packets.push_back(packet);

        int index = this->packets.size();

        if (true) {
            this->addRow(index - 1);
        }
    }
    ui->tableView->scrollToBottom();

    this->textEdit->setText(QString::asprintf(
        "  ipv4: %d  ipv6: %d  arp: %d  other %d || icmp: %d  tcp: %d  udp %d  other %d || dns: %d  other: %d",
        this->count.ipv4_c.size(), this->count.ipv6_c.size(), this->count.arp_c.size(), this->count.other_c.size(),
        this->count.icmp_c.size(), this->count.tcp_c.size(), this->count.udp_c.size(), this->count.other_header_c.size(),
        this->count.dns_c.size(), this->count.other_app_c.size()));
}

MainWindow::~MainWindow() {
    delete ui;
}
