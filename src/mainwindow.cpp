#include "mainwindow.h"
#include "CustomItemModel.h"
#include "src/ui_mainwindow.h"

#include "charts.h"
#include <QStandardItemModel>
#include <QSystemTrayIcon>
#include <QTimer>
//

// 已有记录，不用更新统计量
// i是packets的索引，从0开始
void MainWindow::pushRow(size_t i) {
    pushRow(i, this->packets[i]);
}

// 界面新增记录展示的核心函数，解析结果传给qt界面
// 包必须和序号一起传过来，因为包没与序号关联。。即无状态。。
// i是packets的索引，从0开始
void MainWindow::pushRow(size_t i, const pack& x) {
    //超过显示最大数目
    if (this->model->rowCount() >= this->MAXSHOW) {
        this->model->removeOneRow();
    }
    auto [src, dst] = [&x]() -> std::pair<QString, QString> {
        if (auto p = x.parsed.get<ipv4_header>()) {
            return {p->srcip(), p->dstip()};
        } else if (auto p = x.parsed.get<ipv6_header>()) {
            return {p->srcip(), p->dstip()};
        } else if (auto p = x.parsed.get<arp_packet>()) {
            return {p->srcip(), p->dstip()};
        }
        return {"unknown", "unknown"};
    }();
    this->model->appendRow({
        QString::number(i + 1),
        x.time_str(),
        x.parsed.highest_proto(),
        src,
        dst,
        x.raw_len(),
    });
}

void MainWindow::showDetails(int i) {
    //     assert (i < this->packets.size())
    auto& pk = this->packets[i];

    ui->data->setText(pk.raw_str());

    QStandardItemModel* model = new QStandardItemModel(ui->treeView);
    ui->treeView->setModel(model);
    this->t_model = model;
    this->hadDetails = true;
    model->setHorizontalHeaderLabels({QString::asprintf("第%d个包", i + 1)});

    {
        QStandardItem* info = new QStandardItem("时间: " + pk.time_str() + " 总长度: " + pk.raw_len() + " 字节");
        model->appendRow(info);
    }
    pk.parsed.traverse([model]<typename T>(const T& p) {
        if constexpr (std::is_same_v<T, eth_header>) {
            QStandardItem* eth_d = new QStandardItem("以太头");
            model->appendRow(eth_d);
            eth_d->appendRow(new QStandardItem("类型: " + p.type_str()));
            eth_d->appendRow(new QStandardItem("源mac: " + p.srcmac()));
            eth_d->appendRow(new QStandardItem("目的mac: " + p.dstmac()));
        } else if constexpr (std::is_same_v<T, arp_packet>) {
            QStandardItem* arp_d = new QStandardItem("ARP包");
            model->appendRow(arp_d);
            arp_d->appendRow(new QStandardItem("类型: " + p.op_str()));
            arp_d->appendRow(new QStandardItem("源ip: " + p.srcip()));
            arp_d->appendRow(new QStandardItem("源mac: " + p.srcmac()));
            arp_d->appendRow(new QStandardItem("目的ip: " + p.dstip()));
            arp_d->appendRow(new QStandardItem("目的mac: " + p.dstmac()));
        } else if constexpr (std::is_same_v<T, ipv4_header>) {
            QStandardItem* ip_d = new QStandardItem("IP包头");
            model->appendRow(ip_d);
            ip_d->appendRow(new QStandardItem("版本: 4"));
            ip_d->appendRow(new QStandardItem("源ip: " + p.srcip()));
            ip_d->appendRow(new QStandardItem("目的ip: " + p.dstip()));
            ip_d->appendRow(new QStandardItem("长度: " + p.len_str()));
            ip_d->appendRow(new QStandardItem("tos: " + p.ds_str()));
            ip_d->appendRow(new QStandardItem("ttl: " + p.ttl_str()));
            ip_d->appendRow(new QStandardItem("id: " + p.id_str()));
            {
                QStandardItem* flag = new QStandardItem("flag");
                ip_d->appendRow(flag);
                flag->appendRow(new QStandardItem("DF: " + p.df_str()));
                flag->appendRow(new QStandardItem("MF: " + p.mf_str()));
                ip_d->appendRow(new QStandardItem("offset: " + p.offset_str()));
            }
            ip_d->appendRow(new QStandardItem("校验和: " + p.checksum_str()));
        } else if constexpr (std::is_same_v<T, ipv6_header>) {
            QStandardItem* ip_d = new QStandardItem("IP包头");
            model->appendRow(ip_d);
            ip_d->appendRow(new QStandardItem("版本: 6"));
            ip_d->appendRow(new QStandardItem("源ip: " + p.srcip()));
            ip_d->appendRow(new QStandardItem("目的ip: " + p.dstip()));
            ip_d->appendRow(new QStandardItem("净荷长度: " + p.payload_len_str()));
            ip_d->appendRow(new QStandardItem("流量类别: " + p.traffic_class_str()));
            ip_d->appendRow(new QStandardItem("流标签: " + p.flow_label_str()));
            ip_d->appendRow(new QStandardItem("下一报头: " + p.next_header_str()));
            ip_d->appendRow(new QStandardItem("跳数限制: " + p.hop_limit_str()));
        } else if constexpr (std::is_same_v<T, icmp_packet>) {
            QStandardItem* icmp_d = new QStandardItem("icmp");
            model->appendRow(icmp_d);
            auto [type_str, code_str] = p.type_code_str();
            icmp_d->appendRow(new QStandardItem("type: " + type_str));
            icmp_d->appendRow(new QStandardItem("code: " + code_str));
            icmp_d->appendRow(new QStandardItem("校验和: " + p.checksum_str()));
        } else if constexpr (std::is_same_v<T, tcp_header>) {
            QStandardItem* tcp_d = new QStandardItem("tcp");
            model->appendRow(tcp_d);
            tcp_d->appendRow(new QStandardItem("首部长度: " + p.header_len_str()));
            tcp_d->appendRow(new QStandardItem("源端口: " + p.src_str()));
            tcp_d->appendRow(new QStandardItem("目的端口: " + p.dst_str()));
            tcp_d->appendRow(new QStandardItem("序列号: " + p.seq_str()));
            tcp_d->appendRow(new QStandardItem("确认号: " + p.ack_str()));
            {
                QStandardItem* flags = new QStandardItem("flags");
                tcp_d->appendRow(flags);
                flags->appendRow(new QStandardItem("fin: " + p.flags.fin_str()));
                flags->appendRow(new QStandardItem("syn: " + p.flags.syn_str()));
                flags->appendRow(new QStandardItem("rst: " + p.flags.rst_str()));
                flags->appendRow(new QStandardItem("psh: " + p.flags.psh_str()));
                flags->appendRow(new QStandardItem("ack: " + p.flags.ack_str()));
                flags->appendRow(new QStandardItem("urg: " + p.flags.urg_str()));
                flags->appendRow(new QStandardItem("ece: " + p.flags.ece_str()));
                flags->appendRow(new QStandardItem("cwr: " + p.flags.cwr_str()));
            }
            tcp_d->appendRow(new QStandardItem("窗口尺寸: " + p.window_size_str()));
            tcp_d->appendRow(new QStandardItem("校验和: " + p.checksum_str()));
            tcp_d->appendRow(new QStandardItem("紧急指针: " + p.urgent_ptr_str()));
        } else if constexpr (std::is_same_v<T, udp_header>) {
            QStandardItem* udp_d = new QStandardItem("udp");
            model->appendRow(udp_d);
            udp_d->appendRow(new QStandardItem("源端口: " + p.src_str()));
            udp_d->appendRow(new QStandardItem("目的端口: " + p.dst_str()));
            udp_d->appendRow(new QStandardItem("长度: " + p.len_str()));
            udp_d->appendRow(new QStandardItem("校验和: " + p.checksum_str()));
        } else if constexpr (std::is_same_v<T, dns_packet>) {
            QStandardItem* dns_d = new QStandardItem("dns");
            model->appendRow(dns_d);
            dns_d->appendRow(new QStandardItem("事物id: " + p.id_str()));
            dns_d->appendRow(new QStandardItem("问题计数: " + p.questions_str()));
            dns_d->appendRow(new QStandardItem("回答资源记录数: " + p.answer_rrs_str()));
            dns_d->appendRow(new QStandardItem("权威名称服务器计数: " + p.authority_rrs_str()));
            dns_d->appendRow(new QStandardItem("附加资源记录数: " + p.additional_rrs_str()));
            {
                QStandardItem* flags = new QStandardItem("flags");
                dns_d->appendRow(flags);
                flags->appendRow(new QStandardItem("QR: " + p.flags.qr_str()));
                flags->appendRow(new QStandardItem("opcode: " + p.flags.opcode_str()));
                flags->appendRow(new QStandardItem("AA: " + p.flags.aa_str()));
                flags->appendRow(new QStandardItem("TC: " + p.flags.tc_str()));
                flags->appendRow(new QStandardItem("RD: " + p.flags.rd_str()));
                flags->appendRow(new QStandardItem("RA: " + p.flags.ra_str()));
                flags->appendRow(new QStandardItem("rcode: " + p.flags.rcode_str()));
            }
        } else {
            static_assert(std::is_same_v<T, blob>);
            // todo blob?
        }
    });
}

// 太长了。。化简todo
// 界面初始值交给qt desinger
MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow()),
      textEdit(new QLabel(this)),
      time_record(QDateTime::fromSecsSinceEpoch(0)) {
    ui->setupUi(this);
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
    this->model = new CustomItemModel(this, {"序号", "时间", "协议", "源ip", "目的ip", "长度"});

    ui->tableView->setModel(this->model);
    ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    // 下拉列表选择网卡时触发回调
    connect(ui->comboBox, &QComboBox::currentIndexChanged, this, [this]() {
        this->device_choose = (uint)ui->comboBox->currentIndex();
    });

    //点击查看包详细内容
    connect(ui->tableView, &QTableView::clicked, this, [this](const QModelIndex& index) {
        QModelIndex index1 = this->model->index(index.row(), 0);
        QString id = this->model->data(index1).toString();
        this->showDetails(id.toInt() - 1);
    });

    // this->catch_filt = "";
    // this->show_filt = "";
    // this->catch_f = false;
    // this->show_f = false;

    // 布局变化
    // connect(ui->radioButton, &QRadioButton::toggled, this, [this](bool checked) {
    //     if (checked)
    //         ui->radioButton->setText("显示过滤");
    //     else
    //         ui->radioButton->setText("捕获过滤");
    // });

    //     //显示过滤器
    //     //todo 开一个函数吧
    //     connect(ui->lineEdit, &QLineEdit::returnPressed, this, [this]() {
    //         if (ui->radioButton->isChecked()) {
    //             if (!this->stop)
    //                 return;
    //             if (this->hadClear)
    //                 return;
    //             this->model->clear();
    //             //自定义了
    //             // this->model->setHorizontalHeaderLabels({
    //             //     "序号",
    //             //     "时间",
    //             //     "协议",
    //             //     "源ip",
    //             //     "目的ip",
    //             //     "长度",
    //             // });
    //             ui->data->clear();
    //             if (this->hadDetails) {
    //                 this->t_model->clear();
    //             }
    //             this->hadDetails = false;
    //             this->show_filt = ui->lineEdit->text();
    //             this->show_f = true;

    //             // 清除过滤
    //             if (this->show_filt.trimmed().isEmpty()) {
    //                 this->catch_f = false;
    //                 this->catch_filt = "";
    //                 this->show_f = false;
    //                 this->show_filt = "";
    //                 ui->lineEdit->clear();

    //                 // 显示最后MAXSHOW个包
    //                 if (this->packets.size() > 0) {
    //                     for (int i = std::max((int)this->packets.size() - this->MAXSHOW, 0); i < this->packets.size(); i++) {
    //                         pushRow(i);
    //                     }
    //                     int max = this->packets.size() / this->MAXSHOW;
    //                     max += this->packets.size() % this->MAXSHOW ? 1 : 0;

    //                     ui->spinBox->setRange(1, max);
    //                     ui->spinBox->setValue(max);
    //                     ui->label_2->setText(QString::asprintf("共%d页", max));
    //                 }
    //                 return;
    //             }

    //             // //-------------------这里开始 hh
    //             // if (is_a_sentence(this->show_filt)) { //判断语法
    //             //     show_result = catched_filter(this->show_filt.toStdString());
    //             //     if (show_result.size() != 0) {
    //             //         for (int i = 0; i < show_result.size(); i++)
    //             //             pushRow(show_result[i]);
    //             //         int max = show_result.size() / this->MAXSHOW;
    //             //         max += show_result.size() % this->MAXSHOW ? 1 : 0;

    //             //         ui->spinBox->setRange(1, max);
    //             //         ui->spinBox->setValue(max);
    //             //         ui->label_2->setText(QString::asprintf("共%d页", max));
    //             //     } else {
    //             //         //过滤结果为空
    //             //         QMessageBox::warning(this, "显示过滤", "找不到符合过滤条件的数据包。");
    //             //     }
    //             // } else {
    //             //     //报错：语法错误
    //             //     QMessageBox::critical(this, "显示过滤", "请输入正确的过滤表达式。");
    //             // }
    //         } else {
    //             this->catch_f = true;
    //             this->catch_filt = ui->lineEdit->text();
    //         }
    //     });

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

    //     //开启线程
    //  todo 开成员函数
    //     connect(ui->pushButton_2, &QPushButton::clicked, this, [this, timer]() {
    //         if (!this->stop)
    //             return;
    //         // 因为pcap的保存文件api没有追加功能，所以必须先清空。
    //         // 取消暂停功能
    //         ui->pushButton_5->click();
    //         try {
    //             if (this->device_choose < devices.size()) {
    //                 this->dev = std::make_unique<device>(devices.open(this->device_choose));
    //             } else { //fq
    //                 this->dev = std::make_unique<device>(open_file(this->fileName));
    //             }
    //             if (this->catch_f) {
    //                 this->dev->set_filter(this->catch_filt.toStdString());
    //             }
    //             this->dev->start_capture();
    //             this->stop = false;
    //             ui->radioButton->setChecked(true);
    //             timer->start(0);
    //             this->hadClear = false;
    //         } catch (std::exception& e) {
    //             QMessageBox::critical(this, "打开失败", QString(e.what()));
    //         }
    //     });

    //     //结束抓包
    //  todo 开成员函数
    //     connect(ui->pushButton, &QPushButton::clicked, this, [this, timer]() {
    //         if (!this->stop) {
    //             this->stop = true;
    //             this->dev->stop();
    //             timer->stop();
    //             timerUpdate();
    //             countUpdate(std::any_cast<const simple_info&>(packets[packets.size() - 1][0]).t);

    //             int max = this->packets.size() / this->MAXSHOW;
    //             max += this->packets.size() % this->MAXSHOW ? 1 : 0;

    //             ui->spinBox->setRange(1, max);
    //             ui->label_2->setText(QString::asprintf("共%d页", max));
    //         }
    //     });

    //跳转
    connect(ui->pushButton_10, &QPushButton::clicked, this, [this]() {
        // if (!this->stop || this->hadClear)
        //     return;
        this->model->clear();
        // custom model不用重新setHorizontalHeaderLabels
        // for (int i = (ui->spinBox->value() - 1) * this->MAXSHOW; i < ui->spinBox->value() * this->MAXSHOW; i++) {
        //     if (i < this->packets.size()) {
        //         if (this->show_f) {
        //             if (i < show_result.size())
        //                 this->pushRow(show_result[i]);
        //         } else {
        //             this->pushRow(i);
        //         }
        //     }
        // }
        size_t begin = (ui->spinBox->value() - 1) * this->MAXSHOW;
        size_t end = std::min(ui->spinBox->value() * this->MAXSHOW, packets.size());
        for (size_t i = begin; i < end; ++i) {
            this->pushRow(i);
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
            this->time_record = QDateTime::fromSecsSinceEpoch(0);
            this->packets.clear();
            this->model->clear();
            // custom model不用重新setHorizontalHeaderLabels

            this->count.clear();
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

// idx是数组索引，从0开始
void MainWindow::updStat(size_t idx, const pack& x) {
    // 更新count
    x.parsed.traverse([this, idx, depth = 0]<typename T>(const T& proto) mutable {
        ++depth;
        if constexpr (std::is_same_v<T, eth_header>) {
            ; //none
        } else if constexpr (std::is_same_v<T, arp_packet>) {
            this->count.arp_c.push_back(idx);
        } else if constexpr (std::is_same_v<T, ipv4_header>) {
            this->count.ipv4_c.push_back(idx);
        } else if constexpr (std::is_same_v<T, ipv6_header>) {
            this->count.ipv6_c.push_back(idx);
        } else if constexpr (std::is_same_v<T, icmp_packet>) {
            this->count.icmp_c.push_back(idx);
        } else if constexpr (std::is_same_v<T, tcp_header>) {
            this->count.tcp_c.push_back(idx);
        } else if constexpr (std::is_same_v<T, udp_header>) {
            this->count.udp_c.push_back(idx);
        } else if constexpr (std::is_same_v<T, dns_packet>) {
            this->count.dns_c.push_back(idx);
        } else {
            static_assert(std::is_same_v<T, blob>);
            if (depth == 2)
                this->count.other_c.push_back(idx);
            else if (depth == 3)
                this->count.other_header_c.push_back(idx);
            else if (depth == 4)
                this->count.other_app_c.push_back(idx);
        }
    });

    // 更新count_t
    auto& t = x.time;
    if (this->time_record.addSecs(SAMPLE_INTERVAL) < t) {
        mkSample(t);
        this->time_record = t;
    }
}

// 对统计数据抽个样，标记为在t时刻的数据
void MainWindow::mkSample(QDateTime t) {
    Count_time c_t;
    c_t.time = std::move(t);
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

    this->count_t.push_back(std::move(c_t));
}

void MainWindow::timerUpdate() {
    auto tmp_packs = this->dev->get_all();
    if (tmp_packs.empty()) return;

    for (auto& pkt: tmp_packs) { // 处理info...
        updStat(packets.size(), pkt);

        uint oldmax = ui->spinBox->maximum();

        // 更新分页数目=上取整(所有捕获/单位页展示)。上取整公式有-1，新增此包后size+1，抵消为0
        uint newmax = uint((this->packets.size() + this->MAXSHOW) / this->MAXSHOW);
        setMaxPage(newmax); // setmaxpage必须在setvalue前

        if (ui->spinBox->value() == oldmax) {
            if (ui->radioButton_2->isChecked()) { // trace
                ui->spinBox->setValue(newmax);    // 设置value不会有动作，只有按钮才会触发
                pushRow(packets.size(), pkt);
            } else { // not trace
                pushRow(packets.size(), pkt);
            }
        }

        this->packets.push_back(std::move(pkt));
    }

    if (ui->spinBox->value() == ui->spinBox->maximum()) {
        if (ui->radioButton_2->isChecked()) // trace
            ui->tableView->scrollToBottom();
    }

    this->textEdit->setText(QString::asprintf(
        "  ipv4: %zu  ipv6: %zu  arp: %zu  other %zu || icmp: %zu  tcp: %zu  udp %zu  other %zu || dns: %zu  other: %zu",
        this->count.ipv4_c.size(), this->count.ipv6_c.size(), this->count.arp_c.size(), this->count.other_c.size(),
        this->count.icmp_c.size(), this->count.tcp_c.size(), this->count.udp_c.size(), this->count.other_header_c.size(),
        this->count.dns_c.size(), this->count.other_app_c.size()));
}

void MainWindow::setMaxPage(uint m) {
    ui->spinBox->setMaximum(m);
    ui->label_2->setText(QString::asprintf("共%u页", m));
}

MainWindow::~MainWindow() {
    delete ui;
}
