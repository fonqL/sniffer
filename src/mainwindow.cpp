#include "mainwindow.h"
#include "CustomItemModel.h"
#include "src/ui_mainwindow.h"

#include "charts.h"
#include <QStandardItemModel>
#include <QSystemTrayIcon>
#include <QTimer>
//

// 已有记录，不用更新统计量
// i是底层packets的索引，从0开始
void MainWindow::pushRow(size_t i) {
    pushRow(i, this->packets[i]);
}

// 界面新增记录展示的核心函数，解析结果传给qt界面
// 包必须和序号一起传过来，因为包没与序号关联。。即无状态。。
// i是底层packets的索引，从0开始
void MainWindow::pushRow(size_t i, const pack& x) {
    //超过显示最大数目
    if (this->model->rowCount() >= MAXSHOW) {
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
        x.raw_len(),
        src,
        dst,
    });
}

// i是底层packets的索引，从0开始
void MainWindow::showDetails(int i) {
    auto& pk = this->packets[i];

    ui->data->setText(pk.raw_str());

    tr_model->setHorizontalHeaderLabels({QString::asprintf("第%d个包", i + 1)});

    {
        QStandardItem* info = new QStandardItem("时间: " + pk.time_str() + " 总长度: " + pk.raw_len() + " 字节");
        tr_model->appendRow(info);
    }
    pk.parsed.traverse([tr_model = tr_model]<typename T>(const T& p) {
        if constexpr (std::is_same_v<T, eth_header>) {
            QStandardItem* eth_d = new QStandardItem("以太头");
            tr_model->appendRow(eth_d);
            eth_d->appendRow(new QStandardItem("类型: " + p.type_str()));
            eth_d->appendRow(new QStandardItem("源mac: " + p.srcmac()));
            eth_d->appendRow(new QStandardItem("目的mac: " + p.dstmac()));
        } else if constexpr (std::is_same_v<T, arp_packet>) {
            QStandardItem* arp_d = new QStandardItem("ARP包");
            tr_model->appendRow(arp_d);
            arp_d->appendRow(new QStandardItem("类型: " + p.op_str()));
            arp_d->appendRow(new QStandardItem("源ip: " + p.srcip()));
            arp_d->appendRow(new QStandardItem("源mac: " + p.srcmac()));
            arp_d->appendRow(new QStandardItem("目的ip: " + p.dstip()));
            arp_d->appendRow(new QStandardItem("目的mac: " + p.dstmac()));
        } else if constexpr (std::is_same_v<T, ipv4_header>) {
            QStandardItem* ip_d = new QStandardItem("IP包头");
            tr_model->appendRow(ip_d);
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
            tr_model->appendRow(ip_d);
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
            tr_model->appendRow(icmp_d);
            auto [type_str, code_str] = p.type_code_str();
            icmp_d->appendRow(new QStandardItem("type: " + type_str));
            icmp_d->appendRow(new QStandardItem("code: " + code_str));
            icmp_d->appendRow(new QStandardItem("校验和: " + p.checksum_str()));
        } else if constexpr (std::is_same_v<T, tcp_header>) {
            QStandardItem* tcp_d = new QStandardItem("tcp");
            tr_model->appendRow(tcp_d);
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
            tr_model->appendRow(udp_d);
            udp_d->appendRow(new QStandardItem("源端口: " + p.src_str()));
            udp_d->appendRow(new QStandardItem("目的端口: " + p.dst_str()));
            udp_d->appendRow(new QStandardItem("长度: " + p.len_str()));
            udp_d->appendRow(new QStandardItem("校验和: " + p.checksum_str()));
        } else if constexpr (std::is_same_v<T, dns_packet>) {
            QStandardItem* dns_d = new QStandardItem("dns");
            tr_model->appendRow(dns_d);
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

// 界面初始值交给qt desinger，也有交不了的在这初始化
MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow()),
      textEdit(new QLabel(this)),
      device_choose(0),
      timer(new QTimer(this)),
      time_record(QDateTime::fromSecsSinceEpoch(0)),
      model(new CustomItemModel(this, {"序号", "时间", "协议", "长度", "源ip", "目的ip"})),
      tr_model(new QStandardItemModel(this)),
      show_filter(std::make_unique<ExprAST>()) {
    ui->setupUi(this);
    ui->tableView->setModel(this->model);
    ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    ui->tableView->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setStretchLastSection(true);
    ui->treeView->setModel(tr_model);
    this->statusBar()->addWidget(textEdit);

    // 显示网卡
    for (auto& item: devices.to_strings()) {
        ui->comboBox->addItem(item);
    }

    // 下拉列表选择网卡时触发回调
    connect(ui->comboBox, &QComboBox::currentIndexChanged, [this]() {
        this->device_choose = (uint)ui->comboBox->currentIndex();
    });

    //点击查看包详细内容
    connect(ui->tableView, &QTableView::clicked, [this](const QModelIndex& index) {
        QModelIndex index1 = this->model->index(index.row(), 0);
        auto id = this->model->data(index1).toUInt();
        this->showDetails(id - 1);
    });

    // 捕获过滤
    connect(ui->lineEdit, &QLineEdit::textEdited, [this]() {
        catch_filter = ui->lineEdit->text();
    });

    // 显示过滤，实时语法检查
    connect(ui->lineEdit_2, &QLineEdit::textEdited, [this] {
        // 抛弃临时编译结果，敲回车应用时才/再使用，反正响应够快。
        if (compile(ui->lineEdit_2->text()) != nullptr)
            ui->lineEdit_2->setStyleSheet("background-color:rgba(0,255,0,150)");
        else
            ui->lineEdit_2->setStyleSheet("background-color:rgba(255,0,0,150)");
    });

    // 应用显示过滤
    // 得益于单线程，这里任意操作都不会出冲突
    connect(ui->lineEdit_2, &QLineEdit::returnPressed, [this] {
        auto res = compile(ui->lineEdit_2->text());
        if (res == nullptr) return;
        show_filter = std::move(res);
        ui->lineEdit_2->setStyleSheet("background-color:rgba(255,255,255,255)");
        this->model->clear();
        this->shows.clear();
        for (size_t i = 0; i < packets.size(); ++i) {
            if (show_filter->check(packets[i].parsed))
                this->shows.push_back(i);
        }
        uint newmax = uint((shows.size() + MAXSHOW - 1) / MAXSHOW);
        setMaxPage(newmax);
        if (shows.empty())
            return;
        ui->spinBox->setValue(newmax);
        jump();
        ui->tableView->scrollToBottom();
    });

    //保存 fq
    connect(ui->pushButton_8, &QPushButton::clicked, this, [this]() {
        QString dest_path = QFileDialog::getSaveFileName(this, "保存文件", QDir::homePath() + "/Desktop", "Mycap Files(*.mycap)");
        if (dest_path.isNull()) return;
        if (QFile::exists(dest_path)) {
            bool e = QFile::remove(dest_path);
            if (!e) QMessageBox::critical(this, "保存文件", "失败: QFile::remove");
        }
        bool e = QFile::copy(DEFAULT_FILENAME, dest_path);
        if (!e) QMessageBox::critical(this, "保存文件", "失败: QFile::copy");
    });

    //打开  fq
    connect(ui->pushButton_9, &QPushButton::clicked, this, [this]() {
        this->fileName = QFileDialog::getOpenFileName(this, "打开文件", QDir::homePath() + "/Desktop", "Mycap Files(*.mycap)");
        if (this->fileName.isNull()) return;
        ui->comboBox->addItem(this->fileName);
        ui->comboBox->setCurrentIndex(ui->comboBox->count() - 1);
    });

    connect(timer, &QTimer::timeout, this, &MainWindow::capture);

    connect(ui->pushButton_2, &QPushButton::clicked, this, &MainWindow::startCapture);

    connect(ui->pushButton, &QPushButton::clicked, this, &MainWindow::stopCapture);

    //跳转
    connect(ui->pushButton_10, &QPushButton::clicked, this, &MainWindow::jump);

    //显示统计图
    connect(ui->pushButton_6, &QPushButton::clicked, [this]() {
        charts* ch = new charts(this);
        ch->setCount(this->count_t);
        ch->show();
    });
}

void MainWindow::jump() {
    this->model->clear();
    // custom model不用重新setHorizontalHeaderLabels
    size_t begin = (ui->spinBox->value() - 1) * MAXSHOW;
    size_t end = std::min(ui->spinBox->value() * MAXSHOW, packets.size());
    for (size_t i = begin; i < end; ++i) {
        this->pushRow(shows[i]);
    }
}

// todo 检查shows是否忘记出现
void MainWindow::reset() {
    this->time_record = QDateTime::fromSecsSinceEpoch(0);
    this->shows.clear();
    this->packets.clear();
    this->model->clear();
    // custom model不用重新setHorizontalHeaderLabels

    this->count.clear();
    this->count_t.clear();
    this->textEdit->clear();
    ui->data->clear();
    // todo qt对象好像是有特殊的析构方法？clear应该也可？
    if (tr_model != nullptr)
        this->tr_model->clear();
}

void MainWindow::startCapture() try {
    // 因为pcap的保存文件api没有追加功能，所以必须先清空，不支持暂停功能
    reset();
    if (this->device_choose < devices.size()) {
        this->dev = std::make_unique<device>(devices.open(this->device_choose));
    } else {
        this->dev = std::make_unique<device>(open_file(this->fileName));
    }
    if (!catch_filter.isEmpty()) {
        this->dev->set_filter(this->catch_filter.toStdString());
    }
    ui->pushButton->setEnabled(true);
    ui->pushButton_2->setEnabled(false);
    ui->pushButton_6->setEnabled(false);
    ui->pushButton_8->setEnabled(false);
    ui->pushButton_9->setEnabled(false);
    ui->lineEdit->setEnabled(false);
    this->dev->start_capture();
    this->timer->start(0);
} catch (std::exception& e) {
    QMessageBox::critical(this, "打开失败", QString(e.what()));
}

void MainWindow::stopCapture() {
    ui->pushButton->setEnabled(false);
    ui->pushButton_2->setEnabled(true);
    ui->pushButton_6->setEnabled(true);
    ui->pushButton_8->setEnabled(true);
    ui->pushButton_9->setEnabled(true);
    ui->lineEdit->setEnabled(true);
    this->dev->stop();
    timer->stop();
    // 收集残渣
    capture();
    if (!packets.empty())
        genSample(packets.back().time);
    int max = int((this->packets.size() + MAXSHOW - 1) / MAXSHOW);
    setMaxPage(max);
}

// idx是底层数组索引，从0开始
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
        genSample(t);
        this->time_record = t;
    }
}

// 对统计数据抽个样，标记为在t时刻的数据
void MainWindow::genSample(QDateTime t) {
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

void MainWindow::handleShow(const pack& pkt) {
    shows.push_back(packets.size()); // 预判下标，与capture()其实是耦合的，有点危险

    uint oldmax = ui->spinBox->maximum();

    // 更新分页数目=上取整(所有捕获/单位页展示)。上取整公式有-1，新增此包后size+1，抵消为0
    uint newmax = uint((this->packets.size() + MAXSHOW) / MAXSHOW);
    setMaxPage(newmax); // setmaxpage必须在setvalue前

    if (ui->spinBox->value() == oldmax) {
        if (ui->radioButton_2->isChecked()) { // trace
            ui->spinBox->setValue(newmax);    // 设置value不会有动作，只有按钮才会触发
            pushRow(packets.size(), pkt);
        } else { // not trace
            pushRow(packets.size(), pkt);
        }
    }
}

void MainWindow::capture() {
    auto tmp_packs = this->dev->get_all();
    if (tmp_packs.empty()) return;

    for (auto& pkt: tmp_packs) { // 处理info...
        updStat(packets.size(), pkt);
        if (show_filter->check(pkt.parsed)) {
            handleShow(pkt);
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

// 可以设置为0，在里面特判
void MainWindow::setMaxPage(uint m) {
    if (m == 0) {
        ui->spinBox->setRange(0, 0);
        ui->label_2->setText("共0页");
    } else {
        ui->spinBox->setRange(1, m);
        ui->label_2->setText(QString::asprintf("共%u页", m));
    }
}

MainWindow::~MainWindow() {
    delete ui;
}
