#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "handle_packet.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    
    ui->setupUi(this);    
    device_list devices;
    auto x = devices.to_strings();   
    // 显示网卡 
    for(uint i = 0; i < x.size(); i++){
        ui->comboBox->addItem(x[i]);
    }
    // 选中的下标,做成主页面类的成员变量了,因为lamda表达式传值很麻烦，后面用到也可以用这个办法（引用传值屁用没有
    // 点击开始抓包按钮后可以用这个值
    this->device_choose = 0;

    connect(ui->comboBox, &QComboBox::currentIndexChanged, this, [this](){
        this->device_choose = (uint) ui->comboBox->currentIndex();
    });

    //最顶部的那个label和button是用来测试输出的，到时候再删掉
    connect(ui->pushButton_text, &QPushButton::clicked, this, [=](){
        ui->label_text->setText(x[this->device_choose]);
    });

    //开启线程
    connect(ui->pushButton_2, &QPushButton::clicked, this, [&,this](){
        device dev = devices.open(this->device_choose);
        // 设置过滤规则

        SafeQueue<std::vector<std::any>> packet_queue;
        dev.start_capture(packet_queue); //启动抓包，自动起了一个线程。不会在这阻塞
        std::vector<std::any> packet = packet_queue.blockPop();
        auto sm = std::any_cast<simple_info>(packet[0]);
        ui->label_text->setText(sm.t.toString("yyyy-MM-dd hh:mm:ss"));
    });

}

MainWindow::~MainWindow()
{
    delete ui;
}

