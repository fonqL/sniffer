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
    // 选中的下标
    this->device_choose = 0;

    connect(ui->comboBox, &QComboBox::currentIndexChanged, this, [this](){
        this->device_choose = (uint) ui->comboBox->currentIndex();
    });

    //最顶部的那个label和button是用来测试输出的，到时候再删掉
    connect(ui->pushButton_text, &QPushButton::clicked, this, [=](){
        ui->label_text->setText(x[this->device_choose]);
    });

}

MainWindow::~MainWindow()
{
    delete ui;
}

