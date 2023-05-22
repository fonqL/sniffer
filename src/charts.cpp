#include "charts.h"
#include "src/ui_charts.h"
//

void charts::setCount(std::vector<Count_time> c) {
    this->count_t.assign(c.begin(), c.end());
}

charts::charts(QWidget* parent)
    : QDialog(parent), ui(new Ui::Dialog), chart(std::make_unique<QChart>()) {
    ui->setupUi(this);
    ui->horizontalScrollBar->setVisible(false);

    // ipv4&ipv6
    connect(ui->pushButton, &QPushButton::clicked, this, [=]() {
        chart.get()->removeAllSeries();
        for (int i = 0; i < chart.get()->axes().size(); i++) {
            chart.get()->removeAxis(chart.get()->axes().at(i));
        }
        ui->horizontalScrollBar->disconnect();
        ui->horizontalScrollBar->setVisible(true);

        if (this->count_t.size() < 1) {
            return;
        }
        QBarCategoryAxis* axisX = new QBarCategoryAxis();
        QValueAxis* axisY = new QValueAxis();

        QBarSet* ipv4_set = new QBarSet("ipv4");
        QBarSet* ipv6_set = new QBarSet("ipv6");
        int max = this->count_t.back().ipv4;
        if (this->count_t.back().ipv6 > max) {
            max = this->count_t.back().ipv6;
        }
        for (int i = 0; i < this->count_t.size(); i++) {
            *ipv4_set << this->count_t[i].ipv4;
            *ipv6_set << this->count_t[i].ipv6;
            axisX->append(this->count_t[i].time.toString("hh:mm:ss"));
        }

        axisX->setRange(axisX->at(this->count_t.size() > 5 ? this->count_t.size() - 5 : 0), axisX->at(this->count_t.size() - 1));
        axisY->setRange(0, max);
        axisY->setLabelFormat("%d");

        QBarSeries* series = new QBarSeries();
        series->append(ipv4_set);
        series->append(ipv6_set);

        chart->addSeries(series);

        chart->addAxis(axisX, Qt::AlignBottom);
        chart->addAxis(axisY, Qt::AlignLeft);

        series->attachAxis(axisX);
        series->attachAxis(axisY);
        // series->setLabelsVisible(true);
        series->setVisible(true);

        chart->setTheme(QChart::ChartThemeLight); //设置白色主题
        chart->setDropShadowEnabled(true);
        chart->setTitle("ipv4&ipv6");
        chart->setAnimationOptions(QChart::SeriesAnimations);
        chart->legend()->setVisible(true);
        chart->legend()->setAlignment(Qt::AlignBottom);

        QChartView* cv = new QChartView(chart.get());
        cv->setRenderHint(QPainter::Antialiasing);

        ui->horizontalScrollBar->setRange(0, this->count_t.size() > 5 ? this->count_t.size() - 5 : 0);
        ui->horizontalScrollBar->setPageStep(1);
        ui->horizontalScrollBar->setValue(this->count_t.size() > 5 ? this->count_t.size() - 5 : 0);

        connect(ui->horizontalScrollBar, &QScrollBar::valueChanged, this, [=]() {
            axisX->setRange(axisX->at(ui->horizontalScrollBar->value()), axisX->at(ui->horizontalScrollBar->value() + 4));
        });

        // 删除布局中所有的控件
        while (ui->gridLayout->count()) {
            QWidget* p = this->ui->gridLayout->itemAt(0)->widget();
            p->setParent(NULL);
            this->ui->gridLayout->removeWidget(p);
            delete p; // 清除内存
        }

        ui->gridLayout->addWidget(cv, 0, 1);
    });

    connect(ui->pushButton_2, &QPushButton::clicked, this, [=]() {
        chart.get()->removeAllSeries();
        for (int i = 0; i < chart.get()->axes().size(); i++) {
            chart.get()->removeAxis(chart.get()->axes().at(i));
        }
        ui->horizontalScrollBar->setVisible(false);

        if (this->count_t.size() < 1) {
            return;
        }

        QPieSeries* series = new QPieSeries();

        double arp = this->count_t.back().arp;
        double tcp = this->count_t.back().tcp;
        double udp = this->count_t.back().udp;
        double sum = arp + tcp + udp;

        series->append(QString::asprintf("arp: %.2lf%", arp / sum * 100), arp);
        series->append(QString::asprintf("tcp: %.2lf%", tcp / sum * 100), tcp);
        series->append(QString::asprintf("udp: %.2lf%", udp / sum * 100), udp);

        series->setLabelsVisible(true);
        series->setUseOpenGL(true);
        series->slices().at(0)->setColor(QColor(13, 128, 217)); //设置颜色
        series->slices().at(0)->setLabelColor(QColor(13, 128, 217));
        series->slices().at(1)->setColor(QColor(69, 13, 217));
        series->slices().at(1)->setLabelColor(QColor(69, 13, 217));
        series->slices().at(2)->setColor(QColor(13, 217, 152));
        series->slices().at(2)->setLabelColor(QColor(13, 217, 152));

        chart->setTheme(QChart::ChartThemeLight); //设置白色主题
        chart->setDropShadowEnabled(true);
        chart->addSeries(series);

        chart->setTitle("arp&udp&tcp");

        chart->legend()->setVisible(true);
        chart->legend()->setAlignment(Qt::AlignRight);       //底部对齐
        chart->legend()->setBackgroundVisible(true);         //设置背景是否可视
        chart->legend()->setAutoFillBackground(true);        //设置背景自动填充
        chart->legend()->setColor(QColor(222, 233, 251));    //设置颜色
        chart->legend()->setLabelColor(QColor(0, 100, 255)); //设置标签颜色
        chart->legend()->setMaximumHeight(150);

        QChartView* cv = new QChartView(chart.get());
        cv->setRenderHint(QPainter::Antialiasing);

        // 删除布局中所有的控件
        while (ui->gridLayout->count()) {
            QWidget* p = this->ui->gridLayout->itemAt(0)->widget();
            p->setParent(NULL);
            this->ui->gridLayout->removeWidget(p);
            delete p; // 清除内存
        }

        ui->gridLayout->addWidget(cv, 0, 1);
    });

    //dns占比走势
    connect(ui->pushButton_3, &QPushButton::clicked, this, [=]() {
        chart.get()->removeAllSeries();
        for (int i = 0; i < chart.get()->axes().size(); i++) {
            chart.get()->removeAxis(chart.get()->axes().at(i));
        }
        ui->horizontalScrollBar->setVisible(false);

        if (this->count_t.size() < 1) {
            return;
        }

        QValueAxis* axisY = new QValueAxis();

        QLineSeries* series = new QLineSeries();

        QScatterSeries* series1 = new QScatterSeries();

        series1->setMarkerShape(QScatterSeries::MarkerShapeCircle); //圆形的点

        series1->setBorderColor(QColor(21, 100, 255)); //边框颜色

        series1->setBrush(QBrush(QColor(21, 100, 255))); //背景颜色

        series1->setMarkerSize(5);

        for (int i = 0; i < this->count_t.size(); i++) {
            double dns = this->count_t[i].dns;
            double oth = this->count_t[i].other_a;
            series->append(i, (dns / (dns + oth)) * 100);
            series1->append(i, (dns / (dns + oth)) * 100);
        }

        double max = 1.0 * this->count_t.back().dns / (this->count_t.back().dns + this->count_t.back().other_a) * 100;
        axisY->setRange(0.0, max);
        axisY->setLabelFormat("%.2lf%");

        chart->addSeries(series);

        chart->addAxis(axisY, Qt::AlignLeft);

        series->attachAxis(axisY);
        series->setVisible(true);
        series1->attachAxis(axisY);
        series1->setVisible(true);
        QLabel* label = new QLabel(this);
        label->hide();

        connect(series1, &QLineSeries::hovered, this, [=](const QPointF& point, bool state) {
            if (state) {
                int i = point.x();
                double dns = this->count_t[i].dns;
                double oth = this->count_t[i].other_a;
                label->setText(this->count_t[i].time.toString("hh:mm:ss") + QString::asprintf(": %.2lf%", (dns / (dns + oth)) * 100));
                QPoint curPos = mapFromGlobal(QCursor::pos());
                label->move(curPos.x() - label->width() / 2, curPos.y() - label->height() * 1.5); //移动数值
                label->show();                                                                    //显示出来
            } else {
                label->hide(); //进行隐藏
            }
        });

        chart->setTheme(QChart::ChartThemeLight); //设置白色主题
        chart->setDropShadowEnabled(true);
        chart->addSeries(series);
        chart->addSeries(series1);

        chart->setTitle("dns占比走势");

        QChartView* cv = new QChartView(chart.get());
        cv->setRenderHint(QPainter::Antialiasing);

        while (ui->gridLayout->count()) {
            QWidget* p = this->ui->gridLayout->itemAt(0)->widget();
            p->setParent(NULL);
            this->ui->gridLayout->removeWidget(p);
            delete p; // 清除内存
        }

        ui->gridLayout->addWidget(cv, 0, 1);
    });
}

charts::~charts() {
    delete ui;
}
