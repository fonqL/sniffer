#include "charts.h"
#include "./ui_charts.h"

void charts::setCount(std::vector<Count_time> c){
    this->count_t.assign(c.begin(), c.end());
}

charts::charts(QWidget* parent)
    : QDialog(parent), ui(new Ui::Dialog) {
    ui->setupUi(this);

    connect(ui->pushButton, &QPushButton::clicked, this, [=](){
        QChart *chart = new QChart();

        QBarCategoryAxis *axisX = new QBarCategoryAxis();

        QBarSet* ipv4_set = new QBarSet("ipv4");
        QBarSet* ipv6_set = new QBarSet("ipv6");
        for(int i = 0; i<this->count_t.size(); i++){
            *ipv4_set << this->count_t[i].ipv4; 
            *ipv6_set << this->count_t[i].ipv6; 
            axisX->append(this->count_t[i].time.toString("hh:mm:ss"));
        }

        QBarSeries *series = new QBarSeries();
        series->append(ipv4_set);
        series->append(ipv6_set);

        chart->addAxis(axisX, Qt::AlignBottom);

        QValueAxis *axisY = new QValueAxis();

        series->setLabelsVisible(true);
        series->setVisible(true);

        chart->addSeries(series);
        chart->setTitle("ipv4&ipv6");
        chart->setAnimationOptions(QChart::SeriesAnimations);
        chart->legend()->setVisible(true);
        chart->legend()->setAlignment(Qt::AlignBottom);

        QChartView* cv = new QChartView(chart);
        cv->setRenderHint(QPainter::Antialiasing);
        ui->gridLayout->addWidget(cv, 0, 1);
    });

}

charts::~charts() {
    delete ui;
}