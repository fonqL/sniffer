#include "charts.h"
#include "./ui_charts.h"

void charts::setCount(std::vector<Count_time> c){
    this->count_t.assign(c.begin(), c.end());
}

charts::charts(QWidget* parent)
    : QDialog(parent), ui(new Ui::Dialog) {
    ui->setupUi(this);
    ui->horizontalScrollBar->setVisible(false);
    this->sc_value = 0;

    connect(ui->pushButton, &QPushButton::clicked, this, [=](){
        ui->horizontalScrollBar->setVisible(true);

        QChart *chart = new QChart();

        QBarCategoryAxis *axisX = new QBarCategoryAxis();
        QValueAxis *axisY = new QValueAxis();

        QBarSet* ipv4_set = new QBarSet("ipv4");
        QBarSet* ipv6_set = new QBarSet("ipv6");
        int max = this->count_t[this->count_t.size()-1].ipv4;
        if(this->count_t[this->count_t.size()-1].ipv6>max){
            max = this->count_t[this->count_t.size()-1].ipv6;
        }
        for(int i = 0; i<this->count_t.size(); i++){
            *ipv4_set << this->count_t[i].ipv4; 
            *ipv6_set << this->count_t[i].ipv6; 
            axisX->append(this->count_t[i].time.toString("hh:mm:ss"));
        }

        axisX->setRange(axisX->at(0), axisX->at(4));
        axisY->setRange(0, max);
        axisY->setLabelFormat("%d");
        this->s = 0;

        QBarSeries *series = new QBarSeries();
        series->append(ipv4_set);
        series->append(ipv6_set);

        chart->addSeries(series);

        chart->addAxis(axisX, Qt::AlignBottom);
        chart->addAxis(axisY, Qt::AlignLeft);
        
        series->attachAxis(axisX);
        series->attachAxis(axisY);
        // series->setLabelsVisible(true);
        series->setVisible(true);

        chart->setTitle("ipv4&ipv6");
        chart->setAnimationOptions(QChart::SeriesAnimations);
        chart->legend()->setVisible(true);
        chart->legend()->setAlignment(Qt::AlignBottom);

        QChartView* cv = new QChartView(chart);
        cv->setRenderHint(QPainter::Antialiasing);

        ui->horizontalScrollBar->setRange(0, this->count_t.size()>5?this->count_t.size()-5:0);
        ui->horizontalScrollBar->setPageStep(1);

        connect(ui->horizontalScrollBar, &QScrollBar::valueChanged, this, [=](){

            auto len = cv->chart()->plotArea().width();
            if(ui->horizontalScrollBar->value() != this->sc_value){
                int c = ui->horizontalScrollBar->value()-this->sc_value;
                this->s += c;
                if(this->s<0){
                    this->s = 0;
                }
                if(this->s+4>=this->count_t.size()){
                    this->s = this->count_t.size()-5;
                }
                axisX->setRange(axisX->at(this->s), axisX->at(this->s+4));
            }

            this->sc_value = ui->horizontalScrollBar->value();
        });
        
        ui->gridLayout->addWidget(cv, 0, 1);
    });

}

charts::~charts() {
    delete ui;
}