#include "mainwindow.h"
#include <QApplication>
#include <QMessageBox>

int main(int argc, char* argv[]) {
    QApplication a(argc, argv);
    try {
        MainWindow w;
        w.show();
        return a.exec();
    } catch (std::exception& e) {
        QMessageBox::critical(nullptr, "Error", e.what());
        QFile file("log.txt");
        file.open(QIODevice::WriteOnly | QIODevice::Text);
        file.write(e.what());
        file.close();
    }
}
