// #include "mainwindow.h"
#include <QApplication>
#include <QMessageBox>
#include <qmainwindow.h>

int main(int argc, char* argv[]) {
    QApplication a(argc, argv);
    try {
        // MainWindow w;
        QMainWindow w;
        w.show();
        return a.exec();
    } catch (std::exception& e) {
        QMessageBox::critical(nullptr, "Error", e.what());
    }
    return 0;
}
