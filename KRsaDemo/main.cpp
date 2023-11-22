#include "kmainwindow.h"
#include <QtWidgets/QApplication>
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    KMainWindow w;
    w.show();
    return a.exec();
}
