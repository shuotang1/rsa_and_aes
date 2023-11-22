#ifndef __KRSADEMO_KMAINWINDOW_H__
#define __KRSADEMO_KMAINWINDOW_H__
 
#include <QtWidgets/QWidget>  

class KMainWindow : public QWidget
{
    Q_OBJECT

public:
    KMainWindow(QWidget *parent = Q_NULLPTR);
    ~KMainWindow();

    QString rsa_pub_encrypt_base64(const QString& strEncryptData);   //RSA���ܺ���
    QString rsa_pri_decrypt_base64(const QString& strDecryptData);   //RSA���ܺ���

    QString aes_pub_encrypt_base64(const QString& strEncryptData);   //AES���ܺ���
    QString aes_pri_decrypt_base64(const QString& strDecryptData);   //AES���ܺ���
private:
    void initWindow();

    KMainWindow(const KMainWindow& other) = default;
    void operator=(const KMainWindow& other) = delete;
    KMainWindow(const KMainWindow&& other) = delete;
    KMainWindow& operator=(KMainWindow&& other) = default;
};
#endif