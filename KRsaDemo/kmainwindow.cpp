#include "kmainwindow.h"
#include "KRsa.h"
#include "kaes.h"

#include <QFile>
#include <QLineEdit>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>

KMainWindow::KMainWindow(QWidget *parent)
    : QWidget(parent)
{
    initWindow();
}

KMainWindow::~KMainWindow()
{
    
}

void KMainWindow::initWindow()
{
    QLabel* m_pRSALabel = new QLabel(QStringLiteral("RSA: "), this);
    QLabel* m_pAESLabel = new QLabel("AES: ", this);
    QLineEdit* m_pInputEdit = new QLineEdit(this);
    QPushButton* m_pGenerateRSAKeyPairBtn = new QPushButton(QStringLiteral("生成RSA密钥对"), this);
    QPushButton* m_pRunBtn = new QPushButton("run", this);
    m_pRunBtn->setEnabled(false);
    QLineEdit* m_pAESInputEdit = new QLineEdit(this);
    QPushButton* m_pAESRunBtn = new QPushButton("run", this);
    m_pAESRunBtn->setEnabled(false);
    QPlainTextEdit* m_pEncryptEdit = new QPlainTextEdit(this);
    QPlainTextEdit* m_pDecryptEdit = new QPlainTextEdit(this);

    QHBoxLayout* m_pHBoxLay = new QHBoxLayout;
    m_pHBoxLay->addWidget(m_pRSALabel);
    m_pHBoxLay->addWidget(m_pInputEdit);
    m_pHBoxLay->addWidget(m_pGenerateRSAKeyPairBtn);
    m_pHBoxLay->addWidget(m_pRunBtn);

    QHBoxLayout* m_pHAESLay = new QHBoxLayout;
    m_pHAESLay->addWidget(m_pAESLabel);
    m_pHAESLay->addWidget(m_pAESInputEdit);
    m_pHAESLay->addWidget(m_pAESRunBtn);

    QVBoxLayout* m_pVMainLay = new QVBoxLayout(this);
    m_pVMainLay->addLayout(m_pHBoxLay);
    m_pVMainLay->addLayout(m_pHAESLay);
    m_pVMainLay->addWidget(m_pEncryptEdit);
    m_pVMainLay->addWidget(m_pDecryptEdit);

    (void)connect(m_pInputEdit, &QLineEdit::textChanged, this, [=]() {
        m_pRunBtn->setEnabled(!m_pInputEdit->text().isEmpty());
    });
    (void)connect(m_pAESInputEdit, &QLineEdit::textChanged, this, [=]() {
        m_pAESRunBtn->setEnabled(!m_pAESInputEdit->text().isEmpty());
    });

    (void)connect(m_pGenerateRSAKeyPairBtn, &QPushButton::clicked, this, [&]() {
        KRsa rsa;
        rsa.generateRSAKeyPair();
        QMessageBox::warning(Q_NULLPTR, QStringLiteral("createSuccess"), QStringLiteral("创建成功"), QMessageBox::Ok);
    });

    (void)connect(m_pRunBtn, &QPushButton::clicked, this, [=]() {
        m_pEncryptEdit->setPlainText(rsa_pub_encrypt_base64(m_pInputEdit->text()));
        m_pDecryptEdit->setPlainText(rsa_pri_decrypt_base64(m_pEncryptEdit->toPlainText()));
    });

    (void)connect(m_pAESRunBtn, &QPushButton::clicked, this, [=]() {
        m_pEncryptEdit->setPlainText(aes_pub_encrypt_base64(m_pAESInputEdit->text()));
        m_pDecryptEdit->setPlainText(aes_pri_decrypt_base64(m_pEncryptEdit->toPlainText()));
    });
}

QString KMainWindow::rsa_pub_encrypt_base64(const QString& strEncryptData)
{
    QFile file(".//key//public.pem");
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return "";
    QString pubKey = file.readAll();
    file.close();

    KRsa rsa;
    return rsa.rsaPubEncrypt(strEncryptData, pubKey);
}

QString KMainWindow::rsa_pri_decrypt_base64(const QString& strDecryptData)
{
    QFile file(".//key//private.pem");
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return "";
    QString priKey = file.readAll();
    file.close();

    KRsa rsa;
    return rsa.rsaPriDecrypt(strDecryptData, priKey);
}

QString KMainWindow::aes_pub_encrypt_base64(const QString& strEncryptData)
{ 
    KAes aes;
    return aes.aes_cbc_encrypt(strEncryptData);
}

QString KMainWindow::aes_pri_decrypt_base64(const QString& strDecryptData)
{
    KAes aes;
    return aes.aes_cbc_decrypt(strDecryptData);
}


