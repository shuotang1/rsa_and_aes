#include "kaes.h"

QString KAes::m_sKey = "97F8A9DB-9BAE-49CB-AC2D-E802BC689E00";

KAes::KAes()
{
}

KAes::~KAes()
{
}

QString KAes::aes_cbc_encrypt(const QString& in)
{
    QByteArray inBytes = in.toUtf8();
    QByteArray keyBytes = m_sKey.toUtf8();
    //��������ݴ�СӦ�����������ݴ�С����AES_BLOCK_SIZE�ı���
    QByteArray outBytes(inBytes.size() + AES_BLOCK_SIZE - (inBytes.size() % AES_BLOCK_SIZE), Qt::Uninitialized);

    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0, AES_BLOCK_SIZE);

    //ʹ��AES_set_encrypt_key��������Կת��Ϊ�ʺ�AES�㷨ʹ�õĸ�ʽAES_KEY
    AES_KEY aes;
    if (AES_set_encrypt_key((const unsigned char*)keyBytes.constData(), 128, &aes) < 0)
        return "";

    AES_cbc_encrypt((const unsigned char*)inBytes.constData(),
        (unsigned char*)outBytes.data(),
        inBytes.size(),
        &aes,
        iv,
        AES_ENCRYPT);

    return QString::fromUtf8(outBytes.toBase64());
}

QString KAes::aes_cbc_decrypt(const QString& in)
{
    QByteArray inBytes = QByteArray::fromBase64(in.toUtf8());
    QByteArray keyBytes = m_sKey.toUtf8();
    QByteArray outBytes(inBytes.length(), Qt::Uninitialized);

    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0, AES_BLOCK_SIZE);

    AES_KEY aes;
    if (AES_set_decrypt_key((const unsigned char*)keyBytes.constData(), 128, &aes) < 0)
        return "";

    AES_cbc_encrypt((const unsigned char*)inBytes.constData(), (unsigned char*)outBytes.data(), inBytes.length(), &aes, iv, AES_DECRYPT);

    return QString::fromUtf8(outBytes);
}