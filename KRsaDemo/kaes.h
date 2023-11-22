#ifndef __KRSADEMO_KAES_H__
#define __KRSADEMO_KAES_H__

#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <QString>

class KAes
{
public:
    KAes();
    ~KAes();

    QString aes_cbc_encrypt(const QString& in);
    QString aes_cbc_decrypt(const QString& in);
private:
    KAes(const KAes& other) = default;
    void operator=(const KAes& other) = delete;
    KAes(const KAes&& other) = delete;
    KAes& operator=(KAes&& other) = default;

    static QString m_sKey;
};

//QString aes_cbc_encrypt(const QString& in, const QString& key)
//{
//    QByteArray inBytes = in.toUtf8();
//    QByteArray keyBytes = key.toUtf8();
//    QByteArray outBytes(inBytes.length(), Qt::Uninitialized);
//
//    unsigned char iv[AES_BLOCK_SIZE];
//    memset(iv, 0, AES_BLOCK_SIZE);
//
//    //ʹ��AES_set_encrypt_key��������Կת��Ϊ�ʺ�AES�㷨ʹ�õĸ�ʽAES_KEY
//    AES_KEY aes;
//    if (AES_set_encrypt_key((const unsigned char*)keyBytes.constData(), 128, &aes) < 0)
//        return "";
//
//    AES_cbc_encrypt((const unsigned char*)inBytes.constData(),
//        (unsigned char*)outBytes.data(),
//        inBytes.length(),
//        &aes,
//        iv,
//        AES_ENCRYPT);
//
//    return QString::fromUtf8(outBytes.toBase64());
//}
//
//QString aes_cbc_decrypt(const QString& in, const QString& key) 
//{
//    QByteArray inBytes = QByteArray::fromBase64(in.toUtf8());
//    QByteArray keyBytes = key.toUtf8();
//    QByteArray outBytes(inBytes.length(), Qt::Uninitialized);
//
//    unsigned char iv[AES_BLOCK_SIZE];
//    memset(iv, 0, AES_BLOCK_SIZE);
//
//    AES_KEY aes;
//    if (AES_set_decrypt_key((const unsigned char*)keyBytes.constData(), 128, &aes) < 0)
//        return "";
//
//    AES_cbc_encrypt((const unsigned char*)inBytes.constData(), (unsigned char*)outBytes.data(), inBytes.length(), &aes, iv, AES_DECRYPT);
//
//    return QString::fromUtf8(outBytes);
//}

//// �����������������һ��
//void AES(unsigned char* InBuff, unsigned char* OutBuff, unsigned char* key, char* Type)
//{
//    if (strcmp(Type, "encode") == 0)
//    {
//        AES_KEY AESEncryptKey;
//        AES_set_encrypt_key(key, 256, &AESEncryptKey);
//        AES_encrypt(InBuff, OutBuff, &AESEncryptKey);
//    }
//    else if (strcmp(Type, "decode") == 0)
//    {
//        AES_KEY AESDecryptKey;
//        AES_set_decrypt_key(key, 256, &AESDecryptKey);
//        AES_decrypt(InBuff, OutBuff, &AESDecryptKey);
//    }
//}
#endif
