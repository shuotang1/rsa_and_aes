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
#endif
