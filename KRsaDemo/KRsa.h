#ifndef __KRSADEMO_KRSA_H__
#define __KRSADEMO_KRSA_H__

#include <QString>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define BEGIN_RSA_PUBLIC_KEY    "BEGIN RSA PUBLIC KEY"
#define BEGIN_RSA_PRIVATE_KEY   "BEGIN RSA PRIVATE KEY"
#define BEGIN_PUBLIC_KEY        "BEGIN PUBLIC KEY"
#define BEGIN_PRIVATE_KEY       "BEGIN PRIVATE KEY"
#define KEY_LENGTH              1024

class KRsa
{
public:
	KRsa();
	~KRsa();

	void generateRSAKeyPair();
	QString rsaPubEncrypt(const QString& strPlainData, const QString& strPubKey);
	QString rsaPriDecrypt(const QString& strDecryptData, const QString& strPriKey);
private:
	KRsa(const KRsa& other) = default;
	void operator=(const KRsa& other) = delete;
	KRsa(const KRsa&& other) = delete;
	KRsa& operator=(KRsa&& other) = default;
};
#endif

