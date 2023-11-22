#include "KRsa.h"

KRsa::KRsa()
{

}

KRsa::~KRsa()
{

}

QString KRsa::rsaPubEncrypt(const QString& strPlainData, const QString& strPubKey)
{
    QByteArray pubKeyArry = strPubKey.toUtf8();
    uchar* pPubKey = (uchar*)pubKeyArry.data();
    BIO* pKeyBio = BIO_new_mem_buf(pPubKey, pubKeyArry.length()); //创建一个BIO对象，用于读取公钥字节数组的内存缓冲区。
    if (pKeyBio == NULL)
        return "";

    RSA* pRsa = RSA_new();  
    if (strPubKey.contains(BEGIN_RSA_PUBLIC_KEY)) 
        pRsa = PEM_read_bio_RSAPublicKey(pKeyBio, &pRsa, NULL, NULL);  //从BIO对象中读取公钥数据，并将其存储到RSA对象中。
    else 
        pRsa = PEM_read_bio_RSA_PUBKEY(pKeyBio, &pRsa, NULL, NULL);    

    if (pRsa == NULL) 
    {
        BIO_free_all(pKeyBio);
        return "";
    }

    int nLen = RSA_size(pRsa);         

    //加密
    QByteArray plainDataArry = strPlainData.toUtf8();
    int nPlainDataLen = plainDataArry.length();

    int exppadding = nLen;
    if (nPlainDataLen > exppadding - 11)
        exppadding = exppadding - 11;       //计算加密填充的长度
    int slice = nPlainDataLen / exppadding; //片数
    if (nPlainDataLen % (exppadding))
        slice++;

    QByteArray arry;
    uchar* pEncryptBuf = new uchar[nLen];   //创建一个用于存储加密后数据的缓冲区
    for (int i = 0; i < slice; i++)
    {
        QByteArray baData = plainDataArry.mid(i * exppadding, exppadding);
        nPlainDataLen = baData.length();
        memset(pEncryptBuf, 0, nLen);
        uchar* pPlainData = (uchar*)baData.data();
        int nSize = RSA_public_encrypt(nPlainDataLen, pPlainData, pEncryptBuf, pRsa, RSA_PKCS1_PADDING);
        if (nSize >= 0)
            arry.append(QByteArray(reinterpret_cast<const char*>(pEncryptBuf), nSize));
    }

    //释放内存
    delete[] pEncryptBuf;
    BIO_free_all(pKeyBio);
    RSA_free(pRsa);

    return arry.toBase64();
}

QString KRsa::rsaPriDecrypt(const QString& strDecryptData, const QString& strPriKey)
{
    QByteArray priKeyArry = strPriKey.toUtf8();
    uchar* pPriKey = (uchar*)priKeyArry.data();
    BIO* pKeyBio = BIO_new_mem_buf(pPriKey, priKeyArry.length());
    if (pKeyBio == NULL)
        return "";

    RSA* pRsa = RSA_new();
    pRsa = PEM_read_bio_RSAPrivateKey(pKeyBio, &pRsa, NULL, NULL);
    if (pRsa == NULL) 
    {
        BIO_free_all(pKeyBio);
        return "";
    }

    int nLen = RSA_size(pRsa);

    //解密
    QByteArray decryptDataArry = strDecryptData.toUtf8();
    decryptDataArry = QByteArray::fromBase64(decryptDataArry);
    int nDecryptDataLen = decryptDataArry.length();

    int rsasize = nLen;
    int slice = nDecryptDataLen / rsasize;//片数
    if (nDecryptDataLen % (rsasize))
        slice++;

    QByteArray plainDataArry;
    uchar* pPlainBuf = new uchar[nLen];
    for (int i = 0; i < slice; i++)
    {
        QByteArray baData = decryptDataArry.mid(i * rsasize, rsasize);
        nDecryptDataLen = baData.length();
        memset(pPlainBuf, 0, nLen);
        uchar* pDecryptData = (uchar*)baData.data();
        int nSize = RSA_private_decrypt(nDecryptDataLen, pDecryptData, pPlainBuf, pRsa, RSA_PKCS1_PADDING);
        if (nSize >= 0) 
            plainDataArry.append(QByteArray(reinterpret_cast<const char*>(pPlainBuf), nSize));
    }

    //释放内存
    delete[] pPlainBuf;
    BIO_free_all(pKeyBio);
    RSA_free(pRsa);

    return QString::fromUtf8(plainDataArry);
}

void KRsa::generateRSAKeyPair()
{
    // 初始化OpenSSL库  
    OpenSSL_add_all_algorithms();     //加载所有算法
    ERR_load_crypto_strings();        //加载错误字符串

    // 创建RSA对象  
    BIGNUM* bne = BN_new();           //创建一个BIGNUM对象，用于存储RSA公钥指数
    unsigned long e = RSA_F4;
    int ret = BN_set_word(bne, e);    //将指定无符号整数e设置为公钥指数
    if (ret != 1)
        return;

    RSA* rsa = RSA_new();      //创建RSA对象
    ret = RSA_generate_key_ex(rsa, 2048, bne, NULL);   //使用指定的RSA对象和参数生成RSA密钥对。2048指定密钥长度，bne指定公钥指数。
    if (ret != 1)
        return;

    // 创建BIO对象  
    BIO* bp_public = BIO_new_file(".//key//public.pem", "w+");  //创建一个BIO对象，用于写入公钥文件。
    BIO* bp_private = BIO_new_file(".//key//private.pem", "w+");//创建一个BIO对象，用于写入私钥文件。
 
    ret = PEM_write_bio_RSAPublicKey(bp_public, rsa); // 将RSA公钥对写入BIO对象 
    if (ret != 1)
        return;
    ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL); //将RSA私钥写入到BIO对象中
    if (ret != 1)
        return;

    // 释放资源  
    RSA_free(rsa);
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    BN_free(bne);
    ERR_free_strings();  //释放OpenSSL错误字符串的内存
    EVP_cleanup();       //清理OpenSSL库的资源
}