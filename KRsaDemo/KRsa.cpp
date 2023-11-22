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
    BIO* pKeyBio = BIO_new_mem_buf(pPubKey, pubKeyArry.length()); //����һ��BIO�������ڶ�ȡ��Կ�ֽ�������ڴ滺������
    if (pKeyBio == NULL)
        return "";

    RSA* pRsa = RSA_new();  
    if (strPubKey.contains(BEGIN_RSA_PUBLIC_KEY)) 
        pRsa = PEM_read_bio_RSAPublicKey(pKeyBio, &pRsa, NULL, NULL);  //��BIO�����ж�ȡ��Կ���ݣ�������洢��RSA�����С�
    else 
        pRsa = PEM_read_bio_RSA_PUBKEY(pKeyBio, &pRsa, NULL, NULL);    

    if (pRsa == NULL) 
    {
        BIO_free_all(pKeyBio);
        return "";
    }

    int nLen = RSA_size(pRsa);         

    //����
    QByteArray plainDataArry = strPlainData.toUtf8();
    int nPlainDataLen = plainDataArry.length();

    int exppadding = nLen;
    if (nPlainDataLen > exppadding - 11)
        exppadding = exppadding - 11;       //����������ĳ���
    int slice = nPlainDataLen / exppadding; //Ƭ��
    if (nPlainDataLen % (exppadding))
        slice++;

    QByteArray arry;
    uchar* pEncryptBuf = new uchar[nLen];   //����һ�����ڴ洢���ܺ����ݵĻ�����
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

    //�ͷ��ڴ�
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

    //����
    QByteArray decryptDataArry = strDecryptData.toUtf8();
    decryptDataArry = QByteArray::fromBase64(decryptDataArry);
    int nDecryptDataLen = decryptDataArry.length();

    int rsasize = nLen;
    int slice = nDecryptDataLen / rsasize;//Ƭ��
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

    //�ͷ��ڴ�
    delete[] pPlainBuf;
    BIO_free_all(pKeyBio);
    RSA_free(pRsa);

    return QString::fromUtf8(plainDataArry);
}

void KRsa::generateRSAKeyPair()
{
    // ��ʼ��OpenSSL��  
    OpenSSL_add_all_algorithms();     //���������㷨
    ERR_load_crypto_strings();        //���ش����ַ���

    // ����RSA����  
    BIGNUM* bne = BN_new();           //����һ��BIGNUM�������ڴ洢RSA��Կָ��
    unsigned long e = RSA_F4;
    int ret = BN_set_word(bne, e);    //��ָ���޷�������e����Ϊ��Կָ��
    if (ret != 1)
        return;

    RSA* rsa = RSA_new();      //����RSA����
    ret = RSA_generate_key_ex(rsa, 2048, bne, NULL);   //ʹ��ָ����RSA����Ͳ�������RSA��Կ�ԡ�2048ָ����Կ���ȣ�bneָ����Կָ����
    if (ret != 1)
        return;

    // ����BIO����  
    BIO* bp_public = BIO_new_file(".//key//public.pem", "w+");  //����һ��BIO��������д�빫Կ�ļ���
    BIO* bp_private = BIO_new_file(".//key//private.pem", "w+");//����һ��BIO��������д��˽Կ�ļ���
 
    ret = PEM_write_bio_RSAPublicKey(bp_public, rsa); // ��RSA��Կ��д��BIO���� 
    if (ret != 1)
        return;
    ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL); //��RSA˽Կд�뵽BIO������
    if (ret != 1)
        return;

    // �ͷ���Դ  
    RSA_free(rsa);
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    BN_free(bne);
    ERR_free_strings();  //�ͷ�OpenSSL�����ַ������ڴ�
    EVP_cleanup();       //����OpenSSL�����Դ
}