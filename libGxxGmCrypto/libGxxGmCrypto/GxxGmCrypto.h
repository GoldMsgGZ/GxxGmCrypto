#ifndef _GxxGmCrypto_H_
#define _GxxGmCrypto_H_

#include <string>
#include "openssl/evp.h"
#include "openssl/ossl_typ.h"

#define EVP_MAX_KEY_LENGHT 64

class GxxGmCrypto
{
public:
	GxxGmCrypto();
	~GxxGmCrypto();

public:
	/**
	 * ��ʼ��AES�㷨������
	 * ������
	 *	@key			��Կ��������16�ֽڣ������Ĳ��ֽضϣ�����Ĳ��ֲ���
	 *	@key_len		��Կ����
	 *	@encrypt_mode	����ģʽ��ECB��CBC��CFB��OFB
	 *	@iv				������������16�ֽڣ������Ĳ��ֽضϣ�����Ĳ��ֲ���
	 *	@iv_len			��������
	 * ����ֵ��
	 *	@
	 */
	//int AesInitialize(const char *key, int key_len, const char *encrypt_mode, const char *iv, int iv_len);

	/**
	 * ��������
	 * ������
	 *	@plain			����
	 *	@plain_len		���ĳ���
	 *	@cipher			����
	 *	@cipher_len		���ĳ���
	 * ����ֵ��
	 *	@
	 */
	int AesEncryptData(const unsigned char *plain, int plain_len, unsigned char *cipher, int *cipher_len, const char *key, int key_len, const char *encrypt_mode, const char *iv, int iv_len);

	/**
	 * ��������
	 * ������
	 *	@cipher			����
	 *	@cipher_len		���ĳ���
	 *	@plain			����
	 *	@plain_len		���ĳ���
	 * ����ֵ��
	 *	@
	 */
	int AesDecryptData(const unsigned char *cipher, int cipher_len, unsigned char *plain, int *plain_len, const char *key, int key_len, const char *encrypt_mode, const char *iv, int iv_len);

private:
	unsigned char key_[EVP_MAX_KEY_LENGHT];
	unsigned char iv_[EVP_MAX_KEY_LENGHT];

	const EVP_CIPHER *evp_cipher_;
};

#endif//_GxxGmCrypto_H_
