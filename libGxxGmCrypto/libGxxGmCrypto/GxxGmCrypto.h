#ifndef _GxxGmCrypto_H_
#define _GxxGmCrypto_H_

#include <string>


#define EVP_MAX_KEY_LENGHT 64

class GxxGmCrypto
{
public:
	GxxGmCrypto();
	~GxxGmCrypto();

public:
	/**
	 * �������ݣ���Ҫ�������ġ����ĳ��ȡ���Կ������
	 * ����ģʽĬ��ΪAES/CBC/PKCS5Padding��128λ����
	 * ���ܽ��Ϊ���ĵ�Base64ֵ
	 */
	int GxxGmEncryptData(const unsigned char *plain, int plain_len, unsigned char *cipher, int *cipher_len, const char *key, int key_len, const char *encrypt_mode, const char *iv, int iv_len);

	/**
	 * ��������
	 */
	int GxxGmDecryptData(const unsigned char *cipher, int cipher_len, unsigned char *plain, int *plain_len);

public:
	/**
	 * ��������
	 * ������
	 *	@plain			����
	 *	@plain_len		���ĳ���
	 *	@cipher			����
	 *	@cipher_len		���ĳ���
	 *	@key			��Կ��������16�ֽڣ������Ĳ��ֽضϣ�����Ĳ��ֲ���
	 *	@key_len		��Կ����
	 *	@encrypt_mode	����ģʽ��ECB��CBC��CFB��OFB
	 *	@iv				������������16�ֽڣ������Ĳ��ֽضϣ�����Ĳ��ֲ���
	 *	@iv_len			��������
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
	 *	@key			��Կ��������16�ֽڣ������Ĳ��ֽضϣ�����Ĳ��ֲ���
	 *	@key_len		��Կ����
	 *	@encrypt_mode	����ģʽ��ECB��CBC��CFB��OFB
	 *	@iv				������������16�ֽڣ������Ĳ��ֽضϣ�����Ĳ��ֲ���
	 *	@iv_len			��������
	 * ����ֵ��
	 *	@
	 */
	int AesDecryptData(const unsigned char *cipher, int cipher_len, unsigned char *plain, int *plain_len, const char *key, int key_len, const char *encrypt_mode, const char *iv, int iv_len);

};

#endif//_GxxGmCrypto_H_
