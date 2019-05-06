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
	 * 加密数据，需要输入明文、明文长度、密钥、向量
	 * 加密模式默认为AES/CBC/PKCS5Padding，128位加密
	 * 加密结果为密文的Base64值
	 */
	int GxxGmEncryptData(const unsigned char *plain, int plain_len, unsigned char *cipher, int *cipher_len, const char *key, int key_len, const char *encrypt_mode, const char *iv, int iv_len);

	/**
	 * 解密数据
	 */
	int GxxGmDecryptData(const unsigned char *cipher, int cipher_len, unsigned char *plain, int *plain_len);

public:
	/**
	 * 加密数据
	 * 参数：
	 *	@plain			明文
	 *	@plain_len		明文长度
	 *	@cipher			密文
	 *	@cipher_len		密文长度
	 *	@key			密钥，不超过16字节，超过的部分截断，不足的部分补零
	 *	@key_len		密钥长度
	 *	@encrypt_mode	加密模式，ECB、CBC、CFB、OFB
	 *	@iv				向量，不超过16字节，超过的部分截断，不足的部分补零
	 *	@iv_len			向量长度
	 * 返回值：
	 *	@
	 */
	int AesEncryptData(const unsigned char *plain, int plain_len, unsigned char *cipher, int *cipher_len, const char *key, int key_len, const char *encrypt_mode, const char *iv, int iv_len);

	/**
	 * 解密数据
	 * 参数：
	 *	@cipher			密文
	 *	@cipher_len		密文长度
	 *	@plain			明文
	 *	@plain_len		明文长度
	 *	@key			密钥，不超过16字节，超过的部分截断，不足的部分补零
	 *	@key_len		密钥长度
	 *	@encrypt_mode	加密模式，ECB、CBC、CFB、OFB
	 *	@iv				向量，不超过16字节，超过的部分截断，不足的部分补零
	 *	@iv_len			向量长度
	 * 返回值：
	 *	@
	 */
	int AesDecryptData(const unsigned char *cipher, int cipher_len, unsigned char *plain, int *plain_len, const char *key, int key_len, const char *encrypt_mode, const char *iv, int iv_len);

};

#endif//_GxxGmCrypto_H_
