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
	 * 初始化AES算法环境，
	 * 参数：
	 *	@key			密钥，不超过16字节，超过的部分截断，不足的部分补零
	 *	@key_len		密钥长度
	 *	@encrypt_mode	加密模式，ECB、CBC、CFB、OFB
	 *	@iv				向量，不超过16字节，超过的部分截断，不足的部分补零
	 *	@iv_len			向量长度
	 * 返回值：
	 *	@
	 */
	//int AesInitialize(const char *key, int key_len, const char *encrypt_mode, const char *iv, int iv_len);

	/**
	 * 加密数据
	 * 参数：
	 *	@plain			明文
	 *	@plain_len		明文长度
	 *	@cipher			密文
	 *	@cipher_len		密文长度
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
	 * 返回值：
	 *	@
	 */
	int AesDecryptData(const unsigned char *cipher, int cipher_len, unsigned char *plain, int *plain_len, const char *key, int key_len, const char *encrypt_mode, const char *iv, int iv_len);

private:
	unsigned char key_[EVP_MAX_KEY_LENGHT];
	unsigned char iv_[EVP_MAX_KEY_LENGHT];

	const EVP_CIPHER *evp_cipher_;
};

#endif//_GxxGmCrypto_H_
