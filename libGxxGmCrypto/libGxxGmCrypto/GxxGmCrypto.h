#ifndef _GxxGmCrypto_H_
#define _GxxGmCrypto_H_

#include "openssl/evp.h"

#define EVP_MAX_KEY_LENGHT 64

class GxxGmCrypto
{
public:
	GxxGmCrypto();
	~GxxGmCrypto();

public:
	int AesInitialize(const char *key, int key_len, const char *iv, int iv_len);

	/**
	 * 加密数据
	 */
	int AesEncryptData(const char *plain, int plain_len, char *cipher, int *cipher_len);

	/**
	 * 解密数据
	 */
	int AesDecryptData(const char *cipher, int cipher_len, char *plain, int *plain_len);

private:
	EVP_CIPHER_CTX ctx;
	unsigned char key[EVP_MAX_KEY_LENGHT];
	unsigned char iv[EVP_MAX_KEY_LENGHT];
};

#endif//_GxxGmCrypto_H_
