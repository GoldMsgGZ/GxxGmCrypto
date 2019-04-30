#include "GxxGmCrypto.h"
#include <string>

// https://blog.csdn.net/yygydjkthh/article/details/18666357#

GxxGmCrypto::GxxGmCrypto()
{
	// 加载OpenSSL的全部算法
	OpenSSL_add_all_algorithms();

	memset(key_, 0, EVP_MAX_KEY_LENGHT);
	memset(iv_, 0, EVP_MAX_KEY_LENGHT);
}

GxxGmCrypto::~GxxGmCrypto()
{
	
}

//int GxxGmCrypto::AesInitialize(const char *key, int key_len, const char *encrypt_mode, const char *iv, int iv_len)
//{
//	int errCode = 0;
//
//	
//	return errCode;
//}

int GxxGmCrypto::AesEncryptData(const unsigned char *plain, int plain_len, unsigned char *cipher, int *cipher_len, const char *key, int key_len, const char *encrypt_mode, const char *iv, int iv_len)
{
	int errCode = 0;

	// 数据分组，采用PKCS#7（PKCS7Padding）填充，块大小为16字节
	// 那么这里需要计算明文长度，整合出最终需要加密的数据对其长度，并且进行PKCS#7填充
	int block_count = plain_len / 16 + 1;
	int plain_block_tail_len = plain_len % 16;
	int padding_size = 16 - plain_block_tail_len;
	int padding_plain_buffer_len = 16 * block_count;

	// 判断密文缓冲区长度是否足够，不够则返回
	if (*cipher_len < padding_plain_buffer_len)
	{
		*cipher_len = padding_plain_buffer_len;
		return -2;
	}

	// 初始化加密上下文
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	// 初始化加密密钥、加密向量
	memcpy(key_, key, key_len > 16 ? 16 : key_len);
	memcpy(iv_, iv, iv_len > 16 ? 16 : iv_len);

	// 初始化加密模式
	if (_stricmp(encrypt_mode, "ECB_128") == 0)
		evp_cipher_ = EVP_aes_128_ecb();
	else if (_stricmp(encrypt_mode, "ECB_192") == 0)
		evp_cipher_ = EVP_aes_192_ecb();
	else if (_stricmp(encrypt_mode, "ECB_256") == 0)
		evp_cipher_ = EVP_aes_256_ecb();
	else if (_stricmp(encrypt_mode, "CBC_128") == 0)
		evp_cipher_ = EVP_aes_128_cbc();
	else if (_stricmp(encrypt_mode, "CBC_192") == 0)
		evp_cipher_ = EVP_aes_192_cbc();
	else if (_stricmp(encrypt_mode, "CBC_256") == 0)
		evp_cipher_ = EVP_aes_256_cbc();
	else if (_stricmp(encrypt_mode, "CFB_128") == 0)
		evp_cipher_ = EVP_aes_128_cfb();
	else if (_stricmp(encrypt_mode, "CFB_192") == 0)
		evp_cipher_ = EVP_aes_192_cfb();
	else if (_stricmp(encrypt_mode, "CFB_256") == 0)
		evp_cipher_ = EVP_aes_256_cfb();
	else if (_stricmp(encrypt_mode, "OFB_128") == 0)
		evp_cipher_ = EVP_aes_128_ofb();
	else if (_stricmp(encrypt_mode, "OFB_192") == 0)
		evp_cipher_ = EVP_aes_192_ofb();
	else if (_stricmp(encrypt_mode, "OFB_256") == 0)
		evp_cipher_ = EVP_aes_256_ofb();
	else
		evp_cipher_ = EVP_aes_128_ecb();


	// 初始化AES加密环境
	errCode = EVP_EncryptInit_ex(ctx, evp_cipher_, NULL, key_, iv_);
	if (errCode != 1)
	{
		// 初始化报错
		EVP_CIPHER_CTX_cleanup(ctx);
		return -1;
	}

	// 申请填充缓冲区，所有单元填充为填充字节数，然后将明文复制到缓冲区
	unsigned char *padding_plain_buffer = new unsigned char[padding_plain_buffer_len];
	memset(padding_plain_buffer, padding_size, padding_plain_buffer_len);
	memcpy(padding_plain_buffer, plain, plain_len);

	// 加密
	int encrypted_len = 0;
	errCode = EVP_EncryptUpdate(ctx, cipher, &encrypted_len, padding_plain_buffer, padding_plain_buffer_len);
	if (errCode != 1)
	{
		// 加密出错
		delete [] padding_plain_buffer;
		padding_plain_buffer = NULL;

		EVP_CIPHER_CTX_cleanup(ctx);
		return -3;
	}

	// 处理最后的结果
	int encrypted_final = 0;
	errCode = EVP_EncryptFinal_ex(ctx, cipher + encrypted_len, &encrypted_final);
	if (errCode != 1)
	{
		// 加密出错
		delete [] padding_plain_buffer;
		padding_plain_buffer = NULL;

		EVP_CIPHER_CTX_cleanup(ctx);
		return -4;
	}

	*cipher_len = encrypted_len + encrypted_final;

	delete [] padding_plain_buffer;
	padding_plain_buffer = NULL;

	EVP_CIPHER_CTX_cleanup(ctx);
	return errCode;
}

int GxxGmCrypto::AesDecryptData(const unsigned char *cipher, int cipher_len, unsigned char *plain, int *plain_len, const char *key, int key_len, const char *encrypt_mode, const char *iv, int iv_len)
{
	int errCode = 0;

	// 初始化加密上下文
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	// 初始化加密密钥、加密向量
	memcpy(key_, key, key_len > 16 ? 16 : key_len);
	memcpy(iv_, iv, iv_len > 16 ? 16 : iv_len);

	// 初始化加密模式
	if (_stricmp(encrypt_mode, "ECB_128") == 0)
		evp_cipher_ = EVP_aes_128_ecb();
	else if (_stricmp(encrypt_mode, "ECB_192") == 0)
		evp_cipher_ = EVP_aes_192_ecb();
	else if (_stricmp(encrypt_mode, "ECB_256") == 0)
		evp_cipher_ = EVP_aes_256_ecb();
	else if (_stricmp(encrypt_mode, "CBC_128") == 0)
		evp_cipher_ = EVP_aes_128_cbc();
	else if (_stricmp(encrypt_mode, "CBC_192") == 0)
		evp_cipher_ = EVP_aes_192_cbc();
	else if (_stricmp(encrypt_mode, "CBC_256") == 0)
		evp_cipher_ = EVP_aes_256_cbc();
	else if (_stricmp(encrypt_mode, "CFB_128") == 0)
		evp_cipher_ = EVP_aes_128_cfb();
	else if (_stricmp(encrypt_mode, "CFB_192") == 0)
		evp_cipher_ = EVP_aes_192_cfb();
	else if (_stricmp(encrypt_mode, "CFB_256") == 0)
		evp_cipher_ = EVP_aes_256_cfb();
	else if (_stricmp(encrypt_mode, "OFB_128") == 0)
		evp_cipher_ = EVP_aes_128_ofb();
	else if (_stricmp(encrypt_mode, "OFB_192") == 0)
		evp_cipher_ = EVP_aes_192_ofb();
	else if (_stricmp(encrypt_mode, "OFB_256") == 0)
		evp_cipher_ = EVP_aes_256_ofb();
	else
		evp_cipher_ = EVP_aes_128_ecb();

	// 

	EVP_CIPHER_CTX_cleanup(ctx);
	return errCode;
}