#include "GxxGmCrypto.h"
#include <string>

// https://blog.csdn.net/yygydjkthh/article/details/18666357#

GxxGmCrypto::GxxGmCrypto()
{
	// 加载OpenSSL的全部算法
	OpenSSL_add_all_algorithms();
}

GxxGmCrypto::~GxxGmCrypto()
{

}

int GxxGmCrypto::AesInitialize()
{
	int errCode = 0;

	// 初始化加密上下文
	EVP_CIPHER_CTX_init(&ctx);

	return errCode;
}

int GxxGmCrypto::AesEncryptData(const char *plain, int plain_len, char *cipher, int *cipher_len)
{
	int errCode = 0;

	return errCode;
}

int GxxGmCrypto::AesDecryptData(const char *cipher, int cipher_len, char *plain, int *plain_len)
{
	int errCode = 0;

	return errCode;
}