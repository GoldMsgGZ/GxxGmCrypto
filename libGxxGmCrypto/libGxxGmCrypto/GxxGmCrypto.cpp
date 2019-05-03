#include "GxxGmCrypto.h"
#include <string>

#define BLOCK_SIZE	8

// https://blog.csdn.net/yygydjkthh/article/details/18666357#

GxxGmCrypto::GxxGmCrypto()
{
	// ����OpenSSL��ȫ���㷨
	OpenSSL_add_all_algorithms();

	
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

	unsigned char key_[EVP_MAX_KEY_LENGHT] = {0};
	unsigned char iv_[EVP_MAX_KEY_LENGHT] = {0};
	const EVP_CIPHER *evp_cipher_ = NULL;

	memset(key_, 0, EVP_MAX_KEY_LENGHT);
	memset(iv_, 0, EVP_MAX_KEY_LENGHT);

	// ���ݷ��飬����PKCS#7��PKCS7Padding����䣬���СΪ16�ֽ�
	// ��ô������Ҫ�������ĳ��ȣ����ϳ�������Ҫ���ܵ����ݶ��䳤�ȣ����ҽ���PKCS#7���
	int block_count = plain_len / BLOCK_SIZE + 1;
	int plain_block_tail_len = plain_len % BLOCK_SIZE;
	int padding_size = BLOCK_SIZE - plain_block_tail_len;
	int padding_plain_buffer_len = BLOCK_SIZE * block_count;

	// �ж����Ļ����������Ƿ��㹻�������򷵻�
	if (*cipher_len < padding_plain_buffer_len)
	{
		*cipher_len = padding_plain_buffer_len;
		return -2;
	}

	// ��ʼ������������
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	// ��ʼ��������Կ����������
	memcpy(key_, key, key_len > 16 ? 16 : key_len);
	memcpy(iv_, iv, iv_len > 16 ? 16 : iv_len);

	// ��ʼ������ģʽ
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


	// ��ʼ��AES���ܻ���
	errCode = EVP_EncryptInit_ex(ctx, evp_cipher_, NULL, key_, iv_);
	if (errCode != 1)
	{
		// ��ʼ������
		EVP_CIPHER_CTX_cleanup(ctx);
		return -1;
	}

	// ������仺���������е�Ԫ���Ϊ����ֽ�����Ȼ�����ĸ��Ƶ�������
	unsigned char *padding_plain_buffer = new unsigned char[padding_plain_buffer_len];
	memset(padding_plain_buffer, padding_size, padding_plain_buffer_len);
	memcpy(padding_plain_buffer, plain, plain_len);

	// ����
	int encrypted_len = 0;
	errCode = EVP_EncryptUpdate(ctx, cipher, &encrypted_len, padding_plain_buffer, padding_plain_buffer_len);
	if (errCode != 1)
	{
		// ���ܳ���
		delete [] padding_plain_buffer;
		padding_plain_buffer = NULL;

		EVP_CIPHER_CTX_cleanup(ctx);
		return -3;
	}

	// �������Ľ��
	int encrypted_final = 0;
	errCode = EVP_EncryptFinal_ex(ctx, cipher + encrypted_len, &encrypted_final);
	if (errCode != 1)
	{
		// ���ܳ���
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

	unsigned char key_[EVP_MAX_KEY_LENGHT] = {0};
	unsigned char iv_[EVP_MAX_KEY_LENGHT] = {0};
	const EVP_CIPHER *evp_cipher_ = NULL;

	memset(key_, 0, EVP_MAX_KEY_LENGHT);
	memset(iv_, 0, EVP_MAX_KEY_LENGHT);

	// ��ʼ������������
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	// ��ʼ��������Կ����������
	memcpy(key_, key, key_len > 16 ? 16 : key_len);
	memcpy(iv_, iv, iv_len > 16 ? 16 : iv_len);

	// ��ʼ������ģʽ
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

	// ��ʼ�����ܻ���
	errCode = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key_, iv_);
	if (errCode != 1)
	{
		return -1;
	}

	// Ԥ�����������Ļ�������С
	int align_plain_buffer_len = cipher_len;
	unsigned char *align_plain_buffer = new unsigned char[align_plain_buffer_len];

	int decrypted_len = 0;
	errCode = EVP_DecryptUpdate(ctx, align_plain_buffer, &decrypted_len, cipher, cipher_len);
	if (errCode != 1)
	{
		return -2;
	}

	// �������һ��������
	int decrypted_final = 0;
	errCode = EVP_DecryptFinal_ex(ctx, align_plain_buffer + decrypted_len, &decrypted_final);
	if (errCode != 1)
	{
		return -3;
	}

	int new_plain_len = decrypted_len + decrypted_final;

	// ������һ���ֽڣ�Ȼ�󿽱���
	int padding_len = align_plain_buffer[new_plain_len - 1];
	int data_len = new_plain_len - padding_len;

	if (*plain_len < data_len)
	{
		return -4;
	}

	memcpy(plain, align_plain_buffer, data_len);
	*plain_len = data_len;

	EVP_CIPHER_CTX_cleanup(ctx);
	return errCode;
}