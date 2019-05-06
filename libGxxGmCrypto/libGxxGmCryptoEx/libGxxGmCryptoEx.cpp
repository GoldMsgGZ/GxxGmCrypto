#include "libGxxGmCryptoEx.h"
#include "Poco/Crypto/Cipher.h"
#include "Poco/Crypto/CipherFactory.h"
#include "Poco/Crypto/CipherKey.h"

libGxxGmCryptoEx::libGxxGmCryptoEx()
{

}

libGxxGmCryptoEx::~libGxxGmCryptoEx()
{

}

int libGxxGmCryptoEx::EncryptPin_v1(std::string pin, std::string &pin_cipher, const unsigned char *key, int key_len, std::string mode, const unsigned char *iv, int iv_len)
{
	int errCode = 0;
	std::string errstr;

	// 口令加密实现逻辑说明：
	// 口令加密数据由以下内容组成：
	// 随机数1 + 数据长度[口令密文长度] + AES128(口令, 密钥, 向量) + 随机数2 + AES128(密钥, 随机数1, 随机数2) + 随机数3

	return errCode;
}

int libGxxGmCryptoEx::DecryptPin_v1(std::string pin_cipher, std::string &pin)
{
	int errCode = 0;
	std::string errstr;

	return errCode;
}

int libGxxGmCryptoEx::Encrypt_v1(std::string plain, std::string &cipher, const unsigned char *key, int key_len, std::string mode, const unsigned char *iv, int iv_len)
{
	int errCode = 0;
	std::string errstr;

	try
	{
		// 先准备好密钥和向量
		Poco::Crypto::CipherKey::ByteVec key_vector(16);
		Poco::Crypto::CipherKey::ByteVec iv_vector(16);

		for (int index = 0; index < key_len; ++index)
			key_vector.push_back(key[index]);

		for (int index = 0; index < iv_len; ++index)
			iv_vector.push_back(iv[index]);


		Poco::Crypto::Cipher::Ptr ptr_cipher = Poco::Crypto::CipherFactory::defaultFactory().createCipher(Poco::Crypto::CipherKey(mode, key_vector, iv_vector));

		// 加密数据
		cipher = ptr_cipher->encryptString(plain, Poco::Crypto::Cipher::ENC_BASE64);
		//std::string cipher_tmp = ptr_cipher->encryptString(plain, Poco::Crypto::Cipher::ENC_BASE64);
		//cipher = cipher_tmp;
	}
	catch(Poco::Exception &e)
	{
		errCode = e.code();
		errstr = e.displayText();
	}
	

	return errCode;
}

int libGxxGmCryptoEx::Decrypt_v1(std::string cipher, std::string &plain, const unsigned char *key, int key_len, std::string mode, const unsigned char *iv, int iv_len)
{
	int errCode = 0;
	std::string errstr;

	try
	{
		// 先准备好密钥和向量
		Poco::Crypto::CipherKey::ByteVec key_vector(16);
		Poco::Crypto::CipherKey::ByteVec iv_vector(16);

		for (int index = 0; index < key_len; ++index)
			key_vector.push_back(key[index]);

		for (int index = 0; index < iv_len; ++index)
			iv_vector.push_back(iv[index]);


		Poco::Crypto::Cipher::Ptr ptr_cipher = Poco::Crypto::CipherFactory::defaultFactory().createCipher(Poco::Crypto::CipherKey(mode, key_vector, iv_vector));

		// 解密数据
		plain = ptr_cipher->decryptString(cipher, Poco::Crypto::Cipher::ENC_BASE64);
	}
	catch(Poco::Exception &e)
	{
		errCode = e.code();
		errstr = e.displayText();
	}

	return errCode;
}