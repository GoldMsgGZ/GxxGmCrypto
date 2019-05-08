#include "libGxxGmCryptoEx.h"
#include "Poco/Crypto/Cipher.h"
#include "Poco/Crypto/CipherFactory.h"
#include "Poco/Crypto/CipherKey.h"
#include "Poco/Crypto/PKCS12Container.h"
#include "Poco/Crypto/X509Certificate.h"
#include "Poco/Crypto/RSAKey.h"
#include "Poco/Random.h"
#include "Poco/Json/Object.h"
#include "Poco/Json/Array.h"

#include <iostream>
#include <sstream>
#include <fstream>

libGxxGmCryptoEx::libGxxGmCryptoEx()
{

}

libGxxGmCryptoEx::~libGxxGmCryptoEx()
{

}

int libGxxGmCryptoEx::EncryptPin_v1(std::string pin, std::string &pin_cipher, std::string pkcs12cert_path, std::string pkcs12cert_pin)
{
	int errCode = 0;
	std::string errstr;

	// 1.����16�ֽ��������4��������������ɣ���ΪAES-128-CBC����Կ
	Poco::Random random_generate;
	Poco::UInt32 random_factor_1 = random_generate.next();
	Poco::UInt32 random_factor_2 = random_generate.next();
	Poco::UInt32 random_factor_3 = random_generate.next();
	Poco::UInt32 random_factor_4 = random_generate.next();

	unsigned char key[16] = {0};
	memcpy(key,			&random_factor_1, sizeof(Poco::UInt32));
	memcpy(key + 4,		&random_factor_2, sizeof(Poco::UInt32));
	memcpy(key + 8,		&random_factor_3, sizeof(Poco::UInt32));
	memcpy(key + 12,	&random_factor_4, sizeof(Poco::UInt32));

	// 2.����16�ֽ��������4��������������ɣ���ΪAES-128-CBC������
	Poco::UInt32 random_factor_5 = random_generate.next();
	Poco::UInt32 random_factor_6 = random_generate.next();
	Poco::UInt32 random_factor_7 = random_generate.next();
	Poco::UInt32 random_factor_8 = random_generate.next();

	unsigned char iv[16] = {0};
	memcpy(iv,			&random_factor_5, sizeof(Poco::UInt32));
	memcpy(iv + 4,		&random_factor_6, sizeof(Poco::UInt32));
	memcpy(iv + 8,		&random_factor_7, sizeof(Poco::UInt32));
	memcpy(iv + 12,		&random_factor_8, sizeof(Poco::UInt32));

	// 3. ���ܿ���
	std::string original_pin_cipher;
	errCode = this->Encrypt_v1(pin, original_pin_cipher, key, 16, "aes-128-cbc", iv, 16);
	if (errCode != 0)
	{
		// ����ʧ��
		return -1;
	}

	// 4.������Կ
	std::string key_plain;
	key_plain.append((const char *)key, 16);
	std::string key_cipher;

	errCode = this->RsaEncryptWithPKCS12Cert_v1(key_plain, key_cipher, pkcs12cert_path, pkcs12cert_pin);
	if (errCode != 0)
	{
		// ����ʧ��
		return -1;
	}

	// 5. ��������
	std::string iv_plain;
	iv_plain.append((const char *)iv, 16);
	std::string iv_cipher;
	errCode = this->RsaEncryptWithPKCS12Cert_v1(iv_plain, iv_cipher, pkcs12cert_path, pkcs12cert_pin);
	if (errCode != 0)
	{
		// ����ʧ��
		return -1;
	}

	// 6. ������л��ֱ����л�����������>>>���ܿ���>>>����ģʽ>>>������Կ
	// ������һ�£��ͼ򵥴ֱ��Ĵ���ɣ���Jsonװ����Щ����

	// 7. ���л����Base64Encode

	return errCode;
}

int libGxxGmCryptoEx::DecryptPin_v1(std::string pin_cipher, std::string &pin)
{
	int errCode = 0;
	std::string errstr;

	// 1. Base64Decode������л����

	// 2. ��ȡ������ģʽ�����ܿ��������Կ����������

	// 3. 

	return errCode;
}

int libGxxGmCryptoEx::Encrypt_v1(std::string plain, std::string &cipher, const unsigned char *key, int key_len, std::string mode, const unsigned char *iv, int iv_len)
{
	int errCode = 0;
	std::string errstr;

	try
	{
		// ��׼������Կ������
		Poco::Crypto::CipherKey::ByteVec key_vector(16);
		Poco::Crypto::CipherKey::ByteVec iv_vector(16);

		for (int index = 0; index < key_len; ++index)
			key_vector.push_back(key[index]);

		for (int index = 0; index < iv_len; ++index)
			iv_vector.push_back(iv[index]);


		Poco::Crypto::Cipher::Ptr ptr_cipher = Poco::Crypto::CipherFactory::defaultFactory().createCipher(Poco::Crypto::CipherKey(mode, key_vector, iv_vector));

		// ��������
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
		// ��׼������Կ������
		Poco::Crypto::CipherKey::ByteVec key_vector(16);
		Poco::Crypto::CipherKey::ByteVec iv_vector(16);

		for (int index = 0; index < key_len; ++index)
			key_vector.push_back(key[index]);

		for (int index = 0; index < iv_len; ++index)
			iv_vector.push_back(iv[index]);


		Poco::Crypto::Cipher::Ptr ptr_cipher = Poco::Crypto::CipherFactory::defaultFactory().createCipher(Poco::Crypto::CipherKey(mode, key_vector, iv_vector));

		// ��������
		plain = ptr_cipher->decryptString(cipher, Poco::Crypto::Cipher::ENC_BASE64);
	}
	catch(Poco::Exception &e)
	{
		errCode = e.code();
		errstr = e.displayText();
	}

	return errCode;
}

int libGxxGmCryptoEx::RsaEncryptWithPKCS12Cert_v1(std::string plain, std::string &cipher, std::string pkcs12cert_path, std::string pkcs12cert_pin)
{
	int errCode = 0;
	std::string errstr;

	try
	{
		// ����PKCS12֤��
		std::ifstream ifs(pkcs12cert_path.c_str(), std::ios::binary);
		Poco::Crypto::PKCS12Container pkcs12(ifs, pkcs12cert_pin);

		// �����õ�������Կ�ԣ���˽Կ����
		Poco::Crypto::EVPPKey evpkey = pkcs12.getKey();

		// ��ʼ��RSA��Կ������ʱ����PKCS1���
		Poco::Crypto::RSAKey *rsakey = new Poco::Crypto::RSAKey(evpkey);
		Poco::Crypto::Cipher::Ptr pCipher = Poco::Crypto::CipherFactory::defaultFactory().createCipher(*rsakey, RSA_PADDING_PKCS1);

		cipher = pCipher->encryptString(plain, Poco::Crypto::Cipher::ENC_BASE64);
	}
	catch(Poco::Crypto::CryptoException &e)
	{
		errCode = e.code();
		errstr = e.displayText();
	}
	catch(Poco::Exception &e)
	{
		errCode = e.code();
		errstr = e.displayText();
	}

	return errCode;
}

int libGxxGmCryptoEx::RsaEncryptWithX509Cert_v1(std::string plain, std::string &cipher, std::string x509cert_path)
{
	int errCode = 0;
	std::string errstr;

	try
	{
		// ����X509֤��
		//std::ifstream ifs(x509cert_path.c_str(), std::ios::binary);
		//Poco::Crypto::X509Certificate x509(ifs);
		Poco::Crypto::X509Certificate x509(x509cert_path);

		// ��ʼ��RSA��Կ������ֻ�й�Կ
		Poco::Crypto::RSAKey *rsakey = new Poco::Crypto::RSAKey(x509);
		Poco::Crypto::Cipher::Ptr pCipher = Poco::Crypto::CipherFactory::defaultFactory().createCipher(*rsakey, RSA_PADDING_PKCS1);

		cipher = pCipher->encryptString(plain, Poco::Crypto::Cipher::ENC_BASE64);
	}
	catch(Poco::Crypto::CryptoException &e)
	{
		errCode = e.code();
		errstr = e.displayText();
	}
	catch(Poco::Exception &e)
	{
		errCode = e.code();
		errstr = e.displayText();
	}

	return errCode;
}

int libGxxGmCryptoEx::RsaDecryptWithPKCS12Cert_v1(std::string cipher, std::string &plain, std::string pkcs12cert_path, std::string pkcs12cert_pin)
{
	int errCode = 0;
	std::string errstr;

	try
	{
		// ����PKCS12֤��
		std::ifstream ifs(pkcs12cert_path.c_str(), std::ios::binary);
		Poco::Crypto::PKCS12Container pkcs12(ifs, pkcs12cert_pin);

		// �����õ�������Կ�ԣ���˽Կ����
		Poco::Crypto::EVPPKey evpkey = pkcs12.getKey();

		// ��ʼ��RSA��Կ������ʱ����PKCS1���
		Poco::Crypto::RSAKey *rsakey = new Poco::Crypto::RSAKey(evpkey);
		Poco::Crypto::Cipher::Ptr pCipher = Poco::Crypto::CipherFactory::defaultFactory().createCipher(*rsakey, RSA_PADDING_PKCS1);

		plain = pCipher->decryptString(cipher, Poco::Crypto::Cipher::ENC_BASE64);
	}
	catch(Poco::Crypto::CryptoException &e)
	{
		errCode = e.code();
		errstr = e.displayText();
	}
	catch(Poco::Exception &e)
	{
		errCode = e.code();
		errstr = e.displayText();
	}

	return errCode;
}