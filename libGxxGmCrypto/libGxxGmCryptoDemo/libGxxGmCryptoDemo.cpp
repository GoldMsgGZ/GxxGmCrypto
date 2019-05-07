// libGxxGmCryptoDemo.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <iostream>
#include <string>
#include <Windows.h>

#include "../libGxxGmCryptoEx/libGxxGmCryptoEx.h"

#include "Poco/Crypto/PKCS12Container.h"
#include "Poco/Crypto/RSAKey.h"
#include "Poco/Crypto/Cipher.h"
#include "Poco/Crypto/CipherFactory.h"
#include "Poco/Crypto/CipherKey.h"

#pragma comment(lib, "libGxxGmCryptoEx.lib")
//#pragma comment(lib, "libcrypto.lib")
//#pragma comment(lib, "libssl.lib")


int _tmain(int argc, _TCHAR* argv[])
{
	// �����ܵ�����
	const char *plain = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ+-=";

	// ������Կ������Ӧ���������
	const unsigned char *key = (const unsigned char *)"1234567890123456";
	int key_len = strlen((const char *)key);

	// �������̶���Ҳ�����������
	const unsigned char *iv = (const unsigned char *)"abcdefghijklmnop";
	int iv_len = strlen((const char *)iv);

	libGxxGmCryptoEx crypto;

	// ��������
	std::string cipher;
	crypto.Encrypt_v1(plain, cipher, key, key_len, "aes-128-cbc", iv, iv_len);

	// ��ȡpfx�ļ�����˽Կ������Կ
	int errCode = 0;
	std::string errstr;
	try
	{
		const char *pfx_file = "Gosuncn-levam.pfx";
		Poco::Crypto::PKCS12Container pkcs12(pfx_file, "123456");
		Poco::Crypto::EVPPKey evpkey = pkcs12.getKey();

		Poco::Crypto::RSAKey *rsakey = new Poco::Crypto::RSAKey(evpkey);
		Poco::Crypto::Cipher::Ptr pCipher = Poco::Crypto::CipherFactory::defaultFactory().createCipher(*rsakey, RSA_PADDING_PKCS1);

		std::string protected_key = pCipher->encryptString((const char*)key, Poco::Crypto::Cipher::ENC_BASE64);
	}
	catch(Poco::Crypto::CryptoException &e)
	{
		errCode = e.code();
		errstr = e.displayText();
	}
	catch(Poco::Crypto::OpenSSLException &e)
	{
		errCode = e.code();
		errstr = e.displayText();
	}
	catch(Poco::Exception &e)
	{
		errCode = e.code();
		errstr = e.displayText();
	}

	std::string new_plain;
	crypto.Decrypt_v1(cipher, new_plain, key, key_len, "aes-128-cbc", iv, iv_len);

	//system("pause"):
	return 0;
}

