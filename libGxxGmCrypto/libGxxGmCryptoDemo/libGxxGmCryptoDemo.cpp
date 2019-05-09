// libGxxGmCryptoDemo.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <Windows.h>

#include "../libGxxGmCryptoEx/libGxxGmCryptoEx.h"


#pragma comment(lib, "libGxxGmCryptoEx.lib")

void TestInterface()
{
	int errCode = 0;
	std::string errstr;

	// 待加密的数据
	const char *plain = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ+-=";

	// 加密密钥，这里应该随机生成
	const unsigned char *key = (const unsigned char *)"1234567890123456";
	int key_len = strlen((const char *)key);

	// 向量，固定，也可以随机生成
	const unsigned char *iv = (const unsigned char *)"abcdefghijklmnop";
	int iv_len = strlen((const char *)iv);

	libGxxGmCryptoEx crypto;


	//////////////////////////////////////////////////////////////////////////
	//
	// 对称加解密
	//
	//////////////////////////////////////////////////////////////////////////

	// 加密明文
	std::string cipher;
	crypto.Encrypt_v1(plain, cipher, key, key_len, "aes-128-cbc", iv, iv_len);

	// 解密明文
	std::string new_plain;
	crypto.Decrypt_v1(cipher, new_plain, key, key_len, "aes-128-cbc", iv, iv_len);

	if (new_plain.compare(plain) == 0)
		std::cout<<"对称加解密成功！"<<std::endl;
	else
		std::cout<<"对称加解密失败！"<<std::endl;

	//////////////////////////////////////////////////////////////////////////
	//
	// 非对称加密
	//
	//////////////////////////////////////////////////////////////////////////

	const char *pkcs12cert_path = "TestCert.pfx";
	const char *pkcs12cert_pin = "123456";

	const char *x509cert_path = "TestCert.cer";

	// 使用PKCS12证书加密
	std::string pkcs12_cipher;
	errCode = crypto.RsaEncryptWithPKCS12Cert_v1(plain, pkcs12_cipher, pkcs12cert_path, pkcs12cert_pin);

	//// 使用X509证书加密
	//std::string x509_cipher;
	//errCode = crypto.RsaEncryptWithX509Cert_v1(plain, x509_cipher, x509cert_path);

	//if (pkcs12_cipher.compare(x509_cipher) == 0)
	//	std::cout<<"RSA加密成功！"<<std::endl;
	//else
	//	std::cout<<"RSA加密失败！"<<std::endl;

	// 使用PKCS12证书解密
	std::string rsa_plain;
	errCode = crypto.RsaDecryptWithPKCS12Cert_v1(pkcs12_cipher, rsa_plain, pkcs12cert_path, pkcs12cert_pin);

	if (rsa_plain.compare(plain) == 0)
		std::cout<<"RSA加解密成功！"<<std::endl;
	else
		std::cout<<"RSA加解密失败！"<<std::endl;
}

void TestPinProtect()
{
	// 首先，生成受保护的Pin
	const char *pin = "12345";
	const char *pkcs12cert_path = "TestCert.pfx";
	const char *pkcs12cert_pin = "123456";

	std::string pin_cipher;
	libGxxGmCryptoEx crypto;
	crypto.EncryptPin_v1(pin, pin_cipher, pkcs12cert_path, pkcs12cert_pin);

	std::string pin_plain;
	crypto.DecryptPin_v1(pin_cipher, pin_plain, pkcs12cert_path, pkcs12cert_pin);

	if (pin_plain.compare(pin) == 0)
		std::cout<<"pin码保护成功！"<<std::endl;
	else
		std::cout<<"pin码保护失败！"<<std::endl;
}


int _tmain(int argc, _TCHAR* argv[])
{
	int errCode = 0;
	std::string errstr;

	TestPinProtect();

	//system("pause"):
	return 0;
}

