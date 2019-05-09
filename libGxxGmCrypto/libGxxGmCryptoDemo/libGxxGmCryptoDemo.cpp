// libGxxGmCryptoDemo.cpp : �������̨Ӧ�ó������ڵ㡣
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

	// �����ܵ�����
	const char *plain = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ+-=";

	// ������Կ������Ӧ���������
	const unsigned char *key = (const unsigned char *)"1234567890123456";
	int key_len = strlen((const char *)key);

	// �������̶���Ҳ�����������
	const unsigned char *iv = (const unsigned char *)"abcdefghijklmnop";
	int iv_len = strlen((const char *)iv);

	libGxxGmCryptoEx crypto;


	//////////////////////////////////////////////////////////////////////////
	//
	// �ԳƼӽ���
	//
	//////////////////////////////////////////////////////////////////////////

	// ��������
	std::string cipher;
	crypto.Encrypt_v1(plain, cipher, key, key_len, "aes-128-cbc", iv, iv_len);

	// ��������
	std::string new_plain;
	crypto.Decrypt_v1(cipher, new_plain, key, key_len, "aes-128-cbc", iv, iv_len);

	if (new_plain.compare(plain) == 0)
		std::cout<<"�ԳƼӽ��ܳɹ���"<<std::endl;
	else
		std::cout<<"�ԳƼӽ���ʧ�ܣ�"<<std::endl;

	//////////////////////////////////////////////////////////////////////////
	//
	// �ǶԳƼ���
	//
	//////////////////////////////////////////////////////////////////////////

	const char *pkcs12cert_path = "TestCert.pfx";
	const char *pkcs12cert_pin = "123456";

	const char *x509cert_path = "TestCert.cer";

	// ʹ��PKCS12֤�����
	std::string pkcs12_cipher;
	errCode = crypto.RsaEncryptWithPKCS12Cert_v1(plain, pkcs12_cipher, pkcs12cert_path, pkcs12cert_pin);

	//// ʹ��X509֤�����
	//std::string x509_cipher;
	//errCode = crypto.RsaEncryptWithX509Cert_v1(plain, x509_cipher, x509cert_path);

	//if (pkcs12_cipher.compare(x509_cipher) == 0)
	//	std::cout<<"RSA���ܳɹ���"<<std::endl;
	//else
	//	std::cout<<"RSA����ʧ�ܣ�"<<std::endl;

	// ʹ��PKCS12֤�����
	std::string rsa_plain;
	errCode = crypto.RsaDecryptWithPKCS12Cert_v1(pkcs12_cipher, rsa_plain, pkcs12cert_path, pkcs12cert_pin);

	if (rsa_plain.compare(plain) == 0)
		std::cout<<"RSA�ӽ��ܳɹ���"<<std::endl;
	else
		std::cout<<"RSA�ӽ���ʧ�ܣ�"<<std::endl;
}

void TestPinProtect()
{
	// ���ȣ������ܱ�����Pin
	const char *pin = "12345";
	const char *pkcs12cert_path = "TestCert.pfx";
	const char *pkcs12cert_pin = "123456";

	std::string pin_cipher;
	libGxxGmCryptoEx crypto;
	crypto.EncryptPin_v1(pin, pin_cipher, pkcs12cert_path, pkcs12cert_pin);

	std::string pin_plain;
	crypto.DecryptPin_v1(pin_cipher, pin_plain, pkcs12cert_path, pkcs12cert_pin);

	if (pin_plain.compare(pin) == 0)
		std::cout<<"pin�뱣���ɹ���"<<std::endl;
	else
		std::cout<<"pin�뱣��ʧ�ܣ�"<<std::endl;
}


int _tmain(int argc, _TCHAR* argv[])
{
	int errCode = 0;
	std::string errstr;

	TestPinProtect();

	//system("pause"):
	return 0;
}

