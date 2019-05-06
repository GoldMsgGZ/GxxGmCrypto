// libGxxGmCryptoDemo.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <iostream>
#include <string>
#include <Windows.h>

#include "../libGxxGmCryptoEx/libGxxGmCryptoEx.h"

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
	const char *pfx_file = "LEVAM.pfx";

	std::string new_plain;
	crypto.Decrypt_v1(cipher, new_plain, key, key_len, "aes-128-cbc", iv, iv_len);

	//system("pause"):
	return 0;
}

