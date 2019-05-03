// libGxxGmCryptoDemo.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <iostream>
#include <string>
#include <Windows.h>

#include "../libGxxGmCrypto/GxxGmCrypto.h"

#pragma comment(lib, "libGxxGmCrypto.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")


int _tmain(int argc, _TCHAR* argv[])
{
	const char *plain = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ+-=";
	const char *key = (const char *)"1234567890123456";
	const char *iv = (const char *)"abcdefghijklmnop";

	int cipher_buffer_len = 4096;
	unsigned char cipher[4096] = {0};

	GxxGmCrypto crypto;
	int errCode = crypto.AesEncryptData((const unsigned char *)plain, strlen(plain), cipher, &cipher_buffer_len, key, 16, "CBC_128", iv, 16);

	int new_plain_buffer_len = 4096;
	unsigned char new_plain[4096] = {0};
	errCode = crypto.AesDecryptData(cipher, cipher_buffer_len, new_plain, &new_plain_buffer_len, key, 16, "CBC_128", iv, 16);

	if (memcmp(new_plain, plain, strlen(plain)) == 0)
		std::cout<<"加解密成功！"<<std::endl;
	else
		std::cout<<"加解密失败！"<<std::endl;

	//system("pause"):
	return 0;
}

