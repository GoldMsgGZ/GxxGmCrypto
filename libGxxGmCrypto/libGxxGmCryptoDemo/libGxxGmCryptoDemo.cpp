// libGxxGmCryptoDemo.cpp : 定义控制台应用程序的入口点。
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
	// 待加密的数据
	const char *plain = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ+-=";

	// 加密密钥，这里应该随机生成
	const unsigned char *key = (const unsigned char *)"1234567890123456";
	int key_len = strlen((const char *)key);

	// 向量，固定，也可以随机生成
	const unsigned char *iv = (const unsigned char *)"abcdefghijklmnop";
	int iv_len = strlen((const char *)iv);

	libGxxGmCryptoEx crypto;

	// 加密明文
	std::string cipher;
	crypto.Encrypt_v1(plain, cipher, key, key_len, "aes-128-cbc", iv, iv_len);

	// 读取pfx文件，用私钥加密密钥
	const char *pfx_file = "LEVAM.pfx";

	std::string new_plain;
	crypto.Decrypt_v1(cipher, new_plain, key, key_len, "aes-128-cbc", iv, iv_len);

	//system("pause"):
	return 0;
}

