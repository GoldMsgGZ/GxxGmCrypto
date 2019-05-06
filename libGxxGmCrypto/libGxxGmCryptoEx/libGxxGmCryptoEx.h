#ifndef _libGxxGmCryptoEx_H_
#define _libGxxGmCryptoEx_H_

#include <string>

#ifdef LIBGXXGMCRYPTOEX_EXPORTS
#define DLL_API __declspec(dllexport)
#else
#define DLL_API __declspec(dllimport)
#endif

class DLL_API libGxxGmCryptoEx
{
public:
	libGxxGmCryptoEx();
	~libGxxGmCryptoEx();

public:
	int EncryptPin_v1(std::string pin, std::string &pin_cipher, const unsigned char *key, int key_len, std::string mode, const unsigned char *iv, int iv_len);
	int DecryptPin_v1(std::string pin_cipher, std::string &pin);

public:
	int Encrypt_v1(std::string plain, std::string &cipher, const unsigned char *key, int key_len, std::string mode, const unsigned char *iv, int iv_len);
	int Decrypt_v1(std::string cipher, std::string &plain, const unsigned char *key, int key_len, std::string mode, const unsigned char *iv, int iv_len);
};

#endif//_libGxxGmCryptoEx_H_
