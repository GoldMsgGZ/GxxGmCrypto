#ifndef _libGxxGmCryptoEx_H_
#define _libGxxGmCryptoEx_H_

#include <string>

#define DLL_VERSION		"1.0.0.1"

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
	/**
	 * 通用pin码加密接口，此版本暂未支持
	 */
	int EncryptPin_v1(std::string pin, std::string &pin_cipher, std::string pkcs12cert_path, std::string pkcs12cert_pin);
	int DecryptPin_v1(std::string pin_cipher, std::string &pin, std::string pkcs12cert_path, std::string pkcs12cert_pin);

public:
	/**
	 * 对称加密算法
	 * 参数：
	 *	@plain		[输入] 明文数据
	 *	@cipher		[输出] 密文数据
	 *	@key		[输入] 密钥
	 *	@key_len	[输入] 密钥长度
	 *	@mode		[输入] 加密模式：可填格式：[算法]-[位数]-[模式]，如："aes-128-cbc"；
						   算法推荐：aes/des
						   位数可填写128/192/256，对应的密钥长度为16B/24B/32B
						   模式可填ecb/cbc/cfb/ofb，推荐cbc
	 *	@iv			[输入] 向量
	 *	@iv_len		[输入] 向量长度，长度与密钥一致
	 */
	int Encrypt_v1(std::string plain, std::string &cipher, const unsigned char *key, int key_len, std::string mode, const unsigned char *iv, int iv_len);

	/**
	 * 对称解密算法
	 * 参数：
	 *	@cipher		[输入] 密文数据
	 *	@plain		[输出] 名文数据
	 *	@key		[输入] 密钥
	 *	@key_len	[输入] 密钥长度
	 *	@mode		[输入] 加密模式：可填格式：[算法]-[位数]-[模式]，如："aes-128-cbc"；
						   算法推荐：aes/des
						   位数可填写128/192/256，对应的密钥长度为16B/24B/32B
						   模式可填ecb/cbc/cfb/ofb，推荐cbc
	 *	@iv			[输入] 向量
	 *	@iv_len		[输入] 向量长度，长度与密钥一致
	 */
	int Decrypt_v1(std::string cipher, std::string &plain, const unsigned char *key, int key_len, std::string mode, const unsigned char *iv, int iv_len);

public:
	/**
	 * 使用PKCS12证书（私钥证书，有口令保护，证书可更换）进行RSA加密
	 * 参数：
	 *	@plain				[输入] 明文
	 *	@cipher				[输出] 密文
	 *	@pkcs12cert_path	[输入] PKCS12私钥证书路径
	 *	@pkcs12cert_pin		[输入] PKCS12私钥证书口令
	 */
	int RsaEncryptWithPKCS12Cert_v1(std::string plain, std::string &cipher, std::string pkcs12cert_path, std::string pkcs12cert_pin);

	/**
	 * 使用X509证书进行RSA加密，这里提供的X509证书必须是PEM格式的，不能是DER格式
	 * 参数：
	 *	@plain				[输入] 明文
	 *	@cipher				[输出] 密文
	 *	@x509cert_path		[输入] X509证书路径
	 */
	int RsaEncryptWithX509Cert_v1(std::string plain, std::string &cipher, std::string x509cert_path);

	/**
	 * 使用PKCS12证书进行RSA解密
	 */
	int RsaDecryptWithPKCS12Cert_v1(std::string cipher, std::string &plain, std::string pkcs12cert_path, std::string pkcs12cert_pin);
};

#endif//_libGxxGmCryptoEx_H_
