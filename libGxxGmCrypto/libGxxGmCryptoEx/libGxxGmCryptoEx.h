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
	 * ͨ��pin����ܽӿڣ��˰汾��δ֧��
	 */
	int EncryptPin_v1(std::string pin, std::string &pin_cipher, std::string pkcs12cert_path, std::string pkcs12cert_pin);
	int DecryptPin_v1(std::string pin_cipher, std::string &pin, std::string pkcs12cert_path, std::string pkcs12cert_pin);

public:
	/**
	 * �ԳƼ����㷨
	 * ������
	 *	@plain		[����] ��������
	 *	@cipher		[���] ��������
	 *	@key		[����] ��Կ
	 *	@key_len	[����] ��Կ����
	 *	@mode		[����] ����ģʽ�������ʽ��[�㷨]-[λ��]-[ģʽ]���磺"aes-128-cbc"��
						   �㷨�Ƽ���aes/des
						   λ������д128/192/256����Ӧ����Կ����Ϊ16B/24B/32B
						   ģʽ����ecb/cbc/cfb/ofb���Ƽ�cbc
	 *	@iv			[����] ����
	 *	@iv_len		[����] �������ȣ���������Կһ��
	 */
	int Encrypt_v1(std::string plain, std::string &cipher, const unsigned char *key, int key_len, std::string mode, const unsigned char *iv, int iv_len);

	/**
	 * �Գƽ����㷨
	 * ������
	 *	@cipher		[����] ��������
	 *	@plain		[���] ��������
	 *	@key		[����] ��Կ
	 *	@key_len	[����] ��Կ����
	 *	@mode		[����] ����ģʽ�������ʽ��[�㷨]-[λ��]-[ģʽ]���磺"aes-128-cbc"��
						   �㷨�Ƽ���aes/des
						   λ������д128/192/256����Ӧ����Կ����Ϊ16B/24B/32B
						   ģʽ����ecb/cbc/cfb/ofb���Ƽ�cbc
	 *	@iv			[����] ����
	 *	@iv_len		[����] �������ȣ���������Կһ��
	 */
	int Decrypt_v1(std::string cipher, std::string &plain, const unsigned char *key, int key_len, std::string mode, const unsigned char *iv, int iv_len);

public:
	/**
	 * ʹ��PKCS12֤�飨˽Կ֤�飬�п������֤��ɸ���������RSA����
	 * ������
	 *	@plain				[����] ����
	 *	@cipher				[���] ����
	 *	@pkcs12cert_path	[����] PKCS12˽Կ֤��·��
	 *	@pkcs12cert_pin		[����] PKCS12˽Կ֤�����
	 */
	int RsaEncryptWithPKCS12Cert_v1(std::string plain, std::string &cipher, std::string pkcs12cert_path, std::string pkcs12cert_pin);

	/**
	 * ʹ��X509֤�����RSA���ܣ������ṩ��X509֤�������PEM��ʽ�ģ�������DER��ʽ
	 * ������
	 *	@plain				[����] ����
	 *	@cipher				[���] ����
	 *	@x509cert_path		[����] X509֤��·��
	 */
	int RsaEncryptWithX509Cert_v1(std::string plain, std::string &cipher, std::string x509cert_path);

	/**
	 * ʹ��PKCS12֤�����RSA����
	 */
	int RsaDecryptWithPKCS12Cert_v1(std::string cipher, std::string &plain, std::string pkcs12cert_path, std::string pkcs12cert_pin);
};

#endif//_libGxxGmCryptoEx_H_
