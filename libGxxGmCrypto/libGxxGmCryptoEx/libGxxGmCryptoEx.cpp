#include "libGxxGmCryptoEx.h"
#include "Poco/Crypto/Cipher.h"
#include "Poco/Crypto/CipherFactory.h"
#include "Poco/Crypto/CipherKey.h"
#include "Poco/Crypto/PKCS12Container.h"
#include "Poco/Crypto/X509Certificate.h"
#include "Poco/Crypto/RSAKey.h"
#include "Poco/JSON/Object.h"
#include "Poco/JSON/Parser.h"
#include "Poco/Base64Encoder.h"
#include "Poco/Base64Decoder.h"
#include "Poco/Random.h"


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

	// 1.生成16字节随机数，4个整形随机数即可，作为AES-128-CBC的密钥
	Poco::Random random_generate;
	unsigned char key[16] = {0};

	try {
		Poco::UInt32 random_factor_1 = random_generate.next();
		Poco::UInt32 random_factor_2 = random_generate.next();
		Poco::UInt32 random_factor_3 = random_generate.next();
		Poco::UInt32 random_factor_4 = random_generate.next();

		memcpy(key,			&random_factor_1, sizeof(Poco::UInt32));
		memcpy(key + 4,		&random_factor_2, sizeof(Poco::UInt32));
		memcpy(key + 8,		&random_factor_3, sizeof(Poco::UInt32));
		memcpy(key + 12,	&random_factor_4, sizeof(Poco::UInt32));
	} 
	catch (Poco::Exception &e)
	{
		errCode = -1;
		errstr = e.displayText();
		return errCode;
	}
	

	
	

	// 2.生成16字节随机数，4个整形随机数即可，作为AES-128-CBC的向量
	unsigned char iv[16] = {0};
	try {
		Poco::UInt32 random_factor_5 = random_generate.next();
		Poco::UInt32 random_factor_6 = random_generate.next();
		Poco::UInt32 random_factor_7 = random_generate.next();
		Poco::UInt32 random_factor_8 = random_generate.next();
		
		memcpy(iv,			&random_factor_5, sizeof(Poco::UInt32));
		memcpy(iv + 4,		&random_factor_6, sizeof(Poco::UInt32));
		memcpy(iv + 8,		&random_factor_7, sizeof(Poco::UInt32));
		memcpy(iv + 12,		&random_factor_8, sizeof(Poco::UInt32));
	}
	catch (Poco::Exception &e)
	{
		errCode = -2;
		errstr = e.displayText();
		return errCode;
	}

	// 3. 加密口令
	std::string original_pin_cipher;
	errCode = this->Encrypt_v1(pin, original_pin_cipher, key, 16, "aes-128-cbc", iv, 16);
	if (errCode != 0)
	{
		// 加密失败
		return -3;
	}

	// 4.加密密钥
	std::string key_plain;
	key_plain.append((const char *)key, 16);
	std::string key_cipher;

	errCode = this->RsaEncryptWithPKCS12Cert_v1(key_plain, key_cipher, pkcs12cert_path, pkcs12cert_pin);
	if (errCode != 0)
	{
		// 加密失败
		return -4;
	}

	// 5. 加密加密模式
	std::string mode_plain = "aes-128-cbc";
	std::string mode_cipher;

	errCode = this->RsaEncryptWithPKCS12Cert_v1(mode_plain, mode_cipher, pkcs12cert_path, pkcs12cert_pin);
	if (errCode != 0)
	{
		// 加密失败
		return -5;
	}

	// 6. 加密向量
	std::string iv_plain;
	iv_plain.append((const char *)iv, 16);
	std::string iv_cipher;
	errCode = this->RsaEncryptWithPKCS12Cert_v1(iv_plain, iv_cipher, pkcs12cert_path, pkcs12cert_pin);
	if (errCode != 0)
	{
		// 加密失败
		return -6;
	}

	// 7. 结果序列化分别序列化：加密向量>>>加密口令>>>加密模式>>>加密密钥
	// 纠结了一下，就简单粗暴的处理吧，用Json装载这些数据
	std::string json_str;
	try {
		Poco::JSON::Object json_obj;
		json_obj.set("parameter1", iv_cipher);
		json_obj.set("parameter2", key_cipher);
		json_obj.set("parameter3", mode_cipher);
		json_obj.set("parameter4", original_pin_cipher);

		std::stringstream json_stream;
		json_obj.stringify(json_stream, 0);
		json_str = json_stream.str();
	}
	catch (Poco::JSON::JSONException &e)
	{
		errCode = -7;
		errstr = e.displayText();
		return errCode;
	}

	// 7. 序列化结果Base64Encode
	try {
		std::ostringstream base64_stringstream;
		Poco::Base64Encoder base64encoder(base64_stringstream);
		base64encoder<<json_str;
		base64encoder.close();
		pin_cipher = base64_stringstream.str();
	}
	catch (Poco::Exception &e)
	{
		errCode = -8;
		errstr = e.displayText();
		return errCode;
	}

	return 0;
}

int libGxxGmCryptoEx::DecryptPin_v1(std::string pin_cipher, std::string &pin, std::string pkcs12cert_path, std::string pkcs12cert_pin)
{
	int errCode = 0;
	std::string errstr;

	// 1. Base64Decode解出序列化结果
	std::string json_str;
	try {
		std::istringstream base64_stringstream(pin_cipher);
		Poco::Base64Decoder base64decoder(base64_stringstream);
		if (!base64decoder.good())
			return -1;

		base64decoder>>json_str;
	}
	catch (Poco::Exception &e)
	{
		errCode = -2;
		errstr = e.displayText();
		return errCode;
	}
	

	// 2. 提取出加密模式、加密口令、加密密钥、加密向量
	std::string iv_cipher;
	std::string key_cipher;
	std::string mode_cipher;
	std::string original_pin_cipher;

	try {
		Poco::JSON::Parser json_parser;
		Poco::Dynamic::Var json_var = json_parser.parse(json_str);
		Poco::JSON::Object::Ptr json_obj_ptr = json_var.extract<Poco::JSON::Object::Ptr>();
		iv_cipher			= json_obj_ptr->get("parameter1").toString();
		key_cipher			= json_obj_ptr->get("parameter2").toString();
		mode_cipher			= json_obj_ptr->get("parameter3").toString();
		original_pin_cipher = json_obj_ptr->get("parameter4").toString();
	}
	catch (Poco::JSON::JSONException &e)
	{
		errCode = -3;
		errstr = e.displayText();
		return errCode;
	}
	

	// 3. 解密随机向量
	std::string iv_plain;
	errCode = this->RsaDecryptWithPKCS12Cert_v1(iv_cipher, iv_plain, pkcs12cert_path, pkcs12cert_pin);
	if (errCode != 0)
	{
		return -4;
	}

	// 4. 解密随机密钥
	std::string key_plain;
	errCode = this->RsaDecryptWithPKCS12Cert_v1(key_cipher, key_plain, pkcs12cert_path, pkcs12cert_pin);
	if (errCode != 0)
	{
		return -5;
	}

	// 5. 解密加密模式
	std::string mode_plain;
	errCode = this->RsaDecryptWithPKCS12Cert_v1(mode_cipher, mode_plain, pkcs12cert_path, pkcs12cert_pin);
	if (errCode != 0)
	{
		return -6;
	}

	// 6. 解密口令
	errCode = this->Decrypt_v1(original_pin_cipher, pin, (const unsigned char *)key_plain.data(), key_plain.size(), mode_plain, (const unsigned char *)iv_plain.data(), iv_plain.size());
	if (errCode != 0)
	{
		return -7;
	}

	return 0;
}

int libGxxGmCryptoEx::Encrypt_v1(std::string plain, std::string &cipher, const unsigned char *key, int key_len, std::string mode, const unsigned char *iv, int iv_len)
{
	int errCode = 0;
	std::string errstr;

	try
	{
		// 先准备好密钥和向量
		Poco::Crypto::CipherKey::ByteVec key_vector(16);
		Poco::Crypto::CipherKey::ByteVec iv_vector(16);

		for (int index = 0; index < key_len; ++index)
			key_vector.push_back(key[index]);

		for (int index = 0; index < iv_len; ++index)
			iv_vector.push_back(iv[index]);


		Poco::Crypto::Cipher::Ptr ptr_cipher = Poco::Crypto::CipherFactory::defaultFactory().createCipher(Poco::Crypto::CipherKey(mode, key_vector, iv_vector));

		// 加密数据
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
		// 先准备好密钥和向量
		Poco::Crypto::CipherKey::ByteVec key_vector(16);
		Poco::Crypto::CipherKey::ByteVec iv_vector(16);

		for (int index = 0; index < key_len; ++index)
			key_vector.push_back(key[index]);

		for (int index = 0; index < iv_len; ++index)
			iv_vector.push_back(iv[index]);


		Poco::Crypto::Cipher::Ptr ptr_cipher = Poco::Crypto::CipherFactory::defaultFactory().createCipher(Poco::Crypto::CipherKey(mode, key_vector, iv_vector));

		// 解密数据
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
		// 解析PKCS12证书
		std::ifstream ifs(pkcs12cert_path.c_str(), std::ios::binary);
		Poco::Crypto::PKCS12Container pkcs12(ifs, pkcs12cert_pin);

		// 这里拿到的是密钥对，公私钥都有
		Poco::Crypto::EVPPKey evpkey = pkcs12.getKey();

		// 初始化RSA密钥，加密时采用PKCS1填充
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
		// 解析X509证书
		//std::ifstream ifs(x509cert_path.c_str(), std::ios::binary);
		//Poco::Crypto::X509Certificate x509(ifs);
		Poco::Crypto::X509Certificate x509(x509cert_path);

		// 初始化RSA密钥，这里只有公钥
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
		// 解析PKCS12证书
		std::ifstream ifs(pkcs12cert_path.c_str(), std::ios::binary);
		Poco::Crypto::PKCS12Container pkcs12(ifs, pkcs12cert_pin);

		// 这里拿到的是密钥对，公私钥都有
		Poco::Crypto::EVPPKey evpkey = pkcs12.getKey();

		// 初始化RSA密钥，加密时采用PKCS1填充
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