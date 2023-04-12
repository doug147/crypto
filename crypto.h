#pragma once

#pragma warning (disable : 4267)

#include <string>
#include <string_view>
#include <array>
#include <sstream>
#include <iomanip>
#include <vector>
#include <mutex>
#include <assert.h>
#include <regex>
#include <openssl/evp.h>
#include <openssl/pem.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

namespace crypto
{
	std::string bytes_to_hex(const uint8_t* in, const int32_t count)
	{
		std::stringstream ss;
		ss << std::hex << std::setfill('0');
		for (int32_t i = 0; i < count; ++i) {
			ss << std::setw(2) << static_cast<int>(in[i]);
		}
		return ss.str();
	}
	std::vector<unsigned char> hex_to_bytes(const std::string_view hex_string)
	{
		std::vector<unsigned char> bytes{};
		bytes.clear();

		if (hex_string.length() % 2 != 0) {
			throw std::invalid_argument("hex_string has odd length");
		}

		for (size_t i = 0; i < hex_string.length(); i += 2) {
			if (!std::isxdigit(hex_string[i]) || !std::isxdigit(hex_string[i + 1])) {
				throw std::invalid_argument("hex_string contains invalid characters");
			}

			uint8_t byte = static_cast<uint8_t>(std::stoi(hex_string.substr(i, 2).data(), nullptr, 16));
			bytes.push_back(byte);
		}

		return bytes;
	}
	std::string encode64(const unsigned char* input, const int length)
	{
		BIO* bmem = BIO_new(BIO_s_mem());
		BIO* b64 = BIO_new(BIO_f_base64());
		b64 = BIO_push(b64, bmem);
		BIO_write(b64, input, length);
		BIO_flush(b64);
		BUF_MEM* bptr;
		BIO_get_mem_ptr(b64, &bptr);
		std::string result(bptr->data, bptr->length - 1);
		BIO_free_all(b64);
		return result;
	}
	std::string decode64(const unsigned char* input, const int length)
	{
		BIO* b64, * bmem;
		std::string buffer{};
		buffer.resize(length);
		b64 = BIO_new(BIO_f_base64());
		bmem = BIO_new_mem_buf(input, length);
		bmem = BIO_push(b64, bmem);
		BIO_read(bmem, buffer.data(), length);
		BIO_free_all(bmem);
		return buffer;
	}
	std::string rsa_encrypt(const std::string_view str, const std::string_view pub_key)
	{
		std::string outstr{};
		BIO* bio = BIO_new_mem_buf(pub_key.data(), pub_key.length());
		EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, 0, 0, 0);
		BIO_free(bio);
		if (!pkey) {
			throw std::runtime_error("Failed to read public key");
		}
		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (!ctx) {
			throw std::runtime_error("Failed to create context");
		}
		if (EVP_PKEY_encrypt_init(ctx) <= 0) {
			throw std::runtime_error("Failed to initialize encryption");
		}
		if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
			throw std::runtime_error("Failed to set padding");
		}
		if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
			throw std::runtime_error("Failed to set OAEP digest");
		}
		size_t outlen;
		if (EVP_PKEY_encrypt(ctx, NULL, &outlen, (const unsigned char*)str.data(), str.length()) <= 0) {
			throw std::runtime_error("Failed to determine ciphertext size");
		}
		outstr.resize(outlen);
		if (EVP_PKEY_encrypt(ctx, (unsigned char*)outstr.data(), &outlen, (const unsigned char*)str.data(), str.length()) <= 0) {
			throw std::runtime_error("Failed to encrypt data");
		}
		EVP_PKEY_free(pkey);
		EVP_PKEY_CTX_free(ctx);
		return outstr;
	}
	std::string rsa_decrypt(const std::string_view str, const std::string_view priv_key)
	{
		std::string outstr{};
		BIO* bio = BIO_new_mem_buf(priv_key.data(), priv_key.length());
		EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, 0, 0, 0);
		BIO_free(bio);
		if (!pkey) {
			throw std::runtime_error("Failed to read private key");
		}
		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (!ctx) {
			throw std::runtime_error("Failed to create context");
		}
		if (EVP_PKEY_decrypt_init(ctx) <= 0) {
			throw std::runtime_error("Failed to initialize decryption");
		}
		if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
			throw std::runtime_error("Failed to set padding");
		}
		if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
			throw std::runtime_error("Failed to set OAEP digest");
		}
		size_t outlen;
		if (EVP_PKEY_decrypt(ctx, NULL, &outlen, (const unsigned char*)str.data(), str.length()) <= 0) {
			throw std::runtime_error("Failed to determine plaintext size");
		}
		outstr.resize(outlen);
		if (EVP_PKEY_decrypt(ctx, (unsigned char*)outstr.data(), &outlen, (const unsigned char*)str.data(), str.length()) <= 0) {
			throw std::runtime_error("Failed to decrypt data");
		}
		EVP_PKEY_free(pkey);
		EVP_PKEY_CTX_free(ctx);
		return outstr;
	}
	std::string sha512(const std::string_view str)
	{
		EVP_MD_CTX* context = EVP_MD_CTX_new();
		const EVP_MD* md = EVP_get_digestbyname("sha512");
		EVP_DigestInit_ex(context, md, nullptr);
		EVP_DigestUpdate(context, str.data(), str.size());

		std::array<unsigned char, EVP_MAX_MD_SIZE> md_value;
		unsigned int md_len;
		EVP_DigestFinal_ex(context, md_value.data(), &md_len);
		EVP_MD_CTX_free(context);

		std::ostringstream out;
		out << std::hex << std::setfill('0');
		for (size_t i = 0; i < md_len; i++) {
			out << std::setw(2) << static_cast<int>(md_value[i]);
		}
		return out.str();
	}
	std::string md5(const std::string_view content)
	{
		EVP_MD_CTX* context = EVP_MD_CTX_new();
		const EVP_MD* md = EVP_md5();

		std::array<unsigned char, EVP_MAX_MD_SIZE> md_value;
		unsigned int md_len;
		EVP_DigestInit_ex(context, md, nullptr);
		EVP_DigestUpdate(context, content.data(), content.size());
		EVP_DigestFinal_ex(context, md_value.data(), &md_len);
		EVP_MD_CTX_free(context);

		std::ostringstream out;
		out << std::hex << std::setfill('0');
		for (size_t i = 0; i < md_len; i++) {
			out << std::setw(2) << static_cast<int>(md_value[i]);
		}
		return out.str();
	}
	std::vector<unsigned char> aes_256_cbc_decrypt(const std::vector<unsigned char>& in, const std::string_view key, const std::string_view iv)
	{
		std::vector<unsigned char> out(in.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()) * 2);
		int out_len = 0;
		int len = 0;

		auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);

		EVP_CIPHER_CTX_reset(ctx.get());
		EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()));
		EVP_DecryptUpdate(ctx.get(), out.data(), &len, in.data(), in.size());
		out_len = len;
		EVP_DecryptFinal_ex(ctx.get(), out.data() + len, &len);
		out_len += len;

		out.resize(out_len);
		out.shrink_to_fit();
		return out;
	}
	std::vector<unsigned char> aes_256_cbc_encrypt(const std::string_view in, const std::string_view key, const std::string_view iv)
	{
		std::vector<unsigned char> out(in.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc()) * 2);
		int out_len = 0;
		int len = 0;

		auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);

		EVP_CIPHER_CTX_reset(ctx.get());
		EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()));
		EVP_EncryptUpdate(ctx.get(), out.data(), &len, reinterpret_cast<const unsigned char*>(in.data()), in.length());
		out_len = len;
		EVP_EncryptFinal_ex(ctx.get(), out.data() + len, &len);
		out_len += len;

		out.resize(out_len);
		out.shrink_to_fit();
		return out;
	}
}
