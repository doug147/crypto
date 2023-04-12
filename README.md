# crypto
A collection of functions that use the openssl library

## Examples
### RSA encrypt/decrypt and base64 encode/decode example
```cpp
//RSA public key
std::string public_key = R"(-----BEGIN PUBLIC KEY-----
...your public key
-----END PUBLIC KEY-----)";

//RSA private key
std::string private_key = R"(-----BEGIN PRIVATE KEY-----
...your private key
-----END PRIVATE KEY-----)";

//RSA encrypted
auto rsa_encrypted = crypto::rsa_encrypt(text, public_key);
std::cout << rsa_encrypted << std::endl << std::endl;

//Base64 encoded
auto base64_encoded = crypto::encode64(reinterpret_cast<const unsigned char*>(rsa_encrypted.data()), rsa_encrypted.length());
std::cout << base64_encoded << std::endl << std::endl;

//Base 64 decoded
auto base64_decoded = crypto::decode64(reinterpret_cast<const unsigned char*>(base64_encoded.data()), base64_encoded.length());
std::cout << base64_decoded << std::endl << std::endl;

//RSA decrypted
auto rsa_decrypted = crypto::rsa_decrypt(rsa_encrypted, private_key);
std::cout << rsa_decrypted << std::endl << std::endl;
```

### AES encryption example
```cpp
std::string text = R"(Lorem ipsum dolor sit amet, consectetur adipiscing elit,
sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris
nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in
reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
culpa qui officia deserunt mollit anim id est laborum.)";

//AES key
std::string aes_key = "supersecretkeyforaes123456789876";

//AES iv
std::string aes_iv = "ivforaes12345678";

//AES encrypted
auto aes_encrypted = crypto::aes_256_cbc_encrypt(text, aes_key, aes_iv);
std::string str_encrypted(aes_encrypted.begin(), aes_encrypted.end());
std::cout << str_encrypted << std::endl << std::endl;

//AES decrypted
auto aes_decrypted = crypto::aes_256_cbc_decrypt(aes_encrypted, aes_key, aes_iv);
std::string str_decrypted(aes_decrypted.begin(), aes_decrypted.end());
std::cout << str_decrypted << std::endl << std::endl;
```
