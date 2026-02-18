#include "Crypto.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <cstring>
#include <cstdlib>

std::string Crypto::sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()),
           input.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(hash[i]);

    return ss.str();
}
std::string base64Encode(const unsigned char* buffer, size_t length) {
    BIO* bio;
    BIO* b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}
std::string base64Decode(const std::string& input) {
    BIO* bio;
    BIO* b64;
    char* buffer = (char*)malloc(input.length());
    memset(buffer, 0, input.length());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.data(), input.length());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int length = BIO_read(bio, buffer, input.length());
    BIO_free_all(bio);

    return std::string(buffer, length);
}
std::string Crypto::encryptAES(const std::string& plaintext,
                               const std::string& key) {
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                       (unsigned char*)key.c_str(), iv);

    unsigned char ciphertext[1024];
    int len;
    int ciphertext_len;

    EVP_EncryptUpdate(ctx, ciphertext, &len,
                      (unsigned char*)plaintext.c_str(),
                      plaintext.length());
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    std::string combined((char*)iv, 16);
    combined += std::string((char*)ciphertext, ciphertext_len);

    return base64Encode((unsigned char*)combined.c_str(), combined.size());
}
std::string Crypto::decryptAES(const std::string& ciphertext,
                               const std::string& key) {
    std::string decoded = base64Decode(ciphertext);

    unsigned char iv[16];
    memcpy(iv, decoded.c_str(), 16);

    std::string encrypted = decoded.substr(16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                       (unsigned char*)key.c_str(), iv);

    unsigned char plaintext[1024];
    int len;
    int plaintext_len;

    EVP_DecryptUpdate(ctx, plaintext, &len,
                      (unsigned char*)encrypted.c_str(),
                      encrypted.length());
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string((char*)plaintext, plaintext_len);
}
