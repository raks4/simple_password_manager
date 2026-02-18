#pragma once
#include <string>

class Crypto {
public:
    static std::string sha256(const std::string& input);

    static std::string encryptAES(const std::string& plaintext,
                                  const std::string& key);

    static std::string decryptAES(const std::string& ciphertext,
                                  const std::string& key);
};
