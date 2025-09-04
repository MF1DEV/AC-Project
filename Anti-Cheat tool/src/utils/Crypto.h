#pragma once
#include "../../include/Common.h"

class Crypto {
public:
    static std::string generateClientId();
    static std::string calculateMD5(const std::string& data);
    static std::string calculateSHA256(const std::string& data);
    static std::vector<uint8_t> encryptAES(const std::vector<uint8_t>& data, const std::string& key);
    static std::vector<uint8_t> decryptAES(const std::vector<uint8_t>& encryptedData, const std::string& key);

private:
    static void initCrypto();
};