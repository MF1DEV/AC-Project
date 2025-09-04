#include "Crypto.h"
#include "../core/Logger.h"
#include <random>

std::string Crypto::generateClientId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);

    const char* hexChars = "0123456789ABCDEF";
    std::string clientId;
    clientId.reserve(32);

    for (int i = 0; i < 32; ++i) {
        clientId += hexChars[dis(gen)];
    }

    return clientId;
}

std::string Crypto::calculateMD5(const std::string& data) {
    // Simple MD5 implementation (for production, use a proper crypto library)
    // This is a placeholder - implement proper MD5 or use Windows CryptoAPI

    std::hash<std::string> hasher;
    size_t hashValue = hasher(data);

    std::stringstream ss;
    ss << std::hex << hashValue;
    return ss.str();
}

std::string Crypto::calculateSHA256(const std::string& data) {
    // Simple SHA256 implementation (for production, use a proper crypto library)
    // This is a placeholder - implement proper SHA256 or use Windows CryptoAPI

    std::hash<std::string> hasher;
    size_t hashValue = hasher(data + "salt");

    std::stringstream ss;
    ss << std::hex << hashValue;
    return ss.str();
}

std::vector<uint8_t> Crypto::encryptAES(const std::vector<uint8_t>& data, const std::string& key) {
    // Placeholder AES encryption
    // In production, use Windows CryptoAPI or a proper crypto library

    std::vector<uint8_t> encrypted = data;
    uint8_t keyByte = 0;
    for (char c : key) {
        keyByte ^= static_cast<uint8_t>(c);
    }

    for (auto& byte : encrypted) {
        byte ^= keyByte;
    }

    return encrypted;
}

std::vector<uint8_t> Crypto::decryptAES(const std::vector<uint8_t>& encryptedData, const std::string& key) {
    // Placeholder AES decryption
    return encryptAES(encryptedData, key); // XOR is its own inverse
}