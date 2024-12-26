#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <random>
#include <memory>

#pragma comment(lib, "bcrypt.lib")

namespace Encryption {

inline std::vector<uint8_t> generateKey() {
    std::vector<uint8_t> key(32); // 256-bit key
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (auto& byte : key) {
        byte = static_cast<uint8_t>(dis(gen));
    }

    return key;
}

inline bool encrypt(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key, std::vector<uint8_t>& output) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;
    bool success = false;

    try {
        // Open algorithm provider
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) {
            printf("[-] BCryptOpenAlgorithmProvider failed: 0x%08x\n", status);
            return false;
        }

        // Set chaining mode to CBC
        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (!BCRYPT_SUCCESS(status)) {
            printf("[-] BCryptSetProperty failed: 0x%08x\n", status);
            return false;
        }

        // Generate IV
        std::vector<uint8_t> iv(16, 0); // 128-bit IV
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (auto& byte : iv) {
            byte = static_cast<uint8_t>(dis(gen));
        }

        // Generate key
        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PBYTE)key.data(), key.size(), 0);
        if (!BCRYPT_SUCCESS(status)) {
            printf("[-] BCryptGenerateSymmetricKey failed: 0x%08x\n", status);
            return false;
        }

        // Get cipher text size
        DWORD cbCipherText = 0;
        DWORD cbResult = 0;
        status = BCryptEncrypt(hKey, (PBYTE)input.data(), input.size(), nullptr, iv.data(), iv.size(), nullptr, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
        if (!BCRYPT_SUCCESS(status)) {
            printf("[-] BCryptEncrypt (size query) failed: 0x%08x\n", status);
            return false;
        }

        // Prepare output buffer (IV + Ciphertext)
        output.resize(iv.size() + cbCipherText);
        memcpy(output.data(), iv.data(), iv.size());

        // Encrypt
        status = BCryptEncrypt(hKey, (PBYTE)input.data(), input.size(), nullptr, iv.data(), iv.size(), output.data() + iv.size(), cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
        if (!BCRYPT_SUCCESS(status)) {
            printf("[-] BCryptEncrypt failed: 0x%08x\n", status);
            return false;
        }

        success = true;
    }
    catch (const std::exception& e) {
        printf("[-] Exception during encryption: %s\n", e.what());
        success = false;
    }
    catch (...) {
        printf("[-] Unknown exception during encryption\n");
        success = false;
    }

    // Cleanup
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return success;
}

inline bool decrypt(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key, std::vector<uint8_t>& output) {
    if (input.size() < 16) {
        printf("[-] Input too small\n");
        return false;
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;
    bool success = false;

    try {
        // Open algorithm provider
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) {
            printf("[-] BCryptOpenAlgorithmProvider failed: 0x%08x\n", status);
            return false;
        }

        // Set chaining mode to CBC
        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (!BCRYPT_SUCCESS(status)) {
            printf("[-] BCryptSetProperty failed: 0x%08x\n", status);
            return false;
        }

        // Extract IV from input
        std::vector<uint8_t> iv(input.begin(), input.begin() + 16);
        const uint8_t* ciphertext = input.data() + 16;
        size_t ciphertextSize = input.size() - 16;

        // Generate key
        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PBYTE)key.data(), key.size(), 0);
        if (!BCRYPT_SUCCESS(status)) {
            printf("[-] BCryptGenerateSymmetricKey failed: 0x%08x\n", status);
            return false;
        }

        // Get plaintext size
        DWORD cbPlainText = 0;
        DWORD cbResult = 0;
        status = BCryptDecrypt(hKey, (PBYTE)ciphertext, ciphertextSize, nullptr, iv.data(), iv.size(), nullptr, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
        if (!BCRYPT_SUCCESS(status)) {
            printf("[-] BCryptDecrypt (size query) failed: 0x%08x\n", status);
            return false;
        }

        // Prepare output buffer
        output.resize(cbPlainText);

        // Decrypt
        status = BCryptDecrypt(hKey, (PBYTE)ciphertext, ciphertextSize, nullptr, iv.data(), iv.size(), output.data(), cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
        if (!BCRYPT_SUCCESS(status)) {
            printf("[-] BCryptDecrypt failed: 0x%08x\n", status);
            return false;
        }

        success = true;
    }
    catch (const std::exception& e) {
        printf("[-] Exception during decryption: %s\n", e.what());
        success = false;
    }
    catch (...) {
        printf("[-] Unknown exception during decryption\n");
        success = false;
    }

    // Cleanup
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return success;
}

} // namespace Encryption
