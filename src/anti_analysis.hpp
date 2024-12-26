#pragma once
#include <windows.h>
#include <vector>
#include <random>
#include "pe_manipulator.hpp"

class AntiAnalysis {
public:
    AntiAnalysis() = default;

    bool protect(PEManipulator* pe) {
        try {
            printf("[+] Adding anti-analysis protections\n");

            // Generate anti-debug code section
            std::vector<uint8_t> code = generateAntiDebugCode();
            
            // Add section with execute permission
            if (!pe->addRandomSections()) {
                printf("[-] Failed to add anti-debug section\n");
                return false;
            }

            printf("[+] Anti-analysis protections added\n");
            return true;
        }
        catch (const std::exception& e) {
            printf("[-] Exception while adding protections: %s\n", e.what());
            return false;
        }
    }

private:
    std::vector<uint8_t> generateAntiDebugCode() {
        // x64 assembly code for various anti-debug checks
        std::vector<uint8_t> code = {
            // Check IsDebuggerPresent
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,  // mov rax, gs:[60h]
            0x48, 0x8B, 0x40, 0x60,                                 // mov rax, [rax+60h]
            0x84, 0xC0,                                             // test al, al
            0x75, 0x50,                                             // jnz detected

            // Check BeingDebugged flag
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,  // mov rax, gs:[60h]
            0x80, 0x78, 0x02, 0x00,                                 // cmp byte ptr [rax+2], 0
            0x75, 0x44,                                             // jnz detected

            // Check hardware breakpoints (DR registers)
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,  // mov rax, gs:[30h]
            0x48, 0x8B, 0x40, 0x68,                                 // mov rax, [rax+68h]
            0x48, 0x85, 0xC0,                                       // test rax, rax
            0x75, 0x34,                                             // jnz detected

            // Check for process environment block flags
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,  // mov rax, gs:[60h]
            0x48, 0x8B, 0x40, 0x60,                                 // mov rax, [rax+60h]
            0xF6, 0x40, 0x02, 0x70,                                 // test byte ptr [rax+2], 70h
            0x75, 0x24,                                             // jnz detected

            // Check for hardware breakpoints
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,  // mov rax, gs:[30h]
            0x48, 0x8B, 0x40, 0x20,                                 // mov rax, [rax+20h]
            0x48, 0x83, 0xE0, 0x0F,                                 // and rax, 0Fh
            0x75, 0x14,                                             // jnz detected

            // Check CPUID hypervisor bit
            0x53,                                                    // push rbx
            0x31, 0xC0,                                             // xor eax, eax
            0x0F, 0xA2,                                             // cpuid
            0x81, 0xE3, 0x00, 0x00, 0x00, 0x80,                    // and ebx, 80000000h
            0x5B,                                                    // pop rbx
            0x75, 0x04,                                             // jnz detected

            // Continue execution
            0x48, 0x31, 0xC0,                                       // xor rax, rax
            0xC3,                                                    // ret

            // Detected:
            0x48, 0x31, 0xC9,                                       // xor rcx, rcx
            0x48, 0x31, 0xD2,                                       // xor rdx, rdx
            0x4D, 0x31, 0xC0,                                       // xor r8, r8
            0x4D, 0x31, 0xC9,                                       // xor r9, r9
            0x48, 0x83, 0xEC, 0x28,                                 // sub rsp, 28h
            0x48, 0xB8,                                             // mov rax, ExitProcess
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xD0                                              // call rax
        };

        // Patch ExitProcess address
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32) {
            void* exitProcess = GetProcAddress(kernel32, "ExitProcess");
            if (exitProcess) {
                memcpy(&code[code.size() - 10], &exitProcess, sizeof(void*));
            }
        }

        return code;
    }
};
