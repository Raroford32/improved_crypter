#pragma once

// Windows headers
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnt.h>

// STL headers
#include <vector>
#include <string>
#include <random>
#include <memory>
#include <algorithm>
#include <cstring>

// Project headers
#include "syscall_utils.hpp"

namespace PEUtils {
    inline DWORD alignTo(DWORD value, DWORD alignment) {
        return (value + alignment - 1) & ~(alignment - 1);
    }
}

class PEManipulator {
public:
    enum class InjectionType {
        ProcessHollowing,
        APCInjection,
        ModuleStomping,
        EarlyBird
    };

    PEManipulator() = default;

    bool load(const std::vector<uint8_t>& data) {
        try {
            m_data = data;

            // Validate DOS header
            if (m_data.size() < sizeof(IMAGE_DOS_HEADER)) {
                printf("[-] Invalid PE file: too small for DOS header\n");
                return false;
            }

            auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_data.data());
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                printf("[-] Invalid PE file: invalid DOS signature\n");
                return false;
            }

            // Validate NT headers
            if (m_data.size() < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
                printf("[-] Invalid PE file: too small for NT headers\n");
                return false;
            }

            auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(m_data.data() + dosHeader->e_lfanew);
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
                printf("[-] Invalid PE file: invalid NT signature\n");
                return false;
            }

            // Store headers for later use
            m_dosHeader = dosHeader;
            m_ntHeaders = ntHeaders;

            printf("[+] PE file loaded successfully\n");
            return true;
        }
        catch (const std::exception& e) {
            printf("[-] Exception while loading PE: %s\n", e.what());
            return false;
        }
    }

    bool save(std::vector<uint8_t>& output) {
        try {
            output = m_data;
            printf("[+] PE file saved successfully\n");
            return true;
        }
        catch (const std::exception& e) {
            printf("[-] Exception while saving PE: %s\n", e.what());
            return false;
        }
    }

    bool addRandomSections() {
        try {
            // Add 1-3 random sections
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> numSections(1, 3);
            std::uniform_int_distribution<> sizeRange(0x1000, 0x5000);

            int count = numSections(gen);
            printf("[+] Adding %d random sections\n", count);

            for (int i = 0; i < count; i++) {
                // Generate random section name
                char name[9] = ".";
                std::uniform_int_distribution<> charRange('a', 'z');
                for (int j = 1; j < 8; j++) {
                    name[j] = static_cast<char>(charRange(gen));
                }
                name[8] = '\0';

                // Generate random data
                size_t size = sizeRange(gen);
                std::vector<uint8_t> data(size);
                std::uniform_int_distribution<> byteRange(0, 255);
                for (auto& byte : data) {
                    byte = static_cast<uint8_t>(byteRange(gen));
                }

                // Add section
                if (!addSection(name, data, IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA)) {
                    printf("[-] Failed to add random section %d\n", i + 1);
                    return false;
                }

                printf("[+] Added random section %s, size: 0x%zx\n", name, size);
            }

            return true;
        }
        catch (const std::exception& e) {
            printf("[-] Exception while adding random sections: %s\n", e.what());
            return false;
        }
    }

    bool obfuscateImports() {
        printf("[+] Import obfuscation not implemented\n");
        return true;
    }

    bool addSection(const char* name, const std::vector<uint8_t>& data, DWORD characteristics) {
        try {
            // Calculate new section header offset
            auto* sectionHeader = IMAGE_FIRST_SECTION(m_ntHeaders);
            auto* newSection = &sectionHeader[m_ntHeaders->FileHeader.NumberOfSections];

            // Fill in section header
            std::memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));
            std::memcpy(newSection->Name, name, std::min(std::strlen(name), size_t(8)));
            newSection->Misc.VirtualSize = data.size();
            newSection->VirtualAddress = PEUtils::alignTo(
                sectionHeader[m_ntHeaders->FileHeader.NumberOfSections - 1].VirtualAddress +
                PEUtils::alignTo(sectionHeader[m_ntHeaders->FileHeader.NumberOfSections - 1].Misc.VirtualSize,
                    m_ntHeaders->OptionalHeader.SectionAlignment),
                m_ntHeaders->OptionalHeader.SectionAlignment);
            newSection->SizeOfRawData = PEUtils::alignTo(data.size(), m_ntHeaders->OptionalHeader.FileAlignment);
            newSection->PointerToRawData = PEUtils::alignTo(m_data.size(), m_ntHeaders->OptionalHeader.FileAlignment);
            newSection->Characteristics = characteristics;

            // Update headers
            m_ntHeaders->FileHeader.NumberOfSections++;
            m_ntHeaders->OptionalHeader.SizeOfImage = PEUtils::alignTo(
                newSection->VirtualAddress + PEUtils::alignTo(newSection->Misc.VirtualSize, m_ntHeaders->OptionalHeader.SectionAlignment),
                m_ntHeaders->OptionalHeader.SectionAlignment);

            // Add section data
            size_t oldSize = m_data.size();
            m_data.resize(newSection->PointerToRawData + newSection->SizeOfRawData, 0);
            std::memcpy(&m_data[newSection->PointerToRawData], data.data(), data.size());

            printf("[+] Added section %s at RVA 0x%08X\n", name, newSection->VirtualAddress);
            return true;
        }
        catch (const std::exception& e) {
            printf("[-] Exception while adding section: %s\n", e.what());
            return false;
        }
    }

    bool scrambleHeaders() {
        try {
            // Randomize some non-critical header fields
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 0xFFFF);

            // Modify DOS header fields that don't affect execution
            m_dosHeader->e_maxalloc = dis(gen);
            m_dosHeader->e_minalloc = dis(gen);
            m_dosHeader->e_ss = dis(gen);
            m_dosHeader->e_sp = dis(gen);
            m_dosHeader->e_csum = dis(gen);
            m_dosHeader->e_ip = dis(gen);
            m_dosHeader->e_cs = dis(gen);
            m_dosHeader->e_lfarlc = dis(gen);
            m_dosHeader->e_ovno = dis(gen);

            printf("[+] Headers scrambled\n");
            return true;
        }
        catch (const std::exception& e) {
            printf("[-] Exception while scrambling headers: %s\n", e.what());
            return false;
        }
    }

private:
    std::vector<uint8_t> m_data;
    PIMAGE_DOS_HEADER m_dosHeader = nullptr;
    PIMAGE_NT_HEADERS m_ntHeaders = nullptr;
};
