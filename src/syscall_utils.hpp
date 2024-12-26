#pragma once
#include <windows.h>
#include <winternl.h>

// Define missing NTSTATUS codes
#ifndef STATUS_PROCEDURE_NOT_FOUND
#define STATUS_PROCEDURE_NOT_FOUND ((NTSTATUS)0xC000007A)
#endif

namespace NtApi {
    // Function types
    typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID BaseAddress);
    typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
    typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
    typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
    typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

    // Function pointers
    inline NtUnmapViewOfSection_t GetNtUnmapViewOfSection() {
        static NtUnmapViewOfSection_t func = nullptr;
        if (!func) {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (ntdll) {
                func = reinterpret_cast<NtUnmapViewOfSection_t>(GetProcAddress(ntdll, "NtUnmapViewOfSection"));
            }
        }
        return func;
    }

    // Wrapper functions
    inline NTSTATUS UnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
        auto func = GetNtUnmapViewOfSection();
        if (!func) return STATUS_PROCEDURE_NOT_FOUND;
        return func(ProcessHandle, BaseAddress);
    }
}

// Helper macros
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
