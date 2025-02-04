#include <Windows.h>
#include <iostream>

extern "C" NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
extern "C" NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

template <typename T>
T ReadMemorySyscall(HANDLE hProcess, std::uintptr_t address) {
    T value{};
    NtReadVirtualMemory(hProcess, (PVOID)address, &value, sizeof(T), nullptr);
    return value;
}

template <typename T>
void WriteMemorySyscall(HANDLE hProcess, std::uintptr_t address, const T& value) {
    NtWriteVirtualMemory(hProcess, (PVOID)address, (PVOID)&value, sizeof(T), nullptr);
}
