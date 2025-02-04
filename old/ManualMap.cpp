#include <Windows.h>
#include <iostream>
#include <fstream>

bool ManualMap(HANDLE hProcess, const char* dllPath) {
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file) return false;

    size_t dllSize = file.tellg();
    file.seekg(0, std::ios::beg);

    void* allocMem = VirtualAllocEx(hProcess, nullptr, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocMem) return false;

    char* buffer = new char[dllSize];
    file.read(buffer, dllSize);
    file.close();

    WriteProcessMemory(hProcess, allocMem, buffer, dllSize, nullptr);
    delete[] buffer;

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)allocMem, nullptr, 0, nullptr);
    return hThread != nullptr;
}
