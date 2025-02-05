# not finished | Contributions are welcomed. if you'd like to help with this project! <3
1. **Process Hollowing**:
* This is a technique where a process is created in a suspended state, and then its memory is replaced with malicious code (payload). This allows an attacker to run code inside the context of a legitimate process, making it harder to detect.

2. **DLL Injection**:
* This method involves injecting a DLL (dynamic link library) into the address space of another process. The attacker can execute code within the context of the target process, bypassing many security mechanisms and making detection more difficult.

3. **Memory-Mapped Files Injection**:
* Similar to process hollowing, memory-mapped files can be used to inject malicious code into the target process's memory space.

4. **Anti-Analysis & Anti-Debugging**:
* The script checks for debuggers using the IsDebuggerPresent function and NtQueryInformationProcess to determine if a debugger is attached to the process. If a debugger is detected, it exits immediately. * * This is an attempt to bypass analysis tools that researchers or security software might use to inspect the code.

5. **Exploit & Privilege Escalation**:
* The script contains code that attempts to escalate privileges by adjusting token privileges to enable debugging rights (SE_DEBUG_NAME). This is typically used for further exploitation of the system.

6. **UEFI Bootkit**:
While not implemented, this function `InstallUEFIBootkit(`) is a placeholder for what could potentially install a malicious bootkit at the UEFI (Unified Extensible Firmware Interface) level. This kind of attack allows the attacker to control the system before the OS even starts, making it very difficult to remove.

7. **Kernel-Level Exploits & Rootkit Features**:
* Kernel-level code and rootkits have deep access to the system, allowing the attacker to hide their presence or perform actions that are otherwise undetectable by the operating system or security software.

8. **Direct Syscalls**:
* The script uses direct syscalls to bypass hooks in the system, avoiding commonly used APIs like ReadProcessMemory or WriteProcessMemory, which could be monitored by security tools. This helps in making the malicious actions harder to detect.

8. **Unhooking API Functions**:
* Attempts to unhook API functions like `NtReadVirtualMemory` to ensure the code runs as expected even if the system has been hooked by security software.

---
> This script demonstrates a combination of highly dangerous techniques used in advanced cyber attacks. It is designed to evade detection, exploit system vulnerabilities, inject malicious payloads, and gain kernel-level access. Using or running this code on a system could result in severe security breaches, including unauthorized access, control, and potential data theft.
---

This project is licensed under [**Creative Commons Attribution-NonCommercial-NoDerivs 4.0 International**] – see [CPScript/Legal](https://github.com/CPScript/Legal) for details.
