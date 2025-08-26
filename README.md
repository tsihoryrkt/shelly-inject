# Shellcode injector for C2
*A stealthy shellcode injector designed for C2 payloads, using direct syscalls and XOR encryption to bypass basic EDR detection*

## Features
- **🔒 XOR-encrypted shellcode** (default key: 0x42)
- **🛡️ Direct syscall execution** (no CreateThread/VirtualAlloc API calls)
- **📦 Static compilation** (no external DLL dependencies)
- **🖥️ Silent execution** (optional console-less mode)

## Prerequistes
- **Python 3.0+**
- **Mingw-w64**

## Usage

### Encrypt the Shellcode
```bash
   python xor_encode.py --file your_shell_code.bin
```

### Compile the injector

Update the C++ variables if the default XOR key or output filename has been modified
```cpp
#define XOR_KEY 0x42
#define XORED_FILE "xored.bin"
```

```bash
   x86_64-w64-mingw32-g++ injector.cpp -o tekken8.exe -static -mwindows
```

## Disclaimer
⚠️ This tool is only for testing and academic purposes and can only be used where strict consent has been given.  Mainly used in **penetration testing** or **malware development** to run arbitrary code.  