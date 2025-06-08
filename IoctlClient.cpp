#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <psapi.h>

// Include the shared structures from stdafx.h
#pragma pack(push, 1)

#define DEFAULT_MAGGICCODE 0x999999999

enum REQUEST_TYPE : int
{
    WRITE,
    READ,
    PROTECT,
    ALLOC,
    FREE,
    MODULE,
    MAINBASE,
    THREADCALL
};

typedef struct _REQUEST_WRITE {
    UINT64 ProcessId;
    PVOID Src;
    PVOID Dest;
    UINT64 Size;
    BOOLEAN bPhysicalMem;
} REQUEST_WRITE, *PREQUEST_WRITE;

typedef struct _REQUEST_READ {
    UINT64 ProcessId;
    PVOID Src;
    PVOID Dest;
    UINT64 Size;
    BOOLEAN bPhysicalMem;
} REQUEST_READ, *PREQUEST_READ;

typedef struct _REQUEST_PROTECT {
    UINT64 ProcessId;
    PVOID Address;
    UINT64 Size;
    PVOID InOutProtect;
} REQUEST_PROTECT, *PREQUEST_PROTECT;

typedef struct _REQUEST_ALLOC {
    UINT64 ProcessId;
    UINT64 Size;
    PVOID OutAddress;
} REQUEST_ALLOC, *PREQUEST_ALLOC;

typedef struct _REQUEST_FREE {
    UINT64 ProcessId;
    PVOID Address;
} REQUEST_FREE, *PREQUEST_FREE;

typedef struct _REQUEST_MODULE {
    UINT64 ProcessId;
    WCHAR Module[260];
    PVOID OutAddress;
    PVOID OutSize;
} REQUEST_MODULE, *PREQUEST_MODULE;

typedef struct _REQUEST_MAINBASE {
    UINT64 ProcessId;
    PVOID OutAddress;
} REQUEST_MAINBASE, *PREQUEST_MAINBASE;

typedef struct _REQUEST_DATA {
    UINT64* MaggicCode;
    REQUEST_TYPE Type;
    union {
        REQUEST_WRITE Write;
        REQUEST_READ Read;
        REQUEST_PROTECT Protect;
        REQUEST_ALLOC Alloc;
        REQUEST_FREE Free;
        REQUEST_MODULE Module;
        REQUEST_MAINBASE MainBase;
    } Data;
} REQUEST_DATA, *PREQUEST_DATA;

#pragma pack(pop)

class IoctlDriverClient
{
private:
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    HANDLE hPeauthDevice = INVALID_HANDLE_VALUE;
    REQUEST_DATA* pSharedBuffer = nullptr;
    UINT64 magicCode = DEFAULT_MAGGICCODE;
    
public:
    int process_id = 0;
    
    bool setup()
    {
        std::cout << "Setting up IOCTL Driver client...\n";
        
        // Allocate shared buffer
        pSharedBuffer = (REQUEST_DATA*)VirtualAlloc(nullptr, sizeof(REQUEST_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pSharedBuffer) {
            std::cout << "Failed to allocate shared buffer\n";
            return false;
        }
        
        // Initialize magic code
        pSharedBuffer->MaggicCode = &magicCode;
        *pSharedBuffer->MaggicCode = DEFAULT_MAGGICCODE;
        
        // Write shared buffer address and PID to registry
        HKEY hKey;
        DWORD disposition;
        
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\DexzCHECK", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, &disposition) != ERROR_SUCCESS) {
            std::cout << "Failed to create/open registry key\n";
            VirtualFree(pSharedBuffer, 0, MEM_RELEASE);
            return false;
        }
        
        // Write shared buffer address
        UINT64 bufferAddr = (UINT64)pSharedBuffer;
        RegSetValueExA(hKey, "xxx", 0, REG_QWORD, (BYTE*)&bufferAddr, sizeof(UINT64));
        
        // Write current process ID
        UINT64 currentPid = GetCurrentProcessId();
        RegSetValueExA(hKey, "xx", 0, REG_QWORD, (BYTE*)&currentPid, sizeof(UINT64));
        
        RegCloseKey(hKey);
        
        // Try to open PEAUTH device to trigger the hook
        hPeauthDevice = CreateFileA("\\\\.\\PEAUTH", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPeauthDevice == INVALID_HANDLE_VALUE) {
            std::cout << "Warning: Could not open PEAUTH device (Error: " << GetLastError() << ")\n";
            std::cout << "Driver may not be loaded or accessible\n";
            // Don't fail here - the driver communication might still work
        }
        
        std::cout << "IOCTL Driver client setup complete\n";
        std::cout << "Shared buffer at: 0x" << std::hex << (UINT64)pSharedBuffer << "\n";
        return true;
    }
    
    DWORD get_process_id(const char* process_name)
    {
        PROCESSENTRY32 pe32{};
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
        
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32))
        {
            do {
                if (strcmp(pe32.szExeFile, process_name) == 0)
                {
                    CloseHandle(hSnapshot);
                    return pe32.th32ProcessID;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
        return 0;
    }
    
    bool trigger_driver()
    {
        if (hPeauthDevice == INVALID_HANDLE_VALUE) return false;
        
        // Trigger the hooked IRP_MJ_FLUSH_BUFFERS
        BOOL result = FlushFileBuffers(hPeauthDevice);
        return result != FALSE;
    }
    
    bool driver_read_memory(DWORD target_pid, uintptr_t address, PVOID buffer, SIZE_T size)
    {
        if (!pSharedBuffer) return false;
        
        // Set up the read request
        pSharedBuffer->Type = READ;
        pSharedBuffer->Data.Read.ProcessId = target_pid;
        pSharedBuffer->Data.Read.Src = (PVOID)address;
        pSharedBuffer->Data.Read.Dest = buffer;
        pSharedBuffer->Data.Read.Size = size;
        pSharedBuffer->Data.Read.bPhysicalMem = FALSE;
        
        // Trigger the driver
        if (!trigger_driver()) {
            std::cout << "Failed to trigger driver for read operation\n";
            return false;
        }
        
        return true;
    }
    
    bool driver_write_memory(DWORD target_pid, uintptr_t address, PVOID buffer, SIZE_T size)
    {
        if (!pSharedBuffer) return false;
        
        // Set up the write request
        pSharedBuffer->Type = WRITE;
        pSharedBuffer->Data.Write.ProcessId = target_pid;
        pSharedBuffer->Data.Write.Src = buffer;
        pSharedBuffer->Data.Write.Dest = (PVOID)address;
        pSharedBuffer->Data.Write.Size = size;
        pSharedBuffer->Data.Write.bPhysicalMem = FALSE;
        
        // Trigger the driver
        if (!trigger_driver()) {
            std::cout << "Failed to trigger driver for write operation\n";
            return false;
        }
        
        return true;
    }
    
    uintptr_t driver_get_main_base(DWORD target_pid)
    {
        if (!pSharedBuffer) return 0;
        
        // Set up the main base request
        pSharedBuffer->Type = MAINBASE;
        pSharedBuffer->Data.MainBase.ProcessId = target_pid;
        pSharedBuffer->Data.MainBase.OutAddress = nullptr;
        
        // Trigger the driver
        if (!trigger_driver()) {
            std::cout << "Failed to trigger driver for main base operation\n";
            return 0;
        }
        
        // The driver should have updated OutAddress
        return (uintptr_t)pSharedBuffer->Data.MainBase.OutAddress;
    }
    
    // Legacy usermode functions (fallback)
    bool read_process_memory(DWORD target_pid, uintptr_t address, PVOID buffer, SIZE_T size)
    {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, target_pid);
        if (hProcess == NULL) return false;
        
        SIZE_T bytesRead;
        BOOL result = ReadProcessMemory(hProcess, (LPCVOID)address, buffer, size, &bytesRead);
        CloseHandle(hProcess);
        return result && bytesRead == size;
    }
    
    bool write_process_memory(DWORD target_pid, uintptr_t address, PVOID buffer, SIZE_T size)
    {
        HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, target_pid);
        if (hProcess == NULL) return false;
        
        SIZE_T bytesWritten;
        BOOL result = WriteProcessMemory(hProcess, (LPVOID)address, buffer, size, &bytesWritten);
        CloseHandle(hProcess);
        return result && bytesWritten == size;
    }
    
    uintptr_t get_module_base(DWORD target_pid, const char* module_name)
    {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target_pid);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
        
        MODULEENTRY32 me32{};
        me32.dwSize = sizeof(MODULEENTRY32);
        
        if (Module32First(hSnapshot, &me32))
        {
            do {
                if (strcmp(me32.szModule, module_name) == 0)
                {
                    CloseHandle(hSnapshot);
                    return (uintptr_t)me32.modBaseAddr;
                }
            } while (Module32Next(hSnapshot, &me32));
        }
        CloseHandle(hSnapshot);
        return 0;
    }
    
    void list_modules(DWORD target_pid)
    {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target_pid);
        if (hSnapshot == INVALID_HANDLE_VALUE) 
        {
            DWORD error = GetLastError();
            std::cout << "Failed to create module snapshot. Error: " << error << "\n";
            if (error == ERROR_ACCESS_DENIED) 
            {
                std::cout << "Access denied - process may have anti-cheat protection\n";
            }
            else if (error == ERROR_PARTIAL_COPY)
            {
                std::cout << "Partial copy error - process architecture mismatch or protection\n";
            }
            return;
        }
        
        MODULEENTRY32 me32{};
        me32.dwSize = sizeof(MODULEENTRY32);
        
        std::cout << "Loaded modules:\n";
        if (Module32First(hSnapshot, &me32))
        {
            int count = 0;
            do {
                std::cout << "  " << me32.szModule << " - Base: 0x" << std::hex << (uintptr_t)me32.modBaseAddr << "\n";
                count++;
                if (count > 10) // Limit output to first 10 modules
                {
                    std::cout << "  ... (showing first 10 modules)\n";
                    break;
                }
            } while (Module32Next(hSnapshot, &me32));
        }
        CloseHandle(hSnapshot);
    }
    
    uintptr_t get_process_base_address(DWORD target_pid)
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, target_pid);
        if (hProcess == NULL)
        {
            std::cout << "Failed to open process for base address lookup. Error: " << GetLastError() << "\n";
            return 0;
        }
        
        HMODULE hMods[1024];
        DWORD cbNeeded;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        {
            CloseHandle(hProcess);
            return (uintptr_t)hMods[0]; // First module is usually the main executable
        }
        
        CloseHandle(hProcess);
        return 0;
    }
    
    template<typename T>
    T read(DWORD target_pid, uintptr_t address)
    {
        T value{};
        read_process_memory(target_pid, address, &value, sizeof(T));
        return value;
    }
    
    template<typename T>
    bool write(DWORD target_pid, uintptr_t address, T value)
    {
        return write_process_memory(target_pid, address, &value, sizeof(T));
    }
    
    void cleanup()
    {
        if (hDevice != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hDevice);
            hDevice = INVALID_HANDLE_VALUE;
        }
        
        if (hPeauthDevice != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hPeauthDevice);
            hPeauthDevice = INVALID_HANDLE_VALUE;
        }
        
        if (pSharedBuffer)
        {
            VirtualFree(pSharedBuffer, 0, MEM_RELEASE);
            pSharedBuffer = nullptr;
        }
        
        // Optionally clean up registry entries
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\DexzCHECK", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            RegDeleteValueA(hKey, "xxx");
            RegDeleteValueA(hKey, "xx");
            RegCloseKey(hKey);
        }
    }
    
    ~IoctlDriverClient()
    {
        cleanup();
    }
};

int main()
{
    std::cout << "IOCTL Driver Client\n";
    std::cout << "===================\n\n";
    
    IoctlDriverClient client;
    
    if (!client.setup())
    {
        std::cout << "Failed to initialize IOCTL driver connection!\n";
        return 1;
    }
    
    std::cout << "IOCTL Driver client initialized!\n";
    
    // Example: Find nightreign.exe process
    DWORD pid = client.get_process_id("nightreign.exe");
    if (pid == 0)
    {
        std::cout << "nightreign.exe not found. Please start Elden Ring Nightreign manually...\n";
        std::cout << "Expected path: C:\\Program Files (x86)\\Steam\\steamapps\\common\\ELDEN RING NIGHTREIGN\\Game\\nightreign.exe\n";
        std::cout << "Waiting for process to start (checking every 2 seconds)...\n";
        
        // Keep checking for the process
        for (int i = 0; i < 30; i++) // Check for up to 60 seconds
        {
            Sleep(2000);
            pid = client.get_process_id("nightreign.exe");
            if (pid != 0) break;
            std::cout << "Still waiting... (" << (i + 1) * 2 << "s)\n";
        }
    }
    
    if (pid != 0)
    {
        std::cout << "Found nightreign.exe PID: " << pid << "\n";
        
        // List modules to see what's actually loaded
        client.list_modules(pid);
        
        // Try kernel driver method first
        std::cout << "Attempting to get base address via kernel driver...\n";
        uintptr_t base = client.driver_get_main_base(pid);
        if (base != 0)
        {
            std::cout << "SUCCESS: Process base address (via kernel driver): 0x" << std::hex << base << "\n";
            
            // Try to read PE header using kernel driver
            DWORD pe_header = 0;
            if (client.driver_read_memory(pid, base, &pe_header, sizeof(DWORD)))
            {
                std::cout << "SUCCESS: PE signature area: 0x" << std::hex << pe_header << "\n";
                
                // Test writing to a safe area (our own process memory for testing)
                DWORD test_value = 0x12345678;
                DWORD original_value = 0;
                uintptr_t test_addr = (uintptr_t)&original_value;
                
                std::cout << "Testing kernel driver write capability...\n";
                if (client.driver_write_memory(GetCurrentProcessId(), test_addr, &test_value, sizeof(DWORD)))
                {
                    if (original_value == test_value)
                    {
                        std::cout << "SUCCESS: Kernel driver write test passed!\n";
                    }
                    else
                    {
                        std::cout << "WARNING: Write appeared successful but value not changed\n";
                    }
                }
                else
                {
                    std::cout << "Failed: Kernel driver write test\n";
                }
            }
            else
            {
                std::cout << "Failed to read PE header via kernel driver\n";
            }
        }
        else
        {
            std::cout << "Kernel driver method failed, trying usermode fallbacks...\n";
            
            // Try alternative usermode method
            base = client.get_process_base_address(pid);
            if (base != 0)
            {
                std::cout << "Process base address (via EnumProcessModules): 0x" << std::hex << base << "\n";
                
                // Read PE header
                DWORD pe_header = client.read<DWORD>(pid, base);
                std::cout << "PE signature area: 0x" << std::hex << pe_header << "\n";
            }
            else
            {
                // Fallback: try the original method
                base = client.get_module_base(pid, "nightreign.exe");
                if (base != 0)
                {
                    std::cout << "nightreign.exe base address: 0x" << std::hex << base << "\n";
                    
                    // Read PE header
                    DWORD pe_header = client.read<DWORD>(pid, base);
                    std::cout << "PE signature area: 0x" << std::hex << pe_header << "\n";
                }
                else
                {
                    std::cout << "Could not get base address using any method.\n";
                    std::cout << "Kernel driver is required to bypass anti-cheat protection.\n";
                }
            }
        }
    }
    else
    {
        std::cout << "Could not find target process.\n";
    }
    
    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}