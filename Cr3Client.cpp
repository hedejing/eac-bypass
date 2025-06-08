#include <windows.h>
#include <iostream>
#include <TlHelp32.h>

typedef __int64(*NtUserFunction)(uintptr_t);

enum REQUEST_TYPE : int
{
    NONE = 0,
    WRITE = 1,
    read = 2,
    BASE = 3
};

typedef struct _DRIVER_REQUEST
{
    REQUEST_TYPE type;
    HANDLE pid;
    PVOID address;
    PVOID buffer;
    SIZE_T size;
    PVOID base;
} DRIVER_REQUEST, *PDRIVER_REQUEST;

class DriverClient
{
private:
    NtUserFunction nt_user_function = nullptr;
    
    void send_request(PDRIVER_REQUEST out)
    {
        if (nt_user_function)
        {
            nt_user_function(reinterpret_cast<uintptr_t>(out));
        }
    }

public:
    int process_id = 0;
    
    bool setup()
    {
        HMODULE user32 = LoadLibraryA("user32.dll");
        if (user32)
        {
            nt_user_function = reinterpret_cast<NtUserFunction>(GetProcAddress(user32, "NtUserRegisterErrorReportingDialog"));
        }
        
        if (!nt_user_function)
        {
            HMODULE win32u = LoadLibraryA("win32u.dll");
            if (win32u)
            {
                nt_user_function = reinterpret_cast<NtUserFunction>(GetProcAddress(win32u, "NtUserRegisterErrorReportingDialog"));
            }
        }
        
        return nt_user_function != nullptr;
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
    
    uintptr_t get_base_address()
    {
        DRIVER_REQUEST request{};
        request.type = BASE;
        request.pid = (HANDLE)process_id;
        send_request(&request);
        return (uintptr_t)request.base;
    }
    
    void write_memory(PVOID address, PVOID buffer, SIZE_T size)
    {
        DRIVER_REQUEST request{};
        request.type = WRITE;
        request.pid = (HANDLE)process_id;
        request.address = address;
        request.buffer = buffer;
        request.size = size;
        send_request(&request);
    }
    
    void read_memory(PVOID address, PVOID buffer, SIZE_T size)
    {
        DRIVER_REQUEST request{};
        request.type = read;
        request.pid = (HANDLE)process_id;
        request.address = address;
        request.buffer = buffer;
        request.size = size;
        send_request(&request);
    }
    
    template<typename T>
    void write(uintptr_t address, T value)
    {
        write_memory((PVOID)address, &value, sizeof(T));
    }
    
    template<typename T>
    T read(uintptr_t address)
    {
        T buffer{};
        read_memory((PVOID)address, &buffer, sizeof(T));
        return buffer;
    }
};

int main()
{
    std::cout << "CR3 Ready Driver Client\n";
    std::cout << "=======================\n\n";
    
    DriverClient driver;
    
    if (!driver.setup())
    {
        std::cout << "Failed to initialize driver connection!\n";
        std::cout << "Make sure the CR3 Ready Driver is loaded.\n";
        return 1;
    }
    
    std::cout << "Driver connection established!\n";
    
    // Example: Find nightreign.exe process
    DWORD pid = driver.get_process_id("nightreign.exe");
    if (pid == 0)
    {
        std::cout << "nightreign.exe not found. Please start Elden Ring Nightreign first.\n";
        std::cout << "Game path: C:\\Program Files (x86)\\Steam\\steamapps\\common\\ELDEN RING NIGHTREIGN\\Game\\nightreign.exe\n";
        std::cout << "Waiting for process...\n";
        
        // Wait for process to start
        for (int i = 0; i < 30 && pid == 0; i++)
        {
            Sleep(1000);
            pid = driver.get_process_id("nightreign.exe");
            std::cout << ".";
        }
        std::cout << "\n";
    }
    
    if (pid != 0)
    {
        driver.process_id = pid;
        std::cout << "Found nightreign.exe PID: " << pid << "\n";
        
        uintptr_t base = driver.get_base_address();
        std::cout << "Base address: 0x" << std::hex << base << "\n";
        
        // Example memory read
        if (base != 0)
        {
            DWORD value = driver.read<DWORD>(base);
            std::cout << "Value at base: 0x" << std::hex << value << "\n";
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