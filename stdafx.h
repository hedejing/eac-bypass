#pragma once
#pragma warning( disable : 4099 )

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>
#include <intrin.h>

// Common structures and definitions used by both drivers
#define DEFAULT_MAGGICCODE 0x999999999

// Additional function declarations missing from standard headers
extern "C" {
    NTSTATUS MmCopyVirtualMemory(
        PEPROCESS SourceProcess,
        PVOID SourceAddress,
        PEPROCESS TargetProcess,
        PVOID TargetAddress,
        SIZE_T BufferSize,
        KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize
    );
    
    NTSTATUS ZwProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );
    
    NTSTATUS PsLookupProcessByProcessId(
        HANDLE ProcessId,
        PEPROCESS *Process
    );
    
    VOID KeAttachProcess(
        PRKPROCESS Process
    );
    
    VOID KeDetachProcess(
    );
    
    PVOID PsGetProcessSectionBaseAddress(
        PEPROCESS Process
    );
    
    // VOID ObfDereferenceObject(PVOID Object); // Commented out - conflicts with WDK definition
    
    NTSTATUS ZwAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );
    
    NTSTATUS ZwFreeVirtualMemory(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        PSIZE_T RegionSize,
        ULONG FreeType
    );
}

// Define LDR_DATA_TABLE_ENTRY structure
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// Request types
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

// Request structures
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

// Common utilities namespace
namespace Utils {
    namespace PhysicalMemory {
        ULONG_PTR GetProcessCr3(PEPROCESS Process);
        INT64 TranslateLinearAddress(ULONG_PTR DirectoryTableBase, ULONG64 VirtualAddress);
        NTSTATUS WritePhysicalAddress(PVOID TargetAddress, PVOID Buffer, SIZE_T Size, PSIZE_T BytesWritten);
        NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead);
    }

    // Fix the syntax error by correctly declaring GetModuleByName
    PLDR_DATA_TABLE_ENTRY GetModuleByName(PEPROCESS Process, WCHAR* ModuleName);

    namespace Registry {
        template <typename T>
        T ReadRegistry(UNICODE_STRING RegPath, UNICODE_STRING KeyName);
        NTSTATUS WriteRegistry(UNICODE_STRING RegPath, UNICODE_STRING KeyName, PVOID Data, ULONG Type, ULONG Size);
    }
}

// Function declarations
NTSTATUS CallbackWRITE(PREQUEST_WRITE args);
NTSTATUS CallbackREAD(PREQUEST_READ args);
NTSTATUS CallbackPROTECT(PREQUEST_PROTECT args);
NTSTATUS CallbackALLOC(PREQUEST_ALLOC args);
NTSTATUS CallbackFREE(PREQUEST_FREE args);
NTSTATUS CallbackMODULE(PREQUEST_MODULE args);
NTSTATUS CallbackMAINBASE(PREQUEST_MAINBASE args);

#define CallbackHandler(type) \
case type: { \
    status = Callback##type(&data.Data.type); \
    break; \
} 
