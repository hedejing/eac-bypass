#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include "../../stdafx.h"

namespace Utils {
    namespace PhysicalMemory {
        ULONG_PTR GetProcessCr3(PEPROCESS Process);
        INT64 TranslateLinearAddress(ULONG_PTR DirectoryTableBase, ULONG64 VirtualAddress);
        NTSTATUS WritePhysicalAddress(PVOID TargetAddress, PVOID Buffer, SIZE_T Size, PSIZE_T BytesWritten);
        NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead);
    }

    PLDR_DATA_TABLE_ENTRY GetModuleByName(PEPROCESS Process, WCHAR* ModuleName);

    namespace Registry {
        template <typename T>
        T ReadRegistry(UNICODE_STRING RegPath, UNICODE_STRING KeyName) {
            // Default implementation - should be specialized in source file
            T defaultValue = {};
            return defaultValue;
        }

        NTSTATUS WriteRegistry(UNICODE_STRING RegPath, UNICODE_STRING KeyName, PVOID Data, ULONG Type, ULONG Size);
    }
} 