#include "stdafx.h"

UNICODE_STRING RegPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\DexzCHECK");
typedef NTSTATUS(*HookControl_t)(void* a1, void* a2);
HookControl_t OriginalPtr;
PVOID SharedBuffer = 0;
UINT SharedPid = 0;
ULONG64 NewMaggicCode = DEFAULT_MAGGICCODE;

NTSTATUS HookControl(PDEVICE_OBJECT device, PIRP irp) {
	UNREFERENCED_PARAMETER(device);
	UNREFERENCED_PARAMETER(irp);
	return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	return STATUS_SUCCESS;
}