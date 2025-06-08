#pragma once
#pragma warning( disable : 4099 )

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
// Comment out the WDF include and use our own stub definitions since WDF is not available
// #include <wdf.h>
#include <ntimage.h>
#include <intrin.h>

// Include the root directory's stdafx.h which contains common structures
#include "../../stdafx.h"

#include "Utils.h"
#include "CallbackHandler.h"

#define print(fmt, ...) DbgPrintEx(0, 0, fmt, ##__VA_ARGS__)
