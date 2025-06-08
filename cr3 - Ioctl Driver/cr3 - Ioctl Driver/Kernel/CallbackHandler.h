#pragma once
#include "../../stdafx.h"

// Function declarations (implementations are in CallbackHandler.cpp)
NTSTATUS CallbackWRITE(PREQUEST_WRITE args);
NTSTATUS CallbackREAD(PREQUEST_READ args);
NTSTATUS CallbackPROTECT(PREQUEST_PROTECT args);
NTSTATUS CallbackALLOC(PREQUEST_ALLOC args);
NTSTATUS CallbackFREE(PREQUEST_FREE args);
NTSTATUS CallbackMODULE(PREQUEST_MODULE args);
NTSTATUS CallbackMAINBASE(PREQUEST_MAINBASE args); 