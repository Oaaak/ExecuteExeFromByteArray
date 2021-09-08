#pragma once
#include <Windows.h>
#include <chrono>
#include <thread>
#include <string>
#include <wdmguid.h>
#include <iostream>
using namespace std;
typedef unsigned char ExeData;
typedef IMAGE_DATA_DIRECTORY RelocationData;
typedef LONG(WINAPI* NtUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY;

#define RELOC_32BIT_FIELD 3