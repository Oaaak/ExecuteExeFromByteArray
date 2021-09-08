#pragma once
#include "Includes.h"

#define PEMAXOFFSET 1024

namespace Utils {
	
	
	IMAGE_NT_HEADERS* GetNTHeaders(ExeData* data)
	{
		if (data == NULL) 
			return NULL;

		IMAGE_DOS_HEADER* dheader = (IMAGE_DOS_HEADER*)data;
		if (dheader->e_magic != IMAGE_DOS_SIGNATURE) 
			return NULL;
	
		long Offset = dheader->e_lfanew;
		if (Offset > PEMAXOFFSET) 
			return NULL;

		IMAGE_NT_HEADERS32* NTHeader = (IMAGE_NT_HEADERS32*)((ExeData*)data + Offset);
		if (NTHeader->Signature != IMAGE_NT_SIGNATURE)
			return NULL;

		return NTHeader;
	}
    void Print(const char* T) {
        auto sysc = std::chrono::system_clock::now();


        time_t systime = time(0);
        tm* ctime = localtime(&systime);
        string c = ctime->tm_sec > 9 ? to_string(ctime->tm_sec) : "0" + to_string(ctime->tm_sec);
        string m = ctime->tm_min > 9 ? to_string(ctime->tm_min) : "0" + to_string(ctime->tm_min);
        string h = ctime->tm_hour > 9 ? to_string(ctime->tm_hour) : "0" + to_string(ctime->tm_hour);
        string stime = h + ":" + m + ":" + c;
        std::cout << "[" + stime + "]: " + T + "\n";
    }
	RelocationData* GetRelocationData(ExeData* data, int dir_id)
	{
		if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
			return NULL;

		auto NTHeaders = GetNTHeaders(data);
		if (NTHeaders == NULL)
			return NULL;


		RelocationData* RelocDat = &(NTHeaders->OptionalHeader.DataDirectory[dir_id]);

		if (RelocDat->VirtualAddress == NULL) {
			return NULL;
		}
		return RelocDat;
	}
	bool ApplyRelocation(ULONGLONG newBase, ULONGLONG oldBase, ExeData* modulePtr, SIZE_T moduleSize)
	{
		IMAGE_DATA_DIRECTORY* relocDir = GetRelocationData(modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC);
		if (relocDir == NULL)
			return false;

		size_t maxSize = relocDir->Size;
		size_t relocAddr = relocDir->VirtualAddress;
		IMAGE_BASE_RELOCATION* reloc = NULL;

		size_t parsedSize = 0;
		for (; parsedSize < maxSize; parsedSize += reloc->SizeOfBlock) {
			reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + size_t(modulePtr));
			if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0)
				break;

			size_t entriesNum = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
			size_t page = reloc->VirtualAddress;

			BASE_RELOCATION_ENTRY* entry = (BASE_RELOCATION_ENTRY*)(size_t(reloc) + sizeof(IMAGE_BASE_RELOCATION));
			for (size_t i = 0; i < entriesNum; i++) {
				size_t offset = entry->Offset;
				size_t type = entry->Type;
				size_t reloc_field = page + offset;
				if (entry == NULL || type == 0)
					break;
				if (type != RELOC_32BIT_FIELD) {
					return false;
				}
				if (reloc_field >= moduleSize) {
					return false;
				}

				size_t* relocateAddr = (size_t*)(size_t(modulePtr) + reloc_field);
				(*relocateAddr) = ((*relocateAddr) - oldBase + newBase);
				entry = (BASE_RELOCATION_ENTRY*)(size_t(entry) + sizeof(BASE_RELOCATION_ENTRY));
			}
		}
		return (parsedSize != 0);
	}
	bool FixImportAddressTable(ExeData* modulePtr)
	{
		IMAGE_DATA_DIRECTORY* Imports = GetRelocationData(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
		if (Imports == NULL) return false;

		size_t MAx = Imports->Size;
		size_t VirtualImportAddress = Imports->VirtualAddress;

		IMAGE_IMPORT_DESCRIPTOR* _lib = NULL;
		size_t Size = 0;

		for (; Size < MAx; Size += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
			_lib = (IMAGE_IMPORT_DESCRIPTOR*)(VirtualImportAddress + Size + (ULONG_PTR)modulePtr);

			if (_lib->OriginalFirstThunk == NULL && _lib->FirstThunk == NULL) break;
			LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + _lib->Name);

			size_t call_via = _lib->FirstThunk;
			size_t thunk_addr = _lib->OriginalFirstThunk;
			if (thunk_addr == NULL) thunk_addr = _lib->FirstThunk;

			size_t Field = 0;
			size_t Offset = 0;
			while (true)
			{
				IMAGE_THUNK_DATA* Thunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + Field + call_via);
				IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + Offset + thunk_addr);

				if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) // check if using ordinal (both x86 && x64)
				{
					size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));

					Thunk->u1.Function = addr;
				}

				if (Thunk->u1.Function == NULL) break;

				if (Thunk->u1.Function == orginThunk->u1.Function) {

					PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)(size_t(modulePtr) + orginThunk->u1.AddressOfData);

					LPSTR func_name = (LPSTR)by_name->Name;
					size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name);



					Thunk->u1.Function = addr;

				}
				Field += sizeof(IMAGE_THUNK_DATA);
				Offset += sizeof(IMAGE_THUNK_DATA);
			}
		}
		return true;
	}
}

