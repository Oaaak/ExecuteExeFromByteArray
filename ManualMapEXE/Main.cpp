#include "Includes.h"
#include "Utils.h"
#include "ExeData.h"



int main() {
	NtUnmapViewOfSection_t NtUnmapViewOfSection;
	IMAGE_NT_HEADERS* NTHeaders = Utils::GetNTHeaders(Data);
	if (NTHeaders == NULL) {
		Utils::Print("Invalid NTHeaders");
		return 0;
	}
	RelocationData* relocdata = Utils::GetRelocationData(Data, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	auto Addr = (LPVOID)NTHeaders->OptionalHeader.ImageBase;
	NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtUnmapViewOfSection");
	NtUnmapViewOfSection((HANDLE)-1, (LPVOID)NTHeaders->OptionalHeader.ImageBase);
	unsigned char* base = (unsigned char*)VirtualAlloc(Addr, NTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!base && !relocdata)
		return 0;

	if (!base && relocdata) { //make new base
		base = (unsigned char*)VirtualAlloc(NULL, NTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	NTHeaders->OptionalHeader.ImageBase = (DWORD)base; //update
	memcpy(base, Data, NTHeaders->OptionalHeader.SizeOfHeaders); //mapping

	IMAGE_SECTION_HEADER* SecHeaderAddr = (IMAGE_SECTION_HEADER*)((unsigned int)(NTHeaders)+sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < NTHeaders->FileHeader.NumberOfSections; i++)
	{
		memcpy
		(
			LPVOID((unsigned int)(base)+SecHeaderAddr[i].VirtualAddress),
			LPVOID((unsigned int)(Data)+SecHeaderAddr[i].PointerToRawData),
			SecHeaderAddr[i].SizeOfRawData
		);
	}
	Utils::FixImportAddressTable(base);
	if (base != Addr)
		Utils::ApplyRelocation((size_t)base, (size_t)Addr, base, NTHeaders->OptionalHeader.SizeOfImage);
	size_t ReturnAddress = (size_t)(base)+NTHeaders->OptionalHeader.AddressOfEntryPoint;
	((void(*)())ReturnAddress)();
	return 1;
}


