#include "Island.h"

PNT_FUNCTION_BLOCK NtFunctionBlock = NULL;

BOOL
WINAPI
FindEntryForKernelImageAddress32(
	__in ULONG Address,
	__out PLDR_DATA_TABLE_ENTRY32 DataTableEntry
)
{
	HANDLE ProcessHandle = NULL;

	PEB32 Peb;
	PEB_LDR_DATA32 Ldr;
	LDR_DATA_TABLE_ENTRY32 Entry;

	ULONG ModuleListHead;
	ULONG Next;

	ULONG Base = 0;
	ULONG Bound = 0;

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TrackBlock.ProcessID);

	if (TrackBlock.Peb && ProcessHandle) {
		ReadProcessMemory(
			ProcessHandle,
			TrackBlock.Peb + 0x1000,
			&Peb,
			sizeof(Peb),
			NULL);

		ReadProcessMemory(
			ProcessHandle,
			Peb.Ldr,
			&Ldr,
			sizeof(Ldr),
			NULL);

		ModuleListHead = Peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA32,
			InLoadOrderModuleList);

		Next = Ldr.InLoadOrderModuleList.Flink;

		if (Next) {
			while (Next != ModuleListHead) {
				ReadProcessMemory(
					ProcessHandle,
					Next,
					&Entry,
					sizeof(Entry),
					NULL);

				ReadProcessMemory(
					ProcessHandle,
					Next,
					&Next,
					sizeof(Next),
					NULL);

				Base = Entry.DllBase;
				Bound = Base + Entry.SizeOfImage;

				if (Address >= Base &&
					Address < Bound) {
					*DataTableEntry = Entry;
					return TRUE;
				}
			}
		}
		CloseHandle(ProcessHandle);
	}
	return FALSE;
}

BOOL
WINAPI
FindEntryForKernelImageAddress64(
	__in ULONG64 Address,
	__out PLDR_DATA_TABLE_ENTRY64 DataTableEntry
)
{
	HANDLE ProcessHandle = NULL;

	PEB64 Peb;
	PEB_LDR_DATA64 Ldr;
	LDR_DATA_TABLE_ENTRY64 Entry;

	ULONG64 ModuleListHead;
	ULONG64 Next;

	ULONG64 Base = 0;
	ULONG64 Bound = 0;

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TrackBlock.ProcessID);

	if (TrackBlock.Peb && ProcessHandle) {
		ReadProcessMemory(
			ProcessHandle,
			TrackBlock.Peb,
			&Peb,
			sizeof(Peb),
			NULL);

		ReadProcessMemory(
			ProcessHandle,
			Peb.Ldr,
			&Ldr,
			sizeof(Ldr),
			NULL);

		ModuleListHead = Peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA32,
			InLoadOrderModuleList);

		Next = Ldr.InLoadOrderModuleList.Flink;

		if (Next) {
			while (Next != ModuleListHead) {
				ReadProcessMemory(
					ProcessHandle,
					Next,
					&Entry,
					sizeof(Entry),
					NULL);

				ReadProcessMemory(
					ProcessHandle,
					Next,
					&Next,
					sizeof(Next),
					NULL);

				Base = Entry.DllBase;
				Bound = Base + Entry.SizeOfImage;

				if (Address >= Base &&
					Address < Bound) {
					*DataTableEntry = Entry;
					return TRUE;
				}
			}
		}
		CloseHandle(ProcessHandle);
	}
	return FALSE;
}

BOOL
WINAPI
FindImageBase32(
	__out PLDR_DATA_TABLE_ENTRY32 DataTableEntry
)
{
	HANDLE ProcessHandle = NULL;

	PEB32 Peb;
	PEB_LDR_DATA32 Ldr;
	LDR_DATA_TABLE_ENTRY32 Entry;
	LDR_DATA_TABLE_ENTRY32 ExeEntry;

	ULONG ModuleListHead;
	ULONG Next;

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TrackBlock.ProcessID);

	if (TrackBlock.Peb && ProcessHandle) {
		ReadProcessMemory(
			ProcessHandle,
			TrackBlock.Peb + 0x1000,
			&Peb,
			sizeof(Peb),
			NULL);

		ReadProcessMemory(
			ProcessHandle,
			Peb.Ldr,
			&Ldr,
			sizeof(Ldr),
			NULL);

		ModuleListHead = Peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA32,
			InLoadOrderModuleList);

		Next = Ldr.InLoadOrderModuleList.Flink;

		if (Next) {
			ReadProcessMemory(
				ProcessHandle,
				Next,
				&ExeEntry,
				sizeof(ExeEntry),
				NULL);

			while (Next != ModuleListHead) {
				ReadProcessMemory(
					ProcessHandle,
					Next,
					&Entry,
					sizeof(Entry),
					NULL);

				ReadProcessMemory(
					ProcessHandle,
					Next,
					&Next,
					sizeof(Next),
					NULL);

				if (TrackBlock.DebugThreadContext.Rip > Entry.DllBase &&
					TrackBlock.DebugThreadContext.Rip < Entry.DllBase + Entry.SizeOfImage)
				{
					*DataTableEntry = Entry;
					return TRUE;
				}
			}
			*DataTableEntry = ExeEntry;
		}
		CloseHandle(ProcessHandle);
	}
	return FALSE;
}

BOOL
WINAPI
FindImageBase64(
	__out PLDR_DATA_TABLE_ENTRY64 DataTableEntry
)
{
	HANDLE ProcessHandle = NULL;

	PEB64 Peb;
	PEB_LDR_DATA64 Ldr;
	LDR_DATA_TABLE_ENTRY64 Entry;
	LDR_DATA_TABLE_ENTRY64 ExeEntry;

	ULONG64 ModuleListHead;
	ULONG64 Next;

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TrackBlock.ProcessID);

	if (TrackBlock.Peb && ProcessHandle) {
		ReadProcessMemory(
			ProcessHandle,
			TrackBlock.Peb,
			&Peb,
			sizeof(Peb),
			NULL);

		ReadProcessMemory(
			ProcessHandle,
			Peb.Ldr,
			&Ldr,
			sizeof(Ldr),
			NULL);

		ModuleListHead = Peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA32,
			InLoadOrderModuleList);

		Next = Ldr.InLoadOrderModuleList.Flink;

		if (Next) {
			ReadProcessMemory(
				ProcessHandle,
				Next,
				&ExeEntry,
				sizeof(ExeEntry),
				NULL);

			while (Next != ModuleListHead) {
				ReadProcessMemory(
					ProcessHandle,
					Next,
					&Entry,
					sizeof(Entry),
					NULL);

				ReadProcessMemory(
					ProcessHandle,
					Next,
					&Next,
					sizeof(Next),
					NULL);
				
				if (TrackBlock.DebugThreadContext.Rip > Entry.DllBase &&
					TrackBlock.DebugThreadContext.Rip < Entry.DllBase + Entry.SizeOfImage)
				{
					*DataTableEntry = Entry;
					return TRUE;
				}
			}
			*DataTableEntry = ExeEntry;
		}
		CloseHandle(ProcessHandle);
	}
	return FALSE;
}

VOID
NTAPI
WalkNtFunctionSymbol64(
	__in ULONG64 DllBase
)
{
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS64 NtHeaders;

	PIMAGE_EXPORT_DIRECTORY ExportDirectory;

	PULONG NameTable = 0;
	PCHAR Name = 0;

	PUSHORT OrdinalTable = 0;
	USHORT Ordinal = 0;

	PULONG AddressTable = 0;
	ULONG64 Address = 0;

	USHORT FunctionIndex = 0;
	USHORT NameIndex = 0;

	ULONG NtIndex = 0;


	DosHeader = DllBase;
	NtHeaders = DllBase + DosHeader->e_lfanew;


	ExportDirectory = NtHeaders->OptionalHeader.
		DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + DllBase;

	if (ExportDirectory) {

		NameTable =
			DllBase + ExportDirectory->AddressOfNames;

		OrdinalTable =
			DllBase + ExportDirectory->AddressOfNameOrdinals;

		AddressTable =
			DllBase + ExportDirectory->AddressOfFunctions;

		if (ExportDirectory->AddressOfNames &&
			ExportDirectory->AddressOfNameOrdinals &&
			ExportDirectory->AddressOfFunctions) {

			for (FunctionIndex = 0;
				FunctionIndex < ExportDirectory->NumberOfFunctions;
				FunctionIndex++) {

				Name = NULL;

				for (NameIndex = 0;
					NameIndex < ExportDirectory->NumberOfNames;
					NameIndex++) {
					Ordinal = OrdinalTable[NameIndex];

					if (Ordinal == FunctionIndex) {
						Name = DllBase + NameTable[NameIndex];
						Address = DllBase + AddressTable[Ordinal];
						Ordinal += ExportDirectory->Base;
						break;
					}
				}

				if (Name) {
					if (Name[0] == 'N' &&
						Name[1] == 't') {
						RtlCopyMemory(
							&NtIndex,
							Address + 4,
							sizeof(NtIndex));

						if (NtIndex < 0x2000) {
							NtFunctionBlock[NtIndex].Address = Address;
							NtFunctionBlock[NtIndex].Name = Name;
						}
					}
				}
				else {
					Address = DllBase + AddressTable[FunctionIndex];
					Ordinal = ExportDirectory->Base + FunctionIndex;
				}
			}
		}
	}
}