#include "Island.h"

VOID
WINAPI
RinPrint(
	__in LPCSTR cString,
	__in ...
)
{
	CHAR PrintString[MAX_PATH] = { 0 };
	CHAR Buffer[MAX_PATH] = { 0 };
	va_list ArgumentList;

	va_start(ArgumentList, cString);

	_vsnprintf_s(
		Buffer,
		sizeof(Buffer),
		sizeof(Buffer) - strlen(Buffer),
		cString,
		ArgumentList);

	va_end(ArgumentList);

	sprintf_s(PrintString, MAX_PATH, "[Island] %s", Buffer);

	OutputDebugStringA(PrintString);
}

ULONG_PTR
WINAPI
GetThreadTeb(
	__in ULONG ThreadID
)
{
	HANDLE ThreadHandle = NULL;
	THREAD_BASIC_INFORMATION ThreadInformation = { 0 };

	ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadID);

	if (ThreadHandle) {
		NtQueryInformationThread(
			ThreadHandle,
			0,
			&ThreadInformation,
			sizeof(ThreadInformation),
			NULL);

		CloseHandle(ThreadHandle);
	}

	return ThreadInformation.TebBaseAddress;
}

ULONG_PTR
WINAPI
GetThreadPeb(
	__in ULONG ProcessID,
	__in ULONG_PTR Teb
)
{
	HANDLE ProcessHandle = NULL;
	ULONG_PTR Peb = 0;

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

	if (ProcessHandle) {
		ReadProcessMemory(
			ProcessHandle,
			(PUCHAR)Teb + 0x60,
			&Peb,
			8,
			NULL);

		CloseHandle(ProcessHandle);
	}

	return Peb;
}

VOID
WINAPI
PebDebugHandle(
	VOID
)
{
	HANDLE ProcessHandle = NULL;

	CHAR BeingDebugged = 0;
	ULONG NtGlobalFlag = 0;

	ULONG ProcessHeapFlags = 2;
	ULONG ProcessHeapForceFlags = 0;

	ULONG64 ProcessHeap32 = 0;
	ULONG64 ProcessHeap64 = 0;

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TrackBlock.ProcessID);

	if (ProcessHandle) {
		if (TrackBlock.Wow64Process) {
			WriteProcessMemory(
				ProcessHandle,
				(PUCHAR)TrackBlock.Peb + 0x1000 + 0x2,
				&BeingDebugged,
				sizeof(BeingDebugged),
				NULL);

			WriteProcessMemory(
				ProcessHandle,
				(PUCHAR)TrackBlock.Peb + 0x1000 + 0x68,
				&NtGlobalFlag,
				sizeof(NtGlobalFlag),
				NULL);

			ReadProcessMemory(
				ProcessHandle,
				(PUCHAR)TrackBlock.Peb + 0x1000 + 0x18,
				&ProcessHeap32,
				4,
				NULL);

			WriteProcessMemory(
				ProcessHandle,
				(PUCHAR)ProcessHeap32 + 0x40,
				&ProcessHeapFlags,
				sizeof(ProcessHeapFlags),
				NULL);
			WriteProcessMemory(
				ProcessHandle,
				(PUCHAR)ProcessHeap32 + 0x44,
				&ProcessHeapForceFlags,
				sizeof(ProcessHeapForceFlags),
				NULL);
		}

		WriteProcessMemory(
			ProcessHandle,
			(PUCHAR)TrackBlock.Peb + 0x2,
			&BeingDebugged,
			sizeof(BeingDebugged),
			NULL);

		WriteProcessMemory(
			ProcessHandle,
			(PUCHAR)TrackBlock.Peb + 0xBC,
			&NtGlobalFlag,
			sizeof(NtGlobalFlag),
			NULL);

		ReadProcessMemory(
			ProcessHandle,
			(PUCHAR)TrackBlock.Peb + 0x30,
			&ProcessHeap64,
			8,
			NULL);

		WriteProcessMemory(
			ProcessHandle,
			(PUCHAR)ProcessHeap64 + 0x70,
			&ProcessHeapFlags,
			sizeof(ProcessHeapFlags),
			NULL);
		WriteProcessMemory(
			ProcessHandle,
			(PUCHAR)ProcessHeap64 + 0x74,
			&ProcessHeapForceFlags,
			sizeof(ProcessHeapForceFlags),
			NULL);

		CloseHandle(ProcessHandle);
	}
}