#include "Island.h"

ULONG
WINAPI
TrackViewThread(
	__in LPVOID lpThreadParameter
)
{
	DialogBoxParamA(
		GetModuleHandleA("Island.dll"),
		MAKEINTRESOURCE(IDD_DLG_TRACK),
		NULL,
		DialogTrack,
		0);

	return 0;
}

BOOL
WINAPI
MemoryViewPlugin(
	__in PULONG_PTR DisAssemblerAddress,
	__in PULONG_PTR SelectedDisAssemblerAddress,
	__in PULONG_PTR HexViewAddress
)
{
	CreateThread(
		NULL,
		0,
		TrackViewThread,
		NULL,
		0,
		NULL);

	return TRUE;
}

INT
WINAPI
DebugEventPlugin(
	__in LPDEBUG_EVENT DebugEvent
)
{
	HANDLE ProcessHandle = NULL;
	HANDLE ThreadHandle = NULL;

	LDR_DATA_TABLE_ENTRY64 Entry = { 0 };
	LDR_DATA_TABLE_ENTRY32 Wow64Entry = { 0 };

	TrackBlock.ProcessID = DebugEvent->dwProcessId;

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE,
		DebugEvent->dwProcessId);

	if (ProcessHandle) {
		IsWow64Process(ProcessHandle, &TrackBlock.Wow64Process);
		CloseHandle(ProcessHandle);
	}

	if (STATUS_SINGLE_STEP ==
		DebugEvent->u.Exception.ExceptionRecord.ExceptionCode ||
		STATUS_WX86_SINGLE_STEP == DebugEvent->u.Exception.ExceptionRecord.ExceptionCode) {
		ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE,
			DebugEvent->dwThreadId);

		TrackBlock.ThreadID = DebugEvent->dwThreadId;
		TrackBlock.Teb = GetThreadTeb(TrackBlock.ThreadID);

		if (TrackBlock.Peb != GetThreadPeb(TrackBlock.ProcessID, TrackBlock.Teb)) {
			TrackBlock.Peb = GetThreadPeb(TrackBlock.ProcessID, TrackBlock.Teb);
			PebDebugHandle();
		}

		if (ThreadHandle) {
			TrackBlock.DebugThreadContext.ContextFlags = CONTEXT_ALL;
			if (GetThreadContext(ThreadHandle, &TrackBlock.DebugThreadContext)) {

				if (!TrackBlock.Wow64Process) {
					if (FindImageBase64(&Entry)) {
						TrackBlock.DllBase = Entry.DllBase;
						TrackBlock.SizeOfImage = Entry.SizeOfImage;
					}
				}
				else {
					if (FindImageBase32(&Wow64Entry)) {
						TrackBlock.DllBase = Wow64Entry.DllBase;
						TrackBlock.SizeOfImage = Wow64Entry.SizeOfImage;
					}
				}

				if (TrackBlock.TrackhWnd) {
					SendMessageTimeoutA(
						TrackBlock.TrackhWnd,
						WM_UPDATETEXT,
						0, 0,
						SMTO_BLOCK, 300,
						NULL);
				}
			}
			CloseHandle(ThreadHandle);
		}
	}

	return 0;
}