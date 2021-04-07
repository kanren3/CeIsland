#include "Island.h"

TRACK_BLOCK TrackBlock = { 0 };

BOOL
WINAPI
CEPlugin_GetVersion(
	__in PPluginVersion PV,
	__in INT SizeOfPluginVersion
)
{
	PV->version = CESDK_VERSION;
	PV->pluginname = "Welcome to Island.";

	return TRUE;
}

BOOL
WINAPI
CEPlugin_InitializePlugin(
	__in PExportedFunctions EF,
	__in INT PluginID
)
{
	INT Status = -1;

	MEMORYVIEWPLUGIN_INIT MemoryViewInit = { 0 };
	DEBUGEVENTPLUGIN_INIT DebugEventInit = { 0 };

	TrackBlock.Exported = *EF;

	MemoryViewInit.name = "Island:Track";
	MemoryViewInit.callbackroutine = (CEP_PLUGINTYPE1)MemoryViewPlugin;
	MemoryViewInit.shortcut = "Ctrl+Q";

	Status = TrackBlock.Exported.RegisterFunction(
		PluginID,
		ptMemoryView
		, &MemoryViewInit);
	if (Status == -1) {
		TrackBlock.Exported.ShowMessage("Failure to register the memoryview plugin");
		return FALSE;
	}

	DebugEventInit.callbackroutine = DebugEventPlugin;

	Status = TrackBlock.Exported.RegisterFunction(
		PluginID,
		ptOnDebugEvent,
		&DebugEventInit);
	if (Status == -1){
		TrackBlock.Exported.ShowMessage("Failure to register the ondebugevent plugin");
		return FALSE;
	}

	if (!NtFunctionBlock){
		NtFunctionBlock = malloc(sizeof(NT_FUNCTION_BLOCK) * 0x2000);
		RtlZeroMemory(
			NtFunctionBlock,
			sizeof(NT_FUNCTION_BLOCK) * 0x2000);

		if (NtFunctionBlock) {
			WalkNtFunctionSymbol64(LoadLibraryA("ntdll.dll"));
			WalkNtFunctionSymbol64(LoadLibraryA("win32u.dll"));
		}
	}

	SetWindowText(
		TrackBlock.Exported.GetMainWindowHandle(),
		TEXT("Island"));

	return TRUE;
}

BOOL
WINAPI
CEPlugin_DisablePlugin(
	VOID
)
{
	return TRUE;
}

BOOL
WINAPI
DllMain(
	__in HANDLE Handle,
	__in ULONG  Reason,
	__in LPVOID Reserved
)
{
	switch (Reason) {
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}