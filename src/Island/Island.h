#define UMDF_USING_NTSTATUS
#define _CRT_SECURE_NO_WARNINGS

#ifndef _ISLAND_H_
#define _ISLAND_H_

#include <stdio.h>
#include <ntstatus.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <winternl.h>
#include <windowsx.h>
#include <commctrl.h>
#include <cepluginsdk.h>

#include "uthash.h"

#include "Struct.h"
#include "Tools.h"
#include "Event.h"
#include "Track.h"
#include "Core.h"
#include "Stack.h"

#pragma warning(disable:4022)
#pragma warning(disable:4024)
#pragma warning(disable:4047)
#pragma warning(disable:4244)

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct _TRACK_BLOCK {

		HWND		TrackhWnd;
		ULONG		ProcessID;
		ULONG		ThreadID;
		ULONG_PTR	Peb;
//		ULONG_PTR	PebHandle;
		ULONG_PTR	Teb;

		ULONG64		DllBase;
		ULONG64		SizeOfImage;

		BOOL		Wow64Process;
		CONTEXT		DebugThreadContext;

		uc_engine*	uc_handle;
		uc_hook		uc_hook_code;
		uc_hook		uc_hook_intr;
		csh			cs_handle;

		PTREE_BLOCK_TRACK	TreeBlock;
		ExportedFunctions	Exported;

	}TRACK_BLOCK, * PTRACK_BLOCK;

	extern TRACK_BLOCK TrackBlock;

#ifdef __cplusplus
}
#endif

#endif