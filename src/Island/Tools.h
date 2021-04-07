#ifndef _TOOLS_H_
#define _TOOLS_H_

#ifdef __cplusplus
extern "C" {
#endif

	VOID
		WINAPI
		RinPrint(
			__in LPCSTR cString,
			__in ...
		);

	ULONG_PTR
		WINAPI
		GetThreadTeb(
			__in ULONG ThreadID
		);

	ULONG_PTR
		WINAPI
		GetThreadPeb(
			__in ULONG ProcessID,
			__in ULONG_PTR Teb
		);

	VOID
		WINAPI
		PebDebugHandle(
			VOID
		);

#ifdef __cplusplus
}
#endif

#endif
