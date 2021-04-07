#ifndef _EVENT_H_
#define _EVENT_H_

#ifdef __cplusplus
extern "C" {
#endif

	BOOL
		WINAPI
		MemoryViewPlugin(
			__in PULONG_PTR DisAssemblerAddress,
			__in PULONG_PTR SelectedDisAssemblerAddress,
			__in PULONG_PTR HexViewAddress
		);

	INT
		WINAPI
		DebugEventPlugin(
			__in LPDEBUG_EVENT DebugEvent
		);


#ifdef __cplusplus
}
#endif

#endif
