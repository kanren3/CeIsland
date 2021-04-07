#ifndef _STACK_H_
#define _STACK_H_

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct _NT_FUNCTION_BLOCK {
		PCHAR	Name;
		ULONG64	Address;
	}NT_FUNCTION_BLOCK, * PNT_FUNCTION_BLOCK;

	extern PNT_FUNCTION_BLOCK NtFunctionBlock;

	BOOL
		WINAPI
		FindEntryForKernelImageAddress32(
			__in ULONG Address,
			__out PLDR_DATA_TABLE_ENTRY32 DataTableEntry
		);

	BOOL
		WINAPI
		FindEntryForKernelImageAddress64(
			__in ULONG64 Address,
			__out PLDR_DATA_TABLE_ENTRY64 DataTableEntry
		);

	BOOL
		WINAPI
		FindImageBase32(
			__out PLDR_DATA_TABLE_ENTRY32 DataTableEntry
		);

	BOOL
		WINAPI
		FindImageBase64(
			__out PLDR_DATA_TABLE_ENTRY64 DataTableEntry
		);

	VOID
		NTAPI
		WalkNtFunctionSymbol64(
			__in ULONG64 DllBase
		);


#ifdef __cplusplus
}
#endif

#endif
