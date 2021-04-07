#ifndef _TRACK_H_
#define _TRACK_H_

#ifdef __cplusplus
extern "C" {
#endif

#define IDC_STATIC							(-1)

#define IDD_DLG_TRACK						7750
#define IDC_EDIT_REGISTER					7751
#define IDC_EDIT_LOG						7752
#define IDC_TREE_LOG						7753
#define IDC_RESTART							7754
#define IDC_CONTINUE						7755

#define WM_UPDATETEXT						3379

	typedef struct _TREE_BLOCK_TRACK {
		HTREEITEM	Handle;
		CONTEXT		ThreadContext;

		ULONG		id;
		ULONG64		address;
		USHORT		size;
		UCHAR		bytes[24];
		CHAR		mnemonic[CS_MNEMONIC_SIZE];
		CHAR		op_str[160];
		cs_detail	detail;

		UT_hash_handle hh;
	}TREE_BLOCK_TRACK, * PTREE_BLOCK_TRACK;

	INT_PTR
		CALLBACK
		DialogTrack(
			__in HWND hWnd,
			__in UINT Msg,
			__in WPARAM wParam,
			__in LPARAM lParam
		);

#ifdef __cplusplus
}
#endif

#endif
