#include "Island.h"

HTREEITEM
WINAPI
TreeViewInsertItem(
	__in HTREEITEM hParent,
	__in LPCSTR Text,
	__in ...
)
{
	HTREEITEM wnd = NULL;

	TVINSERTSTRUCTA TvInsertItem;
	CHAR Buffer[0x1000] = { 0 };
	va_list ArgumentList;

	va_start(ArgumentList, Text);
	_vsnprintf_s(
		Buffer,
		sizeof(Buffer),
		sizeof(Buffer) - strlen(Buffer),
		Text,
		ArgumentList);
	va_end(ArgumentList);

	TvInsertItem.hParent = hParent;
	TvInsertItem.hInsertAfter = TVI_LAST;
	TvInsertItem.item.mask = TVIF_TEXT;
	TvInsertItem.item.pszText = Buffer;

	wnd = TreeView_InsertItem(GetDlgItem(TrackBlock.TrackhWnd, IDC_TREE_LOG), &TvInsertItem);
	TreeView_SetAutoScrollInfo(GetDlgItem(TrackBlock.TrackhWnd, IDC_TREE_LOG), 500, 10);
	return wnd;
}

VOID
WINAPI
EditInsertText(
	__in HWND hWnd,
	__in LPCSTR Text,
	__in ...
)
{
	CHAR CurrentText[0x1000] = { 0 };
	CHAR Buffer[0x1000] = { 0 };
	va_list ArgumentList;

	va_start(ArgumentList, Text);
	_vsnprintf_s(
		Buffer,
		sizeof(Buffer),
		sizeof(Buffer) - strlen(Buffer),
		Text,
		ArgumentList);
	va_end(ArgumentList);

	Edit_GetText(hWnd, CurrentText, 0x1000);
	strcat_s(CurrentText, 0x1000, Buffer);
	Edit_SetText(hWnd, CurrentText);
}

VOID
WINAPI
EditPrintRegisters(
	__in HWND hWnd,
	__in CONTEXT ThreadContext
)
{
	Edit_SetText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "");
	if (!TrackBlock.Wow64Process)
	{
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "RAX: %016llX\r\n", ThreadContext.Rax);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "RBX: %016llX\r\n", ThreadContext.Rbx);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "RCX: %016llX\r\n", ThreadContext.Rcx);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "RDX: %016llX\r\n", ThreadContext.Rdx);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "RSI: %016llX\r\n", ThreadContext.Rsi);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "RDI: %016llX\r\n", ThreadContext.Rdi);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "RBP: %016llX\r\n", ThreadContext.Rbp);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "RSP: %016llX\r\n", ThreadContext.Rsp);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "R8: %016llX\r\n", ThreadContext.R8);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "R9: %016llX\r\n", ThreadContext.R9);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "R10: %016llX\r\n", ThreadContext.R10);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "R11: %016llX\r\n", ThreadContext.R11);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "R12: %016llX\r\n", ThreadContext.R12);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "R13: %016llX\r\n", ThreadContext.R13);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "R14: %016llX\r\n", ThreadContext.R14);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "R15: %016llX\r\n", ThreadContext.R15);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "RIP: %016llX\r\n", ThreadContext.Rip);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "EFlags: %016llX\r\n", ThreadContext.EFlags);
	}
	else
	{
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "EAX: %08X\r\n", (ULONG)ThreadContext.Rax);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "EBX: %08X\r\n", (ULONG)ThreadContext.Rbx);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "ECX: %08X\r\n", (ULONG)ThreadContext.Rcx);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "EDX: %08X\r\n", (ULONG)ThreadContext.Rdx);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "ESI: %08X\r\n", (ULONG)ThreadContext.Rsi);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "EDI: %08X\r\n", (ULONG)ThreadContext.Rdi);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "EBP: %08X\r\n", (ULONG)ThreadContext.Rbp);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "ESP: %08X\r\n", (ULONG)ThreadContext.Rsp);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "EIP: %08X\r\n", (ULONG)ThreadContext.Rip);
		EditInsertText(GetDlgItem(hWnd, IDC_EDIT_REGISTER), "EFlags: %08X\r\n", (ULONG)ThreadContext.EFlags);
	}
}

VOID
WINAPI
SetWindowTextEx(
	__in HWND Wnd,
	__in LPCSTR Text,
	__in ...
)
{
	CHAR Buffer[0x1000] = { 0 };
	va_list ArgumentList;

	va_start(ArgumentList, Text);
	_vsnprintf_s(
		Buffer,
		sizeof(Buffer),
		sizeof(Buffer) - strlen(Buffer),
		Text,
		ArgumentList);
	va_end(ArgumentList);

	SetWindowTextA(
		Wnd,
		Buffer);
}

HTREEITEM ParentHandle = NULL;
BOOL IsStop = FALSE;

VOID
WINAPI
HookCodeHandler(
	__in uc_engine* uc,
	__in uint64_t address,
	__in size_t size,
	__in uint64_t user_data
)
{
	if (IsStop) { uc_emu_stop(uc); }

	CONTEXT Context;

	if (!TrackBlock.Wow64Process)
	{
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_RAX, &Context.Rax);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_RBX, &Context.Rbx);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_RCX, &Context.Rcx);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_RDX, &Context.Rdx);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_RSI, &Context.Rsi);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_RDI, &Context.Rdi);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_RBP, &Context.Rbp);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_RSP, &Context.Rsp);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_R8, &Context.R8);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_R9, &Context.R9);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_R10, &Context.R10);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_R11, &Context.R11);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_R12, &Context.R12);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_R13, &Context.R13);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_R14, &Context.R14);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_R15, &Context.R15);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_RIP, &Context.Rip);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_EFLAGS, &Context.EFlags);
	}
	else
	{
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_EAX, &Context.Rax);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_EBX, &Context.Rbx);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_ECX, &Context.Rcx);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_EDX, &Context.Rdx);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_ESI, &Context.Rsi);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_EDI, &Context.Rdi);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_EBP, &Context.Rbp);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_ESP, &Context.Rsp);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_EIP, &Context.Rip);
		uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_EFLAGS, &Context.EFlags);
	}

	cs_insn insn = { 0 };
	uint8_t temp[16] = { 0 };
	uint8_t* buffer = temp;

	uc_mem_read(TrackBlock.uc_handle, address, temp, sizeof(temp));
	if (cs_disasm_iter(TrackBlock.cs_handle, &buffer, &size, &address, &insn)) {

		PTREE_BLOCK_TRACK Block = NULL;

		if (strstr(insn.op_str, "fs")||
			strstr(insn.op_str, "gs")||
			strstr(insn.op_str, "cs")||
			strstr(insn.mnemonic, "fs")||
			strstr(insn.mnemonic, "gs")||
			strstr(insn.mnemonic, "cs"))
		{
			Block = malloc(sizeof(TREE_BLOCK_TRACK));
			RtlZeroMemory(Block, sizeof(TREE_BLOCK_TRACK));

			Block->ThreadContext = Context;

			CHAR ModuleName[MAX_PATH] = { 0 };
			TrackBlock.Exported.sym_addressToName(Context.Rip, ModuleName, sizeof(ModuleName));


			Block->Handle = TreeViewInsertItem(
				ParentHandle,
				"%s  %s %s",
				ModuleName,
				insn.mnemonic,
				insn.op_str);

			Block->address = insn.address;
			Block->size = insn.size;
			Block->id = insn.id;
			memcpy(Block->bytes, insn.bytes, sizeof(insn.bytes));
			memcpy(Block->op_str, insn.op_str, sizeof(insn.op_str));
			memcpy(Block->mnemonic, insn.mnemonic, sizeof(insn.mnemonic));

			if (insn.detail) {
				Block->detail = *insn.detail;
			}

			HASH_ADD(hh, TrackBlock.TreeBlock, Handle, sizeof(HTREEITEM), Block);
		}
		else
		{
			if (!strcmp(insn.mnemonic, "syscall") ||
				strstr(insn.op_str, "33:"))
			{
				Block = malloc(sizeof(TREE_BLOCK_TRACK));
				RtlZeroMemory(Block, sizeof(TREE_BLOCK_TRACK));

				Block->ThreadContext = Context;

				CHAR ModuleName[MAX_PATH] = { 0 };
				TrackBlock.Exported.sym_addressToName(Context.Rip, ModuleName, sizeof(ModuleName));

				Block->Handle = TreeViewInsertItem(
					ParentHandle,
					"%s  %s (%s)",
					ModuleName,
					insn.mnemonic,
					NtFunctionBlock[(USHORT)Context.Rax].Name);

				Block->address = insn.address;
				Block->size = insn.size;
				Block->id = insn.id;
				memcpy(Block->bytes, insn.bytes, sizeof(insn.bytes));
				memcpy(Block->op_str, insn.op_str, sizeof(insn.op_str));
				memcpy(Block->mnemonic, insn.mnemonic, sizeof(insn.mnemonic));

				if (insn.detail) {
					Block->detail = *insn.detail;
				}

				HASH_ADD(hh, TrackBlock.TreeBlock, Handle, sizeof(HTREEITEM), Block);

				IsStop = TRUE;
			}
		}

		if (ParentHandle == NULL) {
			if (address < TrackBlock.DllBase ||
				address > TrackBlock.DllBase + TrackBlock.SizeOfImage) {

				Block = malloc(sizeof(TREE_BLOCK_TRACK));
				RtlZeroMemory(Block, sizeof(TREE_BLOCK_TRACK));

				Block->ThreadContext = Context;

				CHAR ModuleName[MAX_PATH] = { 0 };
				TrackBlock.Exported.sym_addressToName(Context.Rip, ModuleName, sizeof(ModuleName));

				Block->Handle = TreeViewInsertItem(
					ParentHandle,
					"%s  %s %s",
					ModuleName,
					insn.mnemonic,
					insn.op_str);

				Block->address = insn.address;
				Block->size = insn.size;
				Block->id = insn.id;
				memcpy(Block->bytes, insn.bytes, sizeof(insn.bytes));
				memcpy(Block->op_str, insn.op_str, sizeof(insn.op_str));
				memcpy(Block->mnemonic, insn.mnemonic, sizeof(insn.mnemonic));

				if (insn.detail) {
					Block->detail = *insn.detail;
				}

				HASH_ADD(hh, TrackBlock.TreeBlock, Handle, sizeof(HTREEITEM), Block);

				ParentHandle = Block->Handle;
			}
		}
		else {
			if (address > TrackBlock.DllBase &&
				address < TrackBlock.DllBase + TrackBlock.SizeOfImage)
			{
				ParentHandle = NULL;
			}
		}
	}
}


VOID
WINAPI
HashDeleteAll(
	VOID
)
{
	PTREE_BLOCK_TRACK current_user, tmp;

	HASH_ITER(hh, TrackBlock.TreeBlock, current_user, tmp) {
		HASH_DEL(TrackBlock.TreeBlock, current_user);
		free(current_user);
	}

	HASH_CLEAR(hh, TrackBlock.TreeBlock);
}

INT_PTR
CALLBACK
DialogTrack(
	__in HWND hWnd,
	__in UINT Msg,
	__in WPARAM wParam,
	__in LPARAM lParam
)
{
	uc_err uc_error = UC_ERR_OK;

	LPNMTREEVIEW TreeView = NULL;

	switch (Msg) {
	case WM_INITDIALOG: {
		InitCommonControls();
		TrackBlock.TrackhWnd = hWnd;
		SetWindowTextEx(hWnd, "Address:%llX\n", TrackBlock.DebugThreadContext.Rip);
		break;
	}
	case WM_UPDATETEXT: {
		SetWindowTextEx(hWnd, "Address:%llX\n", TrackBlock.DebugThreadContext.Rip);
		break;
	}
	case WM_COMMAND: {
		if (!TrackBlock.DebugThreadContext.Rip) {
			break;
		}
		if (lParam == (LPARAM)GetDlgItem(hWnd, IDC_RESTART)) {
			if (OpenCore()) {
				if (MapVirtualMemory()) {
					MapRegister();
					MapSegment();

					TreeView_DeleteAllItems(GetDlgItem(hWnd, IDC_TREE_LOG));
					HashDeleteAll();

					uc_hook_add(
						TrackBlock.uc_handle,
						&TrackBlock.uc_hook_code,
						UC_HOOK_CODE,
						HookCodeHandler,
						NULL, 1, 0);

					IsStop = FALSE;
					uc_error = uc_emu_start(
						TrackBlock.uc_handle,
						TrackBlock.DebugThreadContext.Rip,
						~1ull, 0, 0);

					if (uc_error != UC_ERR_OK) {

						ULONG64 Rip = 0;
						if (!TrackBlock.Wow64Process) {
							uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_RIP, &Rip);
						}
						else {
							uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_EIP, &Rip);
						}

						EditInsertText(
							GetDlgItem(hWnd, IDC_EDIT_LOG),
							"Rip:%llX %s\r\n",
							Rip,
							uc_strerror(uc_error));
					}
				}
			}
		}
		if (lParam == (LPARAM)GetDlgItem(hWnd, IDC_CONTINUE)) {

			ULONG64 Rip = 0;
			if (!TrackBlock.Wow64Process) {
				uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_RIP, &Rip);
			}
			else {
				uc_reg_read(TrackBlock.uc_handle, UC_X86_REG_EIP, &Rip);
			}
			IsStop = FALSE;
			uc_error = uc_emu_start(
				TrackBlock.uc_handle,
				Rip,
				~1ull, 0, 0);

			if (uc_error != UC_ERR_OK) {
				EditInsertText(
					GetDlgItem(hWnd, IDC_EDIT_LOG),
					"Rip:%llX %s\r\n",
					Rip,
					uc_strerror(uc_error));
			}
		}
		break;
	}
	case WM_NOTIFY: {
		TreeView = (LPNMTREEVIEW)lParam;

		if (TreeView->hdr.idFrom == IDC_TREE_LOG) {
			switch (TreeView->hdr.code) {
			case TVN_SELCHANGED: {
				HTREEITEM CurrentSel = TreeView_GetSelection(GetDlgItem(hWnd, IDC_TREE_LOG));
				PTREE_BLOCK_TRACK CurrentTreeBlock = NULL;

				HASH_FIND(hh, TrackBlock.TreeBlock, &CurrentSel, sizeof(CurrentSel), CurrentTreeBlock);
				if (CurrentTreeBlock)
				{
					EditPrintRegisters(hWnd, CurrentTreeBlock->ThreadContext);
					TrackBlock.Exported.nextOpcode(CurrentTreeBlock->address);
				}
			}
			default:
				break;
			}
		}
		break;
	}
	case WM_CLOSE: {
		EndDialog(hWnd, WM_CLOSE);
		break;
	}
	default:
		return FALSE;
	}

	return TRUE;
}