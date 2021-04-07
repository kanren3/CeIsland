#include "Island.h"

BOOL
WINAPI
UcMapMemory(
	PVOID Address,
	PVOID Buffer,
	SIZE_T Size,
	ULONG Protect
)
{
	uc_err uc_error;

	uc_error = uc_mem_map(
		TrackBlock.uc_handle,
		(uint64_t)Address,
		Size,
		Protect);

	uc_error = uc_mem_write(
		TrackBlock.uc_handle,
		(uint64_t)Address,
		Buffer,
		Size);

	if (uc_error != UC_ERR_OK) {
		return FALSE;
	}

	return TRUE;
}

BOOL
WINAPI
MapVirtualMemory(
	VOID
)
{
	HANDLE ProcessHandle = NULL;

	SYSTEM_INFO SystemInfo = { 0 };
	MEMORY_BASIC_INFORMATION BasicInformation = { 0 };
	SIZE_T NumberOfBytes = 0;

	PSTR Start = NULL;
	PSTR End = NULL;
	PVOID Block = NULL;

	uc_prot Protect = 0;

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TrackBlock.ProcessID);
	if (!ProcessHandle) {
		return FALSE;
	}

	GetSystemInfo(&SystemInfo);
	Start = (PSTR)SystemInfo.lpMinimumApplicationAddress;
	End = (PSTR)SystemInfo.lpMaximumApplicationAddress;

	do
	{
		NumberOfBytes = VirtualQueryEx(
			ProcessHandle,
			Start,
			&BasicInformation,
			sizeof(BasicInformation));

		if (NumberOfBytes) {

			switch (BasicInformation.Protect)
			{
			case PAGE_NOACCESS:
				Protect = UC_PROT_NONE;
				break;
			case PAGE_READONLY:
				Protect = UC_PROT_READ;
				break;
			case PAGE_READWRITE:
			case PAGE_WRITECOPY:
				Protect = UC_PROT_READ | UC_PROT_WRITE;
				break;
			case PAGE_EXECUTE:
			case PAGE_EXECUTE_READ:
				Protect = UC_PROT_READ | UC_PROT_EXEC;
				break;
			case PAGE_EXECUTE_READWRITE:
			case PAGE_EXECUTE_WRITECOPY:
				Protect = UC_PROT_ALL;
				break;
			default:
				Protect = UC_PROT_NONE;
				break;
			}

			if (Protect != UC_PROT_NONE) {

				Block = malloc(BasicInformation.RegionSize);
				ReadProcessMemory(
					ProcessHandle,
					BasicInformation.BaseAddress,
					Block,
					BasicInformation.RegionSize,
					&NumberOfBytes);

				if (Block) {

					if (UcMapMemory(
						BasicInformation.BaseAddress,
						Block,
						BasicInformation.RegionSize,
						Protect)
						) {
						RinPrint("[ok] address:%p size:%x protect:%d\n",
							BasicInformation.BaseAddress,
							BasicInformation.RegionSize,
							BasicInformation.Protect);
					}
					else {
						RinPrint("[error] address:%p size:%x protect:%d\n",
							BasicInformation.BaseAddress,
							BasicInformation.RegionSize,
							BasicInformation.Protect);
					}
				}
				free(Block);
			}

			Start += BasicInformation.RegionSize;
		}
		else {
			break;
		}
	} while (Start <= End);

	CloseHandle(ProcessHandle);
	return TRUE;
}

VOID
WINAPI
MapRegister(
	VOID
)
{
	if (!TrackBlock.Wow64Process)
	{
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_RAX, &TrackBlock.DebugThreadContext.Rax);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_RBX, &TrackBlock.DebugThreadContext.Rbx);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_RCX, &TrackBlock.DebugThreadContext.Rcx);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_RDX, &TrackBlock.DebugThreadContext.Rdx);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_R8, &TrackBlock.DebugThreadContext.R8);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_R9, &TrackBlock.DebugThreadContext.R9);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_R10, &TrackBlock.DebugThreadContext.R10);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_R11, &TrackBlock.DebugThreadContext.R11);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_R12, &TrackBlock.DebugThreadContext.R12);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_R13, &TrackBlock.DebugThreadContext.R13);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_R14, &TrackBlock.DebugThreadContext.R14);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_R15, &TrackBlock.DebugThreadContext.R15);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_RSI, &TrackBlock.DebugThreadContext.Rsi);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_RDI, &TrackBlock.DebugThreadContext.Rdi);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_RSP, &TrackBlock.DebugThreadContext.Rsp);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_RBP, &TrackBlock.DebugThreadContext.Rbp);
	}
	else
	{
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_EAX, &TrackBlock.DebugThreadContext.Rax);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_EBX, &TrackBlock.DebugThreadContext.Rbx);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_ECX, &TrackBlock.DebugThreadContext.Rcx);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_EDX, &TrackBlock.DebugThreadContext.Rdx);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_ESI, &TrackBlock.DebugThreadContext.Rsi);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_EDI, &TrackBlock.DebugThreadContext.Rdi);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_ESP, &TrackBlock.DebugThreadContext.Rsp);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_EBP, &TrackBlock.DebugThreadContext.Rbp);
	}

	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_EFLAGS, &TrackBlock.DebugThreadContext.EFlags);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM0, &TrackBlock.DebugThreadContext.Xmm0);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM1, &TrackBlock.DebugThreadContext.Xmm1);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM2, &TrackBlock.DebugThreadContext.Xmm2);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM3, &TrackBlock.DebugThreadContext.Xmm3);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM4, &TrackBlock.DebugThreadContext.Xmm4);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM5, &TrackBlock.DebugThreadContext.Xmm5);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM6, &TrackBlock.DebugThreadContext.Xmm6);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM7, &TrackBlock.DebugThreadContext.Xmm7);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM8, &TrackBlock.DebugThreadContext.Xmm8);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM9, &TrackBlock.DebugThreadContext.Xmm9);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM10, &TrackBlock.DebugThreadContext.Xmm10);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM11, &TrackBlock.DebugThreadContext.Xmm11);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM12, &TrackBlock.DebugThreadContext.Xmm12);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM13, &TrackBlock.DebugThreadContext.Xmm13);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM14, &TrackBlock.DebugThreadContext.Xmm14);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_XMM15, &TrackBlock.DebugThreadContext.Xmm15);
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_MXCSR, &TrackBlock.DebugThreadContext.MxCsr);
}

void
init_descriptor32(
	struct SegmentDescriptor32* desc,
	uint32_t base,
	uint32_t limit,
	uint8_t is_code,
	uint8_t is_long,
	uint8_t level
)
{
	desc->desc = 0;
	desc->base0 = base & 0xffff;
	desc->base1 = (base >> 16) & 0xff;
	desc->base2 = base >> 24;
	if (limit > 0xfffff) {
		limit >>= 12;
		desc->granularity = 1;
	}
	desc->limit0 = limit & 0xffff;
	desc->limit1 = limit >> 16;

	desc->dpl = level;
	desc->present = 1;
	desc->db = 1;
	desc->type = is_code ? 0xb : 3;
	desc->is_64_code = is_long ? 1 : 0;
	desc->system = 1;
}

void
init_descriptor64(
	struct SegmentDescriptor64* desc,
	uint64_t base,
	uint32_t limit,
	uint8_t is_code,
	uint8_t is_long,
	uint8_t level
)
{
	desc->desc = 0;
	desc->base0 = base & 0xffff;
	desc->base1 = (base >> 16) & 0xff;
	desc->base2 = (char)base >> 24;
	desc->base_upper = base >> 32;
	desc->must_be_zero = 0;

	if (limit > 0xfffff) {
		limit >>= 12;
		desc->granularity = 1;
	}
	desc->limit0 = limit & 0xffff;
	desc->limit1 = limit >> 16;

	desc->dpl = level;
	desc->present = 1;
	desc->db = 1;
	desc->type = is_code ? 0xb : 3;
	desc->is_64_code = is_long ? 1 : 0;
	desc->system = 1;
}

VOID
WINAPI
MapSegment(
	VOID
)
{
	uc_err err = UC_ERR_OK;

	uint32_t sel = 0;

	uc_x86_msr msr = { 0 };
	uc_x86_mmr gdtr = { 0 };

	msr.rid = IA32_GS_BASE;
	msr.value = TrackBlock.Teb;
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_MSR, &msr);

	msr.rid = IA32_FS_BASE;
	msr.value = TrackBlock.Teb + 0x2000;
	uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_MSR, &msr);

	if (TrackBlock.Wow64Process == FALSE) {
		struct SegmentDescriptor64 gdt[16] = { 0 };
		init_descriptor64(&gdt[3], 0, 0xFFFFFFFF, FALSE, FALSE, 0);
		init_descriptor64(&gdt[4], 0, 0xFFFFFFFF, TRUE, FALSE, 3);
		init_descriptor64(&gdt[5], 0, 0xFFFFFFFF, FALSE, FALSE, 3);
		init_descriptor64(&gdt[6], 0, 0xFFFFFFFF, TRUE, TRUE, 3);

		gdtr.base = 0xFFFFF00000000000;
		gdtr.limit = sizeof(gdt) - 1;

		uc_mem_map(TrackBlock.uc_handle, gdtr.base, 0x10000, UC_PROT_WRITE | UC_PROT_READ);
		uc_mem_write(TrackBlock.uc_handle, gdtr.base, gdt, sizeof(gdt));

		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_GDTR, &gdtr);

		sel = KGDT64_R3_CODE | RPL_MASK;
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_CS, &sel);

		sel = KGDT64_R3_DATA | RPL_MASK;
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_DS, &sel);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_ES, &sel);

		sel = KGDT64_R3_CMTEB | RPL_MASK;
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_FS, &sel);

		sel = KGDT64_R0_DATA;
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_SS, &sel);
	}
	else {
		struct SegmentDescriptor32 gdt[16] = { 0 };
		init_descriptor32(&gdt[3], 0, 0xFFFFFFFF, FALSE, FALSE, 0);
		init_descriptor32(&gdt[4], 0, 0xFFFFFFFF, TRUE, FALSE, 3);
		init_descriptor32(&gdt[5], 0, 0xFFFFFFFF, FALSE, FALSE, 3);
		init_descriptor32(&gdt[6], 0, 0xFFFFFFFF, TRUE, TRUE, 3);

		gdtr.base = 0xC0000000;
		gdtr.limit = sizeof(gdt) - 1;

		uc_mem_map(TrackBlock.uc_handle, gdtr.base, 0x10000, UC_PROT_WRITE | UC_PROT_READ);
		uc_mem_write(TrackBlock.uc_handle, gdtr.base, gdt, sizeof(gdt));

		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_GDTR, &gdtr);

		sel = KGDT64_R3_CODE | RPL_MASK;
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_CS, &sel);

		sel = KGDT64_R3_DATA | RPL_MASK;
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_DS, &sel);
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_ES, &sel);

		sel = KGDT64_R3_CMTEB | RPL_MASK;
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_FS, &sel);

		sel = KGDT64_R0_DATA;
		uc_reg_write(TrackBlock.uc_handle, UC_X86_REG_SS, &sel);
	}
}

BOOL
WINAPI
OpenCore(
	VOID
)
{
	uc_err uc_error;
	cs_err cs_error;

	if (TrackBlock.uc_handle) {
		uc_close(TrackBlock.uc_handle);
		TrackBlock.uc_handle = NULL;
	}
	if (TrackBlock.cs_handle) {
		cs_close(&TrackBlock.cs_handle);
		TrackBlock.cs_handle = 0;
	}

	if (!TrackBlock.Wow64Process) {
		uc_error = uc_open(
			UC_ARCH_X86,
			UC_MODE_64,
			&TrackBlock.uc_handle);

		if (uc_error == UC_ERR_OK) {
			cs_error = cs_open(
				CS_ARCH_X86,
				CS_MODE_64,
				&TrackBlock.cs_handle);

			if (cs_error == CS_ERR_OK) {
				RinPrint("Bit-64 Process\n");

				return TRUE;
			}
		}
	}
	else {
		uc_error = uc_open(
			UC_ARCH_X86,
			UC_MODE_32,
			&TrackBlock.uc_handle);

		if (uc_error == UC_ERR_OK) {
			cs_error = cs_open(
				CS_ARCH_X86,
				CS_MODE_32,
				&TrackBlock.cs_handle);

			if (cs_error == CS_ERR_OK) {
				RinPrint("Bit-32 Process\n");
				return TRUE;
			}
		}
	}

	return FALSE;
}