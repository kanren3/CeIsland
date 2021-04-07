#ifndef _VER_H_
#define _VER_H_

#ifdef __cplusplus
extern "C" {
#endif

#define VER_DEBUG                   2
#define VER_PRERELEASE              0
#define VER_FILEFLAGSMASK           VS_FFI_FILEFLAGSMASK
#define VER_FILEOS                  VOS_NT_WINDOWS32
#define VER_FILEFLAGS               (VER_PRERELEASE|VER_DEBUG)

#define VER_FILETYPE                VFT_DRV
#define VER_FILESUBTYPE             VFT2_DRV_SYSTEM

#define VER_COMPANYNAME_STR         "Kanren"
#define VER_PRODUCTNAME_STR         "Island"
#define VER_LEGALCOPYRIGHT_YEARS    "2021"
#define VER_LEGALCOPYRIGHT_STR      "Copyright (c) " VER_LEGALCOPYRIGHT_YEARS " " VER_COMPANYNAME_STR
#define VER_LEGALTRADEMARKS_STR     "Copyright (c) " VER_LEGALCOPYRIGHT_YEARS " " VER_COMPANYNAME_STR

#define VER_PRODUCTVERSION          1.0.0.0
#define VER_PRODUCTVERSION_STR      "1.0.0.0"
#define VER_PRODUCTVERSION_W        (0x0200)
#define VER_PRODUCTVERSION_DW       (0x0200)

#define VER_FILEDESCRIPTION_STR     "Island"
#define VER_INTERNALNAME_STR        "Island"
#define VER_ORIGINALFILENAME_STR    "Island.dll"

#ifdef __cplusplus
}
#endif

#endif
