#pragma once

#include "PART_INFO_DEFS.h"
#include "spraygen.h"
#include <windows.h>


EXTERN_ZVAR(PVOID alloc_lpImage);
EXTERN_ZVAR(DWORD alloc_CachedSizeOfImage);



// A1D -> dwProtect
SPRAYABLE_PROC(alloc);

#ifdef DEALLOC_POSSIBLE
SPRAYABLE_PROC(dealloc);
#endif

