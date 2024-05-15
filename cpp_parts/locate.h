#pragma once

#include "PART_INFO_DEFS.h"
#include "spraygen.h"
#include <windows.h>

// locate generic
// no args for locate()
EXTERN_ZVAR(unsigned char* locate_paydata);
EXTERN_ZVAR(size_t locate_paydatalen);
EXTERN_ZVAR(BOOL locate_bReadOnly);


SPRAYABLE_PROC(locate);

#ifdef UNLOCATE_POSSIBLE
SPRAYABLE_PROC(unlocate);
#endif

