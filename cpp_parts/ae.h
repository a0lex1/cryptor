#pragma once

#include "spraygen.h"
#include <windows.h>


// Returns 1 (as other usercodes); check ae_ret
SPRAYABLE_PROC(antiemu);


EXTERN_ZVAR(DWORD ae_ret); // if 0 after _CALL(antiemu), then we are emulated

