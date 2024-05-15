#pragma once

#include "evil_common.h"

#ifndef SPRAYED_BUILD

#define XCHKAPI(title, e)  { if (!(e)) { printf("[!]CHKAPI: %s failed, err %d\n", title, GetLastError()); *(int*)0 = 2; } }


#else

// Danger, ASSERT() does not exist in SPRAYED_BUILD, all checks are passed
#define XCHKAPI(...)

#endif



