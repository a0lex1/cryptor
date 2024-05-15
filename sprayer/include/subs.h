#pragma once

#ifndef SPRAYED_BUILD

// Non-sprayed build, static obf dwords
#define OBFUSCATION_DWORD 0xabadabae //why is it here?

#else

// For SPRAYED_BUILD:
#include "gened_substitutions.h"

#endif


// For both sprayed and non-sprayed builds

#ifdef _WIN64
typedef unsigned __int64 dword_ptr;
#else
typedef unsigned dword_ptr;
#endif


#define NEVER_EXEC(code) { if (_xarg[XARG_IDX_STACK] == 0/*CANNOT BE*/) { code; } }

