#pragma once

#include "../payload.info.h"

#ifdef _WIN64

#ifndef PAYLOAD_X64
#error("platform is x64, payload needs x86")
#endif
#ifdef PAYLOAD_X86
#error("both PAYLOAD_X64 and 86 are defined")
#endif

#else

#ifndef PAYLOAD_X86
#error("platform is x86, payload needs x64")
#endif
#ifdef PAYLOAD_X64
#error("both PAYLOAD_X86 and 64 are defined")
#endif

#endif

