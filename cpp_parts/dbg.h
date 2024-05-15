#pragma once

#include "spraygen.h"


#ifdef _DEBUG
#define __DBGPOINT__() if (FindWindowA("WMPlayerApp", "Windows Media Player")) { DebugBreak(); }
#define dbgprn(x, ...) printf(x, __VA_ARGS__)
#else
#define __DBGPOINT__()
#define dbgprn(x, ...)
#endif


#ifndef SPRAYED_BUILD
// printf and crash
#define XASSERT(e) { if (!(e)) { printf("--------- Check failed - %s\n", #e);  *(int*)0 = 1; } }
#define XCHKAPI(title, e)  { if (!(e)) { printf("[!]CHKAPI: %s failed, err %d\n", title, GetLastError()); *(int*)0 = 2; } }
#else
// Danger, ASSERT() does not exist in SPRAYED_BUILD, all checks are passed
#define XASSERT(...)
#define XCHKAPI(...)
#endif


#ifdef _DEBUG

#define DBGINIT() \
  {\
    if (AttachConsole(ATTACH_PARENT_PROCESS) || AllocConsole()) { \
      FILE* _fp; \
      freopen_s(&_fp, "CONOUT$", "w", stdout); \
      freopen_s(&_fp, "CONOUT$", "w", stderr); \
      freopen_s(&_fp, "CONIN$", "r", stdin); \
    }\
  }


SPRAYABLE_PROC(dbg_init);

#else

#define DBGINIT()

#endif


