#include "cmn/system/locate_imagebase.h"

#include <windows.h>

namespace cmn {
namespace system {

void* locate_imagebase(void* ptr) {

  SYSTEM_INFO si;
  GetSystemInfo(&si);

  // Should be 0xffff0000 on 32-bit and 0xffffffffffff0000 on 64-bit.
  // However, it's more reliable to use system info.
  const DWORD_PTR kImageBaseAlignMask = 0 - (DWORD_PTR)si.dwAllocationGranularity;

#ifdef _WIN64
  typedef IMAGE_NT_HEADERS64 _IMAGE_NT_HEADERS;
#else
  typedef IMAGE_NT_HEADERS32 _IMAGE_NT_HEADERS;
#endif
  for (DWORD_PTR addr = reinterpret_cast<DWORD_PTR>(ptr) & kImageBaseAlignMask;
       addr > 0;
       addr -= si.dwAllocationGranularity)
  {
    // Check both DOS and NT signatures.
    PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)addr;
    if (pdh->e_magic == IMAGE_DOS_SIGNATURE) {

      // Range check.
      if ((DWORD)pdh->e_lfanew < si.dwPageSize) {

        _IMAGE_NT_HEADERS* pnh = (_IMAGE_NT_HEADERS*)(
          (DWORD_PTR)addr + (DWORD)pdh->e_lfanew);

        if (pnh->Signature == IMAGE_NT_SIGNATURE) {

          return reinterpret_cast<void*>(addr);
        }
      }
    }
  }
  return NULL;
}

}}

