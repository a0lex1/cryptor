#include "cmn/common.h"
#include <stdexcept>
#include <windows.h>

using namespace std;

class SectionProtChecker {
public:
  SectionProtChecker(LPVOID lpImage)
    : lpImage_(lpImage)
  {
  }
  void execute() {
    IMAGE_DOS_HEADER* pdh = (IMAGE_DOS_HEADER*)lpImage_;
    printf("My base: %p\n", pdh);
    pnh_ = (IMAGE_NT_HEADERS*)((DWORD_PTR)pdh + pdh->e_lfanew);
    psh_ = (IMAGE_SECTION_HEADER*)((DWORD_PTR)&pnh_->OptionalHeader + pnh_->FileHeader.SizeOfOptionalHeader);

    for (int sec_idx=0; sec_idx<pnh_->FileHeader.NumberOfSections; sec_idx++) {
      //psh_[sec_idx].Characteristics;
      DWORD dwSecAlignedVSize = ALIGN_UP(psh_[sec_idx].Misc.VirtualSize, pnh_->OptionalHeader.SectionAlignment);
      PVOID lpSecFirstPage = (PVOID)((DWORD_PTR)pdh + psh_[sec_idx].VirtualAddress);
      PVOID lpSecLastPage = (PVOID)((DWORD_PTR)lpSecFirstPage + dwSecAlignedVSize - 1);

      check_for_page(lpSecFirstPage, sec_idx);
      check_for_page(lpSecLastPage, sec_idx);
    }
  }

private:
  void check_for_page(LPVOID lpPage, int sec_idx) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T qret = VirtualQuery(lpPage, &mbi, sizeof(mbi));
    if (!qret) {
      printf("section %d %s -- VirtualQuery(%p) failed, err %d\n", sec_idx, (char*)psh_[sec_idx].Name, lpPage, GetLastError());
      throw runtime_error("VirtualQuery failed, see log");
    }
    DWORD dwChars = psh_[sec_idx].Characteristics;
    DWORD dwProt = mbi.Protect & 0xff;
    if (!enough_protect(dwChars, dwProt)) {
      printf("section %d %s -- NOT ENOUGH protect %x for characteristics %x\n", sec_idx, psh_[sec_idx].Name, dwProt, psh_[sec_idx].Characteristics);
      throw runtime_error("not enough protect (first page)");
    }
  }

  // sec_prot shouldn't have flags like PAGE_GUARD, only first byte PAGE_XXX prot consts
  bool enough_protect(DWORD sec_char, DWORD sec_prot) {
    if (!valid_sec_prot(sec_prot)) {
      printf("invalid sec prot - %x\n", sec_prot);
      throw runtime_error("invalid sec prot");
    }
    if (sec_char & IMAGE_SCN_MEM_EXECUTE) {
      if (sec_prot != PAGE_EXECUTE && sec_prot != PAGE_EXECUTE_READ && sec_prot != PAGE_EXECUTE_READWRITE && sec_prot != PAGE_EXECUTE_WRITECOPY) {
        return false;
      }
    }
    if (sec_char & IMAGE_SCN_MEM_READ) {
      if (sec_prot != PAGE_EXECUTE_READ && sec_prot != PAGE_EXECUTE_READWRITE && sec_prot != PAGE_READONLY && sec_prot != PAGE_EXECUTE_WRITECOPY && sec_prot != PAGE_READWRITE && sec_prot != PAGE_WRITECOPY) {
        return false;
      }
    }
    if (sec_char & IMAGE_SCN_MEM_WRITE) {
      if (sec_prot != PAGE_EXECUTE_READWRITE && sec_prot != PAGE_EXECUTE_WRITECOPY && sec_prot != PAGE_READWRITE && sec_prot != PAGE_WRITECOPY) {
        return false;
      }
    }
    return true;
  }

  bool valid_sec_prot(DWORD sec_prot) const {
    return sec_prot == PAGE_EXECUTE ||
      sec_prot == PAGE_EXECUTE_READ ||
      sec_prot == PAGE_EXECUTE_READWRITE ||
      sec_prot == PAGE_EXECUTE_WRITECOPY ||
      sec_prot == PAGE_NOACCESS ||
      sec_prot == PAGE_READONLY ||
      sec_prot == PAGE_READWRITE ||
      sec_prot == PAGE_WRITECOPY;
  }

private:
  LPVOID lpImage_;
  IMAGE_NT_HEADERS* pnh_{nullptr};
  IMAGE_SECTION_HEADER* psh_{nullptr};
};


