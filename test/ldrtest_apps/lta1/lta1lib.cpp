#include "section_prot_checker.h"
#include "cmn/system/locate_imagebase.h"

#include <windows.h>


void use_ordinal_imports();

BOOL WINAPI DllMain(HMODULE hDll, DWORD dwReason, LPVOID) {
  if (dwReason == DLL_PROCESS_ATTACH) {
    Beep(1700, 400);

    use_ordinal_imports();

    SectionProtChecker checker(cmn::system::locate_imagebase(DllMain));
    checker.execute();
  }

  return 812739;
}

