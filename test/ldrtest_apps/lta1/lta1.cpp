#include "section_prot_checker.h"
#include "cmn/system/locate_imagebase.h"
#include <windows.h>

#define DBGINIT() \
  {\
    if (AttachConsole(ATTACH_PARENT_PROCESS) || AllocConsole()) { \
      FILE* _fp; \
      freopen_s(&_fp, "CONOUT$", "w", stdout); \
      freopen_s(&_fp, "CONOUT$", "w", stderr); \
      freopen_s(&_fp, "CONIN$", "r", stdin); \
    }\
  }

void use_ordinal_imports();


int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {

  DBGINIT();

  Beep(1200, 200);

  use_ordinal_imports();

  SectionProtChecker checker(cmn::system::locate_imagebase(WinMain));
  checker.execute();

  return 812739;

}