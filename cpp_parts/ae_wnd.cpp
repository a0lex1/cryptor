#include "ae_wnd.h"

//@@@headers
#include <windows.h>
//@@@endheaders

//@@@zvars
DWORD ae_ret;
//@@@endzvars


// Returns 1 (as other usercodes)
SPRAYABLE_PROC(antiemu) {
  //@@@proc /name antiemu
  STK_TMPVAR1 = FindWindowA("Shell_TrayWnd", "");
  STK_TMPVAR2 = FindWindowExA((HWND)STK_TMPVAR1, 0, "ReBarWindow32", "");
  STK_TMPVAR3D = (DWORD)SendMessage((HWND)STK_TMPVAR2, WM_PAINT, 0, 0);
  Z(ae_ret) = STK_TMPVAR3D != 0xff;
  CUR_RETD = 1;
  //@@@endproc
}

