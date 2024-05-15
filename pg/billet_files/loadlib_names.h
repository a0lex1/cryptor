#pragma once

#include <stdlib.h>

#define LOADLIB_NUM_NAMES 10

static constexpr const char* LOADLIB_NAME(int n) {
  switch (n) {
  case 0: return "dcomp.dll";
  case 1: return "mpr.dll";
  case 2: return "netprofm.dll";
  case 3: return "msctf.dll";
  case 4: return "xmllite.dll";
  case 5: return "nsi.dll";
  case 6: return "propsys.dll";
  case 7: return "shcore.dll";
  case 8: return "srvcli.dll";
  case 9: return "ninput.dll";
  default: abort();
  }
}


