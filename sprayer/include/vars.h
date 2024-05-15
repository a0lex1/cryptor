#pragma once

#ifdef SPRAYED_BUILD

  #define Z(vn)      (((ZVARS*)_xarg[XARG_IDX_VARS])->vn) // for sprayed builds
  #define EXTERN_ZVAR(vn)

  // for sprayed build, ability to access ZVARS through globvar without xarg (DllMain, etc., e.g. code outside gened_code.cpp)
  #define ZZ(vn)     ((g_pzvars)->vn)

struct ZVARS;
extern ZVARS* g_pzvars;

#else

  #define Z(vn)      (vn) // for nonsprayed builds, variables are fairly global
  #define EXTERN_ZVAR(vn) extern vn

  #define ZZ(vn)     (vn)

#endif

