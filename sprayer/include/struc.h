#pragma once

#ifdef SPRAYED_BUILD

  // give struct private name so nobody knows, we hide this struct
  #define _STRUCT(F) struct __prototype_##F

#else

  #define _STRUCT(F) struct F

#endif


