#pragma once


#define ENSURE_MORE_ARGS(argc, cur_idx, more_needed) \
  if (cur_idx+more_needed > argc-1) {\
    printf("ERROR: need %d more args", more_needed);\
    abort();\
  }


#define ALIGN_DOWN(p, n) ((uintptr_t)(p) - ( (uintptr_t)(p) % (uintptr_t)(n) ))
#define ALIGN_UP(p, n)   ALIGN_DOWN((uintptr_t)(p) + (uintptr_t)(n) - 1, (n))
