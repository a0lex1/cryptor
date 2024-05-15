//@@@headers
#include "pg/act_loadlib.h"
#include "loadlib_names.h"
#include <windows.h>
#include <cassert>
//@@@endheaders
//TODO: RANDOM instead of TRUE, etc.

//@@@privdefs
#define V_LL() ((ACTVARS_loadlib*)CUR_A1)
//@@@endprivdefs


SPRAYABLE_PROC(A_init_loadlib) {
  //@@@proc /name A_init_loadlib
  CoInitialize(NULL);
  V_LL()->idx_hinst = 0;
  V_LL()->idx_name = 0;
  V_LL()->overwriting = FALSE;
  //@@@endproc
}

SPRAYABLE_PROC(A_runonce_loadlib) {
  //@@@proc /name A_runonce_loadlib
  if (V_LL()->idx_hinst == LOADLIB_RING_SIZE) { V_LL()->idx_hinst = 0; V_LL()->overwriting = TRUE; }
  if (V_LL()->overwriting) { FreeLibrary(V_LL()->hinst_ring[V_LL()->idx_hinst]); }
  if (V_LL()->idx_name == LOADLIB_NUM_NAMES) { V_LL()->idx_name = 0; }
  //V_LL()->hr = CoCreateInstance(COCREL_CLSID(V_LL()->idx_hinst), 0, CLSCTX_ALL, COCREL_IID(V_LL()->idx_hinst), (void**)&V_LL()->ptr_ring[V_LL()->idx_hinst]);
  //printf("A_runonce_loadlib: loading %s\n", LOADLIB_NAME(V_LL()->idx_name));
  V_LL()->hinst_ring[V_LL()->idx_hinst] = LoadLibraryA(LOADLIB_NAME(V_LL()->idx_name));
  assert(V_LL()->hinst_ring[V_LL()->idx_hinst] != NULL);
  V_LL()->idx_hinst++;
  V_LL()->idx_name++;
  //@@@endproc
}

SPRAYABLE_PROC(A_uninit_loadlib) {
  //@@@proc /name A_uninit_loadlib
  for (int i = 0; i < LOADLIB_RING_SIZE; i++) { FreeLibrary(V_LL()->hinst_ring[i]); }
  //@@@endproc
}



