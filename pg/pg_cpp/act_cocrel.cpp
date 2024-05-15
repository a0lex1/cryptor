//@@@headers
#include "pg/act_cocrel.h"
#include "cocrel_guids.h"
#include <windows.h>
#include <cassert>
//@@@endheaders
//TODO: RANDOM instead of TRUE, etc.

//@@@privdefs
#define V_COCR() ((ACTVARS_cocrel*)CUR_A1)
//@@@endprivdefs

//@@@libs
#pragma comment(lib, "ole32.lib")
//@@@endlibs


SPRAYABLE_PROC(A_init_cocrel) {
  //@@@proc /name A_init_cocrel
  CoInitialize(NULL);
  V_COCR()->idx_ptr = 0;
  V_COCR()->idx_guid = 0;
  V_COCR()->overwriting = FALSE;
  //@@@endproc
}
SPRAYABLE_PROC(A_runonce_cocrel) {
  //@@@proc /name A_runonce_cocrel
  if (V_COCR()->idx_ptr == COCREL_RING_SIZE) { V_COCR()->idx_ptr = 0; V_COCR()->overwriting = TRUE; }
  if (V_COCR()->overwriting) { V_COCR()->ptr_ring[V_COCR()->idx_ptr]->Release(); }
  if (V_COCR()->idx_guid == COCREL_NUM_GUIDPAIRS) { V_COCR()->idx_guid = 0; }
  printf("A_runonce_cocrel: calling CoCreateInstance\n");
  V_COCR()->hr = CoCreateInstance(COCREL_CLSID(V_COCR()->idx_ptr), 0, CLSCTX_ALL, COCREL_IID(V_COCR()->idx_ptr), (void**)&V_COCR()->ptr_ring[V_COCR()->idx_ptr]);
  assert(SUCCEEDED(V_COCR()->hr));
  V_COCR()->idx_ptr++;
  V_COCR()->idx_guid++;
  //@@@endproc
}
SPRAYABLE_PROC(A_uninit_cocrel) {
  //@@@proc /name A_uninit_cocrel
  for (int i = 0; i < COCREL_RING_SIZE; i++) { V_COCR()->ptr_ring[i]->Release(); }
  //@@@endproc
}




