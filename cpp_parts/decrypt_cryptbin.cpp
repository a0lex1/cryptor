//@@@headers
#include "decrypt_cryptbin.h"
#include "../cryptbin.keys.h"
#include <memory.h>
#include <stdlib.h> // malloc
//@@@endheaders
#include "spraygen.h"

//@@@privdefs
#define V_DECCRB() ((DEC_CRYPTBIN_VARS*)SELF())
//@@@endprivdefs

_STRUCT(DEC_CRYPTBIN_VARS) {
//@@@structfields /name DEC_CRYPTBIN_VARS
  u32 i;
  u32 count;
#ifdef CRYPTBIN_REARR0
  u8* lpbRearrPtr;
  u8 tmp_buf[8];
#endif
#ifdef CRYPTBIN_KEY
  u32 dwNewKey;
#endif
//@@@endstructfields
};

// A1 -> lpData, A2D -> xval
// TODO: 1, 2 width, not only 4 (DWORD)
static SPRAYABLE_PROC(decrypt_cryptbin_keyxor_iter) {
  //@@@proc /name decrypt_cryptbin_keyxor_iter
#ifdef CRYPTBIN_KEY
  *(u32*)&((char*)CUR_A1)[V_DECCRB()->i * 4] ^= V_DECCRB()->dwNewKey;
#ifdef CRYPTBIN_XVAL
  // TODO: Note: we don't actually need to #ifdef CRYPTBIN_XVAL cuz
  // we can just set CRYPTBIN_XVAL to 1 so multiplication makes no effect.
  V_DECCRB()->dwNewKey *= CUR_A2D;
#endif
  V_DECCRB()->i += 1;
#endif
  //@@@endproc 
}

#ifdef CRYPTBIN_REARR0
// A1 -> lpData
static SPRAYABLE_PROC(decrypt_cryptbin_rearrange_iter) {
  //@@@proc /name decrypt_cryptbin_rearrange_iter
  V_DECCRB()->lpbRearrPtr = &((u8*)CUR_A1)[V_DECCRB()->i * CRYPTBIN_REARR_PATSIZE];
  V_DECCRB()->tmp_buf[0] = V_DECCRB()->lpbRearrPtr[CRYPTBIN_REARR0];
  V_DECCRB()->tmp_buf[1] = V_DECCRB()->lpbRearrPtr[CRYPTBIN_REARR1];
  V_DECCRB()->tmp_buf[2] = V_DECCRB()->lpbRearrPtr[CRYPTBIN_REARR2];
  V_DECCRB()->tmp_buf[3] = V_DECCRB()->lpbRearrPtr[CRYPTBIN_REARR3];
  V_DECCRB()->tmp_buf[4] = V_DECCRB()->lpbRearrPtr[CRYPTBIN_REARR4];
  V_DECCRB()->tmp_buf[5] = V_DECCRB()->lpbRearrPtr[CRYPTBIN_REARR5];
  V_DECCRB()->tmp_buf[6] = V_DECCRB()->lpbRearrPtr[CRYPTBIN_REARR6];
  V_DECCRB()->tmp_buf[7] = V_DECCRB()->lpbRearrPtr[CRYPTBIN_REARR7];
  memcpy(V_DECCRB()->lpbRearrPtr, V_DECCRB()->tmp_buf, CRYPTBIN_REARR_PATSIZE);
  V_DECCRB()->i += 1;
  //@@@endproc
}
#endif

// A1 -> lpData, A2D -> dwDataLen
SPRAYABLE_PROC(decrypt)
{
  //@@@proc /name decrypt
  PUSH_SELF(malloc(sizeof(DEC_CRYPTBIN_VARS)));


  CHILD_A1 = CUR_A1;

  // Do not rearrange the tail
#ifdef CRYPTBIN_REARR0
  //V_DECCRB()->count = CUR_A2D / CRYPTBIN_REARR_PATSIZE;
  V_DECCRB()->count = CUR_A2D - (CRYPTBIN_TAIL_COUNT * CRYPTBIN_WIDTH);
  V_DECCRB()->count /= CRYPTBIN_REARR_PATSIZE;
  V_DECCRB()->i = 0;
  while (V_DECCRB()->i != V_DECCRB()->count) { _CALL(decrypt_cryptbin_rearrange_iter); }
#endif

  // CHILD_A1 already set to CUR_A1 (e.g. lpData)
  CHILD_A2D = CRYPTBIN_XVAL;

#ifdef CRYPTBIN_KEY
  // decode body
  V_DECCRB()->dwNewKey = CRYPTBIN_KEY;
  V_DECCRB()->count = CUR_A2D / sizeof(u32) - CRYPTBIN_TAIL_COUNT;
  V_DECCRB()->i = 0;
  while (V_DECCRB()->i != V_DECCRB()->count) { _CALL(decrypt_cryptbin_keyxor_iter); }

  /* uncomment to decode trailer too (not yet needed) */
  //// decode tail
  //CHILD_A2D = 1; // set xval to 1 to disable multipliying the key
  //V_DECCRB()->dwNewKey = CRYPTBIN_TAIL_XORKEY;
  //V_DECCRB()->count = CUR_A2D / sizeof(u32);
  //V_DECCRB()->i = V_DECCRB()->count - CRYPTBIN_TAIL_COUNT;
  //while (V_DECCRB()->i != V_DECCRB()->count) { _CALL(decrypt_cryptbin_keyxor_iter); }
#endif


  POP_SELF();
  //@@@endproc 
}


