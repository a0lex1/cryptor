#pragma once

//#define CRYPTBIN_WIDTH 4 // use sizeof(CRYPTBIN_KEY_TYPE)
#define CRYPTBIN_COUNT 128
#define CRYPTBIN_KEY_TYPE unsigned long
#define CRYPTBIN_KEY ((CRYPTBIN_KEY_TYPE)0x47AA1774)
#define CRYPTBIN_XVAL ((CRYPTBIN_KEY_TYPE)0x6AA1036D)

/*
// --- Cheatsheet ---
void cryptbin_simple_decrypt(void* buffer) {
  CRYPTBIN_KEY_TYPE init_key = CRYPTBIN_KEY;
  CRYPTBIN_KEY_TYPE new_key = init_key;
  for (unsigned long i=0; i<CRYPTBIN_COUNT; i++) {
    ((CRYPTBIN_KEY_TYPE*)buffer)[i] ^= new_key;
    if (CRYPTBIN_XVAL != 0) {
      new_key *= CRYPTBIN_XVAL;
    }
  }
}
*/

