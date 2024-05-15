#pragma once

#include <windows.h>

#include "spraygen.h"

//@@@privdefs
#define LOADLIB_RING_SIZE 9
//@@@endprivdefs

_STRUCT(ACTVARS_loadlib) {
  //@@@structfields /name ACTVARS_loadlib
  int idx_hinst;
  int idx_name;
  BOOL overwriting;
  HINSTANCE hinst_ring[LOADLIB_RING_SIZE];
  //@@@endstructfields
};

SPRAYABLE_PROC(A_init_loadlib);
SPRAYABLE_PROC(A_runonce_loadlib);
SPRAYABLE_PROC(A_uninit_loadlib);

