#pragma once

#include <windows.h>

#include "spraygen.h"

//@@@privdefs
#define COCREL_RING_SIZE 3
//@@@endprivdefs

_STRUCT(ACTVARS_cocrel) {
  //@@@structfields /name ACTVARS_cocrel
  int idx_ptr;
  int idx_guid;
  BOOL overwriting;
  HRESULT hr;
  IUnknown* ptr_ring[COCREL_RING_SIZE];
  //@@@endstructfields
};

SPRAYABLE_PROC(A_init_cocrel);
SPRAYABLE_PROC(A_runonce_cocrel);
SPRAYABLE_PROC(A_uninit_cocrel);

