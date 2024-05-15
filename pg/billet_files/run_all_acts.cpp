#include "pg/act_cocrel.h"
#include "pg/act_loadlib.h"

//@@@zvars
ACTVARS_cocrel _cocrel_vars;
ACTVARS_loadlib _loadlib_vars;
//@@@endzvars

SPRAYABLE_PROC(run_all_acts) {
  //@@@proc /name run_all_acts

  CHILD_A1 = &Z(_loadlib_vars);
  _CALL(A_init_loadlib);
  for (int i = 0; i < 1000; i++) { _CALL(A_runonce_loadlib); }
  _CALL(A_uninit_loadlib);

  CHILD_A1 = &Z(_cocrel_vars);
  _CALL(A_init_cocrel);
  for (int i = 0; i < 100; i++) { _CALL(A_runonce_cocrel); }
  _CALL(A_uninit_cocrel);

  //@@@endproc
}

