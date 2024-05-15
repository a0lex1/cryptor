#pragma once

#include "./subs.h"
#include "./gc.h"
#include "./vars.h"
#include "./stk.h"
#include "./struc.h"


// FG's temporary home
// using maximum instead of minimum is supposed to make more stress
//#define _fk(minimum,maximum) (maximum)
#define _fka(minimum, maximum)  (minimum)
#define _fkb(minimum, maximum)  (maximum)

#ifdef SPRAYED_BUILD
#include "spraytab.h"
#include "gened_headers.h"
#endif


#ifndef _DEBUG
#ifdef SPRAYED_BUILD
#define SLEEP_RELEASE_ONLY(msec) Sleep(msec)
#endif
#endif
#ifndef SLEEP_RELEASE_ONLY
#define SLEEP_RELEASE_ONLY(msec) __noop
#endif

