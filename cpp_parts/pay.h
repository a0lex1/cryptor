#pragma once

#include "check_payload_info.h"
#include "spraygen.h"


SPRAYABLE_PROC(pay_read);

#ifndef PAYLOAD_SHELLCODE
SPRAYABLE_PROC(pay_mz_setup);
SPRAYABLE_PROC(pay_mz_setup_post);
#endif

SPRAYABLE_PROC(pay_call);

