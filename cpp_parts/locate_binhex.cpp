//@@@headers
#include "locate_binhex.h"
#include "../include_payload.binhex.h.h"
//@@@endheaders

//@@@zvars
unsigned char* locate_paydata; // locate.h
size_t locate_paydatalen; // locate.h
BOOL locate_bReadOnly; // locate.h
//@@@endzvars

SPRAYABLE_PROC(locate)
{
  //@@@proc /name locate
  Z(locate_paydata) = payload_data;
  Z(locate_paydatalen) = payload_len;
  Z(locate_bReadOnly) = FALSE; // binhex data is writeable
  //@@@endproc 
}

// Nothing to do. The data is readonly.
//SPRAYABLE_PROC(unlocate) {
//  //@@@proc /name unlocate
//  //@@@endproc
//}
