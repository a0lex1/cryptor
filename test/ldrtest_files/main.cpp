//@@@headers
#include "ldr.h"
#include "lpfns.h"
#include "evil_common.h"
#include <windows.h>
#include <shellapi.h>
#include "dbg.h"
//@@@endheaders

//@@@privdefs
#define main_DECL() int main() // g0 t0
#define main_PRE() XARGSETUP()
#define main_POST() XARGCLEANUP(); return Z(dwEntryRet)
#define DIRENTRY_BASERELOC IMAGE_DIRECTORY_ENTRY_BASERELOC
#define DIRENTRY_IMPORT IMAGE_DIRECTORY_ENTRY_IMPORT
#define DIRENTRY_TLS IMAGE_DIRECTORY_ENTRY_TLS
//@@@endprivdefs

//@@@zvars
int argc;
wchar_t** argv;
BOOL IsDll;

HANDLE hFile;
DWORD dwFileSize;
DWORD dwBytesRead;
LPVOID lpBuffer;
BOOL bOk;

LPVOID lpMappedImage;
IMAGE_DOS_HEADER* pDosHdr;
DWORD SizeOfImage;

LPVOID lpEntryPoint;
DWORD dwEntryRet;

BOOL bOK;
//@@@endzvars


static SPRAYABLE_PROC(dealloc) {
  Z(bOK) = VirtualFree(Z(lpMappedImage), Z(SizeOfImage), MEM_DECOMMIT);
  XASSERT(bOK);
  Z(bOK) = VirtualFree(Z(lpMappedImage), 0, MEM_RELEASE);
  XASSERT(bOK);
}

static SPRAYABLE_PROC(verify_same_cpu) {
#ifdef _WIN64
  XASSERT(Z(ldr_pNtHdrs)->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
#else
  XASSERT(Z(ldr_pNtHdrs)->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
#endif
}

static SPRAYABLE_PROC(dllmain_fail) {
  ((LPFN_DllMain)Z(lpEntryPoint))((HMODULE)Z(lpMappedImage), DLL_PROCESS_DETACH, 0);
  //_CALL(dealloc);
}

static SPRAYABLE_PROC(call_dll) {
  Z(dwEntryRet) = ((LPFN_DllMain)Z(lpEntryPoint))((HMODULE)Z(lpMappedImage), DLL_PROCESS_ATTACH, 0);
  CUR_RETD = Z(dwEntryRet); // return what entry returned
  if (FALSE == Z(dwEntryRet)) { _CALL(dllmain_fail); }
}

static SPRAYABLE_PROC(call_exe) {
  ((LPFN_ExeEntry)Z(lpEntryPoint))();
  _CALL(dealloc);
}


main_DECL() {
  main_PRE();
  //@@@proc /decl main /root yes

  dbgprn("(The usage of this tool:  ldrtest.exe <dll|exe> <file.dll/exe>)\n");
  _CALL(common_init);
  _CALL(lpfns_resolve);
  
  Z(argv) = CommandLineToArgvW(GetCommandLineW(), &Z(argc));
  XASSERT(Z(argc) == 3);
  XASSERT(!wcscmp(argv[1], L"exe") || !wcscmp(argv[1], L"dll"));

  Z(IsDll) = !wcscmp(argv[1], L"dll");

  wprintf(L"Loading fucking file %s\n", Z(argv[2]));
  Z(hFile) = CreateFileW(Z(argv[2]), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); XASSERT(Z(hFile) != INVALID_HANDLE_VALUE);
  Z(dwFileSize) = GetFileSize(Z(hFile), NULL); XASSERT(Z(dwFileSize) != 0);
  Z(lpBuffer) = malloc(Z(dwFileSize)); XASSERT(Z(lpBuffer));
  Z(bOk) = ReadFile(Z(hFile), Z(lpBuffer), Z(dwFileSize), &Z(dwBytesRead), NULL); XASSERT(Z(bOk)); XASSERT(Z(dwBytesRead) == Z(dwFileSize));
  CloseHandle(Z(hFile));

  wprintf(L"Getting PE headers ...\n");
  Z(pDosHdr) = (IMAGE_DOS_HEADER*)Z(lpBuffer);
  Z(ldr_pNtHdrs) = (IMAGE_NT_HEADERS*)((DWORD_PTR)Z(lpBuffer) + Z(pDosHdr)->e_lfanew);
  Z(ldr_pOptHdr) = (IMAGE_OPTIONAL_HEADER*) & Z(ldr_pNtHdrs)->OptionalHeader;
  Z(ldr_pSecHdrs) = (IMAGE_SECTION_HEADER*)((DWORD_PTR)Z(ldr_pOptHdr) + Z(ldr_pNtHdrs)->FileHeader.SizeOfOptionalHeader);
  Z(ldr_pDataDir) = Z(ldr_pOptHdr)->DataDirectory;
  Z(SizeOfImage) = Z(ldr_pOptHdr)->SizeOfImage;
  wprintf(L"PE headers: TLS:(rva %x, size %x), RELOCS: (rva %x, size %x)\n", Z(ldr_pDataDir[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress), Z(ldr_pDataDir[IMAGE_DIRECTORY_ENTRY_TLS].Size), Z(ldr_pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress), Z(ldr_pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size));

  _CALL(verify_same_cpu);

  Z(lpMappedImage) = VirtualAlloc(NULL, Z(SizeOfImage), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  wprintf(L"VirtualAlloc lpMappedImage = %p\n", Z(lpMappedImage));
  XASSERT(Z(lpMappedImage));

  Z(protsec_lpTargetImage) = Z(lpMappedImage); // only for ldr_prot_sec

  // All ldr_* uses CUR_A1
  CHILD_A1 = Z(lpMappedImage);


#ifndef DO_STOMP
  // copy headers
  memcpy(lpMappedImage, lpBuffer, Z(ldr_pOptHdr)->SizeOfHeaders);
#endif

  wprintf(L"Doing ldr_copy_sections ...\n");
  CHILD_A2 = Z(lpBuffer);
  _CALL(ldr_copy_sections);

  if (Z(ldr_pDataDir[DIRENTRY_BASERELOC].VirtualAddress) && Z(ldr_pDataDir[DIRENTRY_BASERELOC].Size)) { wprintf(L"Doing ldr_process_relocs ...\n"); _CALL(ldr_process_relocs); }
  if (Z(ldr_pDataDir[DIRENTRY_IMPORT].VirtualAddress) && Z(ldr_pDataDir[DIRENTRY_IMPORT].Size)) { wprintf(L"Doing ldr_process_imports ...\n"); _CALL(ldr_process_imports); }

  wprintf(L"Protecting sections ...\n");
  for (int i = 0; i < Z(ldr_pNtHdrs)->FileHeader.NumberOfSections; i++) { CHILD_A1D = ObfEncDw(i);  _CALL(ldr_prot_sec); }


  // POST
  CHILD_A1 = Z(lpMappedImage);
  if (Z(ldr_pDataDir[DIRENTRY_TLS].VirtualAddress) && Z(ldr_pDataDir[DIRENTRY_TLS].Size)) { dbgprn("TLS present, processing\n");  _CALL(ldr_call_tls_callbacks); }


  wprintf(L"CALLING EP\n");
  Z(lpEntryPoint) = (PVOID)((DWORD_PTR)lpMappedImage + Z(ldr_pOptHdr)->AddressOfEntryPoint);
  wprintf(L"lpEntryPoint = %p\n", lpEntryPoint);
  if (Z(IsDll)) { _CALL(call_dll); } else { _CALL(call_exe); }




  wprintf(L"Freeing file buffer\n");
  free(Z(lpBuffer));

  wprintf(L"main() done\n");

  //@@@endproc
  main_POST();
}




