#include "cmn/infra/cli_seed.h"
#include "cmn/base/get_cur_dir.h"
#include "cmn/base/rng.h"
#include "cmn/base/str.h"

#include <argparse/argparse.hpp>

#include <windows.h>
#include <ImageHlp.h>
#include <iostream>
#include <cassert>
#include <stdexcept>

#pragma comment(lib, "imagehlp.lib")

using namespace std;

#define DWP DWORD_PTR

// can be PIMAGE_NT_HEADERS32, doesn't matter
static BOOL RvaToFileOffset(PIMAGE_NT_HEADERS64 pnh, DWORD dwRva, LPDWORD lpdwOffset) {
  PIMAGE_SECTION_HEADER psh;
  psh = (PIMAGE_SECTION_HEADER)((DWP)& pnh->OptionalHeader
    + pnh->FileHeader.SizeOfOptionalHeader);
  for (UINT i = 0; i < pnh->FileHeader.NumberOfSections; i++) {
    PIMAGE_SECTION_HEADER sh = &psh[i];
    if (dwRva >= sh->VirtualAddress && dwRva <= sh->VirtualAddress + sh->SizeOfRawData)
    {
      DWORD sec_ofs = dwRva - sh->VirtualAddress;
      *lpdwOffset = psh[i].PointerToRawData + sec_ofs;
      return TRUE;
    }
  }
  return FALSE;
}

static unsigned rand32() {
  return rand() << 16 | rand();
}

static unsigned rand_between(unsigned Min, unsigned Max) {
  return (rand32() % (Max - Min)) + Min;
}

#define EDITMZ_FLAG_TIMESTAMPS 1
#define EDITMZ_FLAG_CHECKSUM 2

static void EditMzAtPlace(void* p, DWORD dwEditmzFlags) {
  assert(dwEditmzFlags != 0);

  // Confusion about x86/x64 using of this tool/code (optional header.. )
  PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)p;

  PIMAGE_DATA_DIRECTORY debug_dir = NULL;

  PIMAGE_NT_HEADERS64 pnh64 = (PIMAGE_NT_HEADERS64)((DWP)p + pdh->e_lfanew);
  PIMAGE_NT_HEADERS32 pnh32 = NULL;
  if (pnh64->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
    pnh32 = (PIMAGE_NT_HEADERS32)pnh64;
    debug_dir = &pnh32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
  }
  else {
    if (pnh64->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
      debug_dir = &pnh64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    }
    else {
      assert(!"unknown machine");
    }
  }

  // Generate random timestamp, it's UNIX TIME
#define MIN_UNIX_TIME  1512005988/*2018*/
#define MAX_UNIX_TIME  1669772388/*2023*/
  DWORD dwNewStamp = rand_between(MIN_UNIX_TIME, MAX_UNIX_TIME);
  printf("-= [[[   New time stamp (unix time): %u   ]]] =-\n", dwNewStamp);

  if (dwEditmzFlags & EDITMZ_FLAG_TIMESTAMPS) {
    printf("Flags & EDITMZ_FLAG_TIMESTAMPS :: timestamping FileHeader\n");
    // 1. Edit in FileHeader
    pnh64->FileHeader.TimeDateStamp = dwNewStamp;

    // 2. Edit in DebugDirectory
    // use pnh64 until we need optional header which differs
    printf("DebugDir.VA = %08X, .Size = %08X\n", debug_dir->VirtualAddress, debug_dir->Size);
    printf("Old TimeDateStamp: %08X\n", pnh64->FileHeader.TimeDateStamp);
    //64! opt headers size diff! this is why it detects 0 debug_dir
    DWORD old;
    if (debug_dir->VirtualAddress != 0 && debug_dir->Size != 0) {
      DWORD debug_dir_file_ofs;
      if (RvaToFileOffset(pnh64, debug_dir->VirtualAddress, &debug_dir_file_ofs)) {
        PIMAGE_DEBUG_DIRECTORY pdd = (PIMAGE_DEBUG_DIRECTORY)((DWP)p + debug_dir_file_ofs);

        // Align check before calculating |num_dbgdirs|
        if (debug_dir->Size % sizeof(IMAGE_DEBUG_DIRECTORY) != 0) {
          throw runtime_error("debug_dir->Size % sizeof(IMAGE_DEBUG_DIRECTORY) != 0");
        }
        int num_dbgdirs = debug_dir->Size / sizeof(IMAGE_DEBUG_DIRECTORY);

        // several debug dirs can be
        for (int ndbgdir = 0; ndbgdir < num_dbgdirs; ndbgdir++) {
          //
          // WARNING, WEAKNESS! Not all legit binaries has equal IMAGE_FILE_HEADER.TimeStamp and DEBUG DIR's TimeStamp
          //
          old = pdd[ndbgdir].TimeDateStamp;
          pdd[ndbgdir].TimeDateStamp = dwNewStamp;
          printf("IMAGE_DEBUG_DIRECTORY[%d] TimeDateStamp [file+0x%x] fixed from 0x%x to 0x%x\n",
            ndbgdir,
            debug_dir_file_ofs+ndbgdir*sizeof(IMAGE_DEBUG_DIRECTORY), old, pdd[ndbgdir].TimeDateStamp);
        }
      }
    }
    else {
      printf("Image has no Debug Dir (dir.va = 0x%08X, dir.size = 0x%08X)\n",
             debug_dir->VirtualAddress, debug_dir->Size);
    }
  }

  // 3... Rich! ... Todo
}

static int EditWorker(LPCWSTR lpExeOrDllPath, DWORD dwEditmzFlags) {
  int ret = -1;
  HANDLE f;
  f = CreateFileW(lpExeOrDllPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
  if (f != INVALID_HANDLE_VALUE) {
    HANDLE m;
    DWORD dwSizeHigh, dwFileSize = GetFileSize(f, &dwSizeHigh);
    if (GetLastError() == ERROR_SUCCESS) {
      m = CreateFileMappingA(f, 0, PAGE_READWRITE, 0, 0, NULL);
      if (m != NULL) {
        LPVOID p;
        p = MapViewOfFile(m, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, dwFileSize);
        if (p != NULL) {

          printf("Editing MZ file in file mapping\n");

          // ----------------------------
          EditMzAtPlace(p, dwEditmzFlags);
          ret = 0;

          if (dwEditmzFlags & EDITMZ_FLAG_CHECKSUM) {
            printf("Flags & EDITMZ_FLAG_CHECKSUM :: Checksuming mapped file\n");

            DWORD dwHdrSum, dwCheckSum;
            // ----------------------------
            PIMAGE_NT_HEADERS pnh = CheckSumMappedFile(
              p, dwFileSize, &dwHdrSum, &dwCheckSum);

            if (pnh != NULL) {
              printf("New checksum: HDR checksum=%08X checksum=%08X\n", dwHdrSum, dwCheckSum);

              // DONE
              pnh->OptionalHeader.CheckSum = dwCheckSum;
            }
            else {
              printf("ERROR: CheckSumMappedFile failed! err %d\n", GetLastError());
            }
          }

          printf("Unmapping file\n");
          UnmapViewOfFile(p);

          printf("DONE: %S\n", lpExeOrDllPath);
        }
        else {
          printf("MapViewOfFile Error %d\n", GetLastError());
        }
        CloseHandle(m);
      }
      else {
        printf("CreateFileMapping Error %d\n", GetLastError());
      }
      CloseHandle(f);
    }
  }
  else {
    printf("CreateFileW Error %d\n", GetLastError());
  }
  return ret;
}

/*
int wmain(int argc, wchar_t* argv[]) {

  printf("SYNTAX: binhide /infile file.exe [/seed 12345]\n");
#ifdef _WIN64
  printf("NOTE: this is x64 version of binhide\n");
#else
  printf("NOTE: this is x86 version of binhide\n");
#endif

  wchar_t* a_infile = nullptr, *a_seed = nullptr;
  for (int i = 1; i < argc; i++) {
    if (!_wcsicmp(argv[i], L"/infile")) {
      if (i > argc - 2) { abort(); }
      a_infile = argv[i + 1];
      i++;
      continue;
    }
    if (!_wcsicmp(argv[i], L"/seed")) {
      if (i > argc - 2) { abort(); }
      a_seed = argv[i + 1];
      i++;
      continue;
    }
  }
  if (!a_infile) {
    printf("/infile is required\n");
    return -1;
  }
  long seed;
  if (a_seed) {
    seed = _wtol(a_seed);
    printf("Using seed %d from argument /seed\n", seed);
  }
  else {
    seed = GetTickCount();
    seed *= GetCurrentProcessId() + GetCurrentThreadId();
    printf("Using dumb stupid vulnerable seed - %u\n", seed);
  }
  printf("<binhide.exe rng probe: %d>\n", rand_between(0, -1));

  printf("Sranding...\n");
  srand(seed);

  bool ret = EditWorker(a_infile, EDITMZ_FLAG_TIMESTAMPS);

  return ret;
}
*/

// NEW CODE

// WARNING: May not support UNICODE (we use str2wstr())
class BinhideCLI {
  BinhideCLI(const BinhideCLI&) = delete;
  BinhideCLI& operator=(const BinhideCLI&) = delete;
public:
  BinhideCLI(int argc, char* argv[])
    :
    argc_(argc), argv_(argv),
    cli_seed_(
      make_unique<std::string>(cmn::base::get_cur_dir()),
      16 // seed_size
    )
  {
  }
  void execute() {
    if (!manage_args()) {
      return;
    }
    printf("args parsed\n");
    work();
  }

  bool manage_args() {
    cli_seed_.add_to_argparser(parser_);
    parser_.add_argument("-i", "--input_file").required();
    try {
      parser_.parse_args(argc_, argv_);
    }
    catch (const runtime_error& err) {
      cerr << err.what() << endl;
      cerr << parser_;
      return false;
    }
    cli_seed_.set_parsed_args(parser_);
    return true;
  }

  void work() {
    bool ret = EditWorker(
      cmn::base::str2wstr(parser_.get<string>("input_file")).c_str(),
      EDITMZ_FLAG_TIMESTAMPS
    );
    if (!ret) {
      throw runtime_error("EditWorker returned false");
    }
  }
private:
  int argc_;
  char** argv_;
  argparse::ArgumentParser parser_;
  cmn::base::Rng rng_;
  cmn::infra::CLISeed cli_seed_;
  int seed_size_;
};


int main(int argc, char* argv[]) {
  BinhideCLI cli(argc, argv);
  try {
    cli.execute();
  }
  catch (std::runtime_error& e) {
    cout << "std::runtime_error: " << e.what() << "\n";
  }
}

