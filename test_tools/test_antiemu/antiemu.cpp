#include <windows.h>
#include <cstdio>
#include <ntsecapi.h>

#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

int antiemu() {
  BCRYPT_HANDLE CngAlgHandle;
  NTSTATUS st;
  DWORD HashObjectLength;
  DWORD ResultLength;
  st = BCryptOpenAlgorithmProvider(&CngAlgHandle, BCRYPT_SHA1_ALGORITHM, NULL, 0);
  st = BCryptGetProperty(CngAlgHandle, BCRYPT_OBJECT_LENGTH, (PBYTE)& HashObjectLength, sizeof(DWORD), &ResultLength, 0);
  return ResultLength == 4;
}







