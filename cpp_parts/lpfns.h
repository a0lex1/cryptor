#pragma once

#include "PART_INFO_DEFS.h"
#include "spraygen.h"
#include <windows.h>

typedef LPVOID(WINAPI* LPFN_VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
typedef BOOL(WINAPI* LPFN_VirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL(WINAPI* LPFN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE(WINAPI* LPFN_LoadLibraryExA)(LPCSTR, HANDLE, DWORD);

typedef void*(WINAPI* LPFN_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LPFN_GetModuleHandleA)(LPCSTR);
typedef BOOL(WINAPI* LPFN_DevIoCtl)(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);


#ifdef NEEDAPI_VirtualAlloc
EXTERN_ZVAR(LPFN_VirtualAlloc lpfnVirtualAlloc);
#endif
#ifdef NEEDAPI_VirtualFree
EXTERN_ZVAR(LPFN_VirtualFree lpfnVirtualFree);
#endif
#ifdef NEEDAPI_VirtualProtect
EXTERN_ZVAR(LPFN_VirtualProtect lpfnVirtualProtect);
#endif
#ifdef NEEDAPI_LoadLibraryExA
EXTERN_ZVAR(LPFN_LoadLibraryExA lpfnLoadLibraryExA);
#endif


SPRAYABLE_PROC(lpfns_resolve);


