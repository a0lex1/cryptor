#include <cstdio>
#include <format>
#include <iostream>

#include <windows.h>
#include "tbcommon.h"
#include "beacon_client.h"

#pragma comment(lib, "Winmm.lib")

using namespace std;

// disable format string warnings:
#pragma warning(disable:4477)
#pragma warning(disable:4313)

// PlaySoundA hangs the program, probably because it's called from DllMain
void SignalFromWinMain() {
  Beep(1000, 200);
}

void SignalFromDllInstall() {
  Beep(1700, 200);
}

void SignalFromDllMain() {
  Beep(2700, 200);
}

void SignalFromDllMainFailflagSet() {
  Beep(3500, 200);
}


// DllInstall is our postfn ! It's only called with postfn mechanism
// works with regsvr32 xxx.dll /e /n /i:AnyJunk
HRESULT WINAPI DllInstallF(BOOL bInstall, PCWSTR pszCmdLine) {
#ifdef _WIN64
  const char* arch = "x64";
#else
  const char* arch = "x86";
#endif
  OUTPUTDBGSTRING("Hello from %s DllInstall; a1=%p, a2=%p (%S)\n", arch, bInstall, pszCmdLine, pszCmdLine);
  InformIPC("__@DLLINSTALL_CALLED");
  SignalFromDllInstall();
  return S_OK;
}


PVOID WINAPI XExport0F() {
  MSGBOX("Hello from Export0. No args.");
  return 0;
}

PVOID WINAPI XExport1F(LPVOID a1) {
  MSGBOX("Hello from XExport1; a1=%p\n", a1);
  return 0;
}

PVOID WINAPI XExport2F(LPVOID a1, LPVOID a2) {
  MSGBOX("Hello from XExport2; a1=%p, a2=%p\n", a1, a2);
  return (LPVOID)((DWORD_PTR)a1 + (DWORD_PTR)a2);
}


#ifndef _USRDLL

int APIENTRY WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance,
  _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
{
  if (IsDebuggerPresent()) {
    DebugBreak();
  }
  try {
    InformIPC("__@WINMAIN_CALLED");
    SignalFromWinMain();
  }
  catch (exception&) {
    //cout << "TESTBIN.EXE WinMain(): Exception!!! What: " << e.what() << "\n"; // we're not console app
  }
  return 10000;
}

#else

static BOOL IsForceDllmainFailFlagSet() {
  CHAR szBuf[10];
  return 0 != GetEnvironmentVariableA("TESTBIN_DLLMAINFAIL", szBuf, 10);
}

BOOL WINAPI DllMain(_In_ void* _DllHandle, _In_ unsigned long _Reason, _In_opt_ void* _Reserved) {
  if (_Reason == DLL_PROCESS_ATTACH) {
    if (IsDebuggerPresent()) {
      DebugBreak();
    }
    if (IsForceDllmainFailFlagSet()) {
      SignalFromDllMainFailflagSet();
      return FALSE;
    }
    InformIPC("__@DLLMAIN_CALLED");
    SignalFromDllMain();
  }
  return TRUE;
}

#endif


