#pragma once

//pls include windows.h before this header

#define MSGBOX(title, ...) {\
    CHAR buf[255];\
    snprintf(buf, 255, title, __VA_ARGS__);\
    MessageBoxA(0, buf, "MSGBOX", MB_ICONEXCLAMATION);\
  }
#define OUTPUTDBGSTRING(title, ...) {\
    CHAR buf[255];\
    snprintf(buf, 255, title, __VA_ARGS__);\
    OutputDebugStringA(buf); \
  }

typedef HRESULT (WINAPI* LPFN_DllInstall)(BOOL bInstall, PCWSTR pszCmdLine);
//typedef int (WINAPI* LPFN_RundllFunc)(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);//obsolete


// dont append \n, it's auto
void Raise(const char* msg, ...);


BOOL UnsetEnvVarA(LPCSTR lpVarName);
BOOL IsEnvVarSetA(LPCSTR lpVarName);
BOOL IsEnvVarEQA(LPCSTR lpVarName, LPCSTR lpComparand, BOOL case_sensitive = TRUE);
// race condition in these:
BOOL SetNewEnvVarA(LPCSTR lpVarName, LPCSTR lpValue);
BOOL SetNewEnvVarW(LPCWSTR lpVarName, LPCWSTR lpValue);

ULONG_PTR GetParentProcessId(); // By Napalm @ NetCore2K

// replacement for system(); but this shit doesn't pipe fucking stdout
int exec_and_wait(const char* commandLine);

