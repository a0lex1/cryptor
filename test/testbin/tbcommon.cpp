#include <format>
#include <stdexcept>
#include <windows.h>
#include "tbcommon.h"

using namespace std;


// don't append \n, it's auto
void Raise(const char* msg, ...) {
  va_list vl;
  va_start(vl, msg);
  char buf[1024];
  _vsnprintf_s(buf, sizeof(buf), msg, vl);
  strncat_s(buf, sizeof(buf), "\n", 1);
  OutputDebugStringA(buf);
  printf("%s", buf); // only if there is a console...
  throw runtime_error(buf);
}


BOOL UnsetEnvVarA(LPCSTR lpVarName) {
  return SetEnvironmentVariableA(lpVarName, NULL);
}

BOOL IsEnvVarSetA(LPCSTR lpVarName) {
  return GetEnvironmentVariableA(lpVarName, NULL, 0);
}

BOOL IsEnvVarEQA(LPCSTR lpVarName, LPCSTR lpComparand, BOOL case_sensitive ) {
  CHAR value[2048];
  if (GetEnvironmentVariableA(lpVarName, value, 2048)) {
    if (case_sensitive) {
      if (!strcmp(value, lpComparand)) {
        return TRUE;
      }
    }
    else {
      if (!_stricmp(value, lpComparand)) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

BOOL SetNewEnvVarA(LPCSTR lpVarName, LPCSTR lpValue) {
  if (GetEnvironmentVariableA(lpVarName, NULL, 0)) {
    throw runtime_error(format("Var {} already set !", lpVarName));
  }
  return SetEnvironmentVariableA(lpVarName, lpValue);
}

BOOL SetNewEnvVarW(LPCWSTR lpVarName, LPCWSTR lpValue) {
  if (GetEnvironmentVariableW(lpVarName, NULL, 0)) {
    throw runtime_error("Var {} already set !");
  }
  return SetEnvironmentVariableW(lpVarName, lpValue);
}


ULONG_PTR GetParentProcessId() // By Napalm @ NetCore2K
{
  ULONG_PTR pbi[6];
  ULONG ulSize = 0;
  LONG(WINAPI * NtQueryInformationProcess)(HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
  *(FARPROC*)&NtQueryInformationProcess =
    GetProcAddress(LoadLibraryA("NTDLL.DLL"), "NtQueryInformationProcess");
  if (NtQueryInformationProcess) {
    if (NtQueryInformationProcess(GetCurrentProcess(), 0,
      &pbi, sizeof(pbi), &ulSize) >= 0 && ulSize == sizeof(pbi))
      return pbi[5];
  }
  return (ULONG_PTR)-1;
}


// doesn't pipe stdout
int exec_and_wait(const char* commandLine)
{
  const size_t stringSize = 1000;
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  DWORD exit_code;
  //char commandLine[stringSize] = "C:\\myDir\\someExecutable.exe param1 param2";
  //WCHAR wCommandLine[stringSize];
  //mbstowcs(wCommandLine, commandLine, stringSize);

  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));

  // Start the child process. 
  if (!CreateProcessA(NULL,  // No module name (use command line)
    (char*)commandLine,    // Command line
    NULL,           // Process handle not inheritable
    NULL,           // Thread handle not inheritable
    FALSE,          // Set handle inheritance to FALSE
    0,              // No creation flags
    NULL,           // Use parent's environment block
    NULL,           // Use parent's starting directory 
    &si,            // Pointer to STARTUPINFO structure
    &pi)           // Pointer to PROCESS_INFORMATION structure
    )
  {
    throw runtime_error(format("CreateProcess failed (err {}).\n", GetLastError()));
  }

  // Wait until child process exits.
  WaitForSingleObject(pi.hProcess, INFINITE);

  GetExitCodeProcess(pi.hProcess, &exit_code);

  printf("the execution of: \"%s\"\nreturns: %d\n", commandLine, exit_code);

  // Close process and thread handles. 
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  return exit_code;
}

/*int exec_and_wait2(const char* commandLine) {
  SHELLEXECUTEINFOA ShExecInfo = { 0 };
  ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
  ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
  ShExecInfo.hwnd = NULL;
  ShExecInfo.lpVerb = NULL;
  ShExecInfo.lpFile = commandLine;
  ShExecInfo.lpParameters = "";
  ShExecInfo.lpDirectory = NULL;
  ShExecInfo.nShow = SW_SHOW;
  ShExecInfo.hInstApp = NULL;
  ShellExecuteExA(&ShExecInfo);
  WaitForSingleObject(ShExecInfo.hProcess, INFINITE);
}*/