#include "cmn/common.h"
#include "cmn/base/str.h"

#include <iostream>
#include <string>
#include <windows.h>

typedef NTSTATUS(WINAPI* LPFN_NtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);

using namespace std;
using namespace cmn::base;

static NTSTATUS DisableErrors(HANDLE hProcess) {
  LPFN_NtSetInformationProcess lpfnNtSetInformationProcess = (LPFN_NtSetInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
  //UINT NewMode = SEM_FAILCRITICALERRORS;
  UINT NewMode = 0;
  NTSTATUS st;
  st = lpfnNtSetInformationProcess(hProcess, 12/*ProcessDefaultHardErrorMode*/, (PVOID)&NewMode, sizeof(NewMode));
  return st;
}

class ExechlpCLI {
public:
  ExechlpCLI(int argc, wchar_t* argv[]): argc_(argc), argv_(argv)
  {
    RtlZeroMemory(&pi_, sizeof(pi_));
  }

  static void usage() {
    cout << "Usage: exechlp.exe [/t <timeout_msec>] [/e] [/b] <executable> [args]\n";
  }

  void execute() {
    if (!manage_args()) {
      dwExitCode_ = 1;
      return;
    }

    printf("timeout: %d (0x%x)\n", timeout_, timeout_);
    printf("suppress_errors: %s\n", suppress_errors_ ? "yes" : "no");

    do_exec();
  }

  int get_ret() {
    return dwExitCode_;
  }

  ~ExechlpCLI() {
    if (pi_.hProcess) {
      CloseHandle(pi_.hProcess);
    }
    if (pi_.hThread) {
      CloseHandle(pi_.hThread);
    }
  }

private:
  void do_exec() {
    NTSTATUS st;
    STARTUPINFOW si;
    RtlZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, (LPWSTR)cmdline_.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi_)) {
      printf("CreateProcessW failed, err %d\n", GetLastError());
      throw runtime_error("CreateProcessW failed");
    }
    printf("CreateProcessW succeeded\n");

    if (suppress_errors_) {
      st = DisableErrors(pi_.hProcess);
      if (st < 0) {
        printf("NtSetInformationProcess(ProcessDefaultHardErrorMode) failed, status %x\n", st);
        throw runtime_error("NtSetInformationProcess failed");
      }
    }
    printf("NtSetInformationProcess(ProcessDefaultHardErrorMode) succeeded\n");

    if (!ResumeThread(pi_.hThread)) {
      printf("ResumeThread failed, err %d\n", GetLastError());
      throw runtime_error("ResumeThread failed");
    }
    printf("Thread resumed\n");

    printf("Waiting %d msec (-1 means INFINITE)\n", timeout_);
    DWORD dwWait = WaitForSingleObject(pi_.hProcess, timeout_);
    printf("Wait done, dwWait = %d\n", dwWait);
    if (timeout_ != INFINITE) {
      if (dwWait == WAIT_TIMEOUT) {
        printf("Timeout, killing process ...\n");
        Beep(200, 300);
        TerminateProcess(pi_.hProcess, 31337);
      }
    }

    if (!GetExitCodeProcess(pi_.hProcess, &dwExitCode_)) {
      printf("GetExitCodeProcess failed, err %d\n", GetLastError());
      throw runtime_error("GetExitCodeProcess failed");
    }
    printf("Process exited, code %d (%x)\n", dwExitCode_, dwExitCode_);
  }

  bool manage_args() {
    int narg;
    for (narg = 1; narg < argc_; narg++) {
      if (!wcscmp(argv_[narg], L"/t")) {
        ENSURE_MORE_ARGS(argc_, narg, 1);
        timeout_ = str_to_integer<wchar_t>(argv_[narg + 1]);
        narg++;
      }
      else if (!wcscmp(argv_[narg], L"/e")) {
        suppress_errors_ = true;
      }
      else if (!wcscmp(argv_[narg], L"/b")) {
        beep_on_kill_ = true;
      }
      else {
        break;
      }
    }
    if (argc_ < 2) {
      usage();
      return false;
    }
    for (int i = narg; i < argc_; i++) {
      wstring sarg(argv_[i]);
      if (sarg.find(L" ") != wstring::npos) {
        cmdline_ += L"\"" + sarg + L"\"";
      }
      else {
        cmdline_ += sarg;
      }
      if (i < argc_ - 1) {
        cmdline_ += L" ";
      }
    }
    wcout << cmdline_ << L"\n";
    return true;
  }

private:
  int argc_;
  wchar_t** argv_;
  DWORD timeout_{ INFINITE };
  bool suppress_errors_{ false };
  bool beep_on_kill_{false};
  wstring cmdline_;
  DWORD dwExitCode_{13111112};
  PROCESS_INFORMATION pi_;
};

int wmain(int argc, wchar_t* argv[]) {
  ExechlpCLI cli(argc, argv);
  cli.execute();
  return cli.get_ret();
}



