#include <memory>
#include <vector>
#include <list>
#include <iostream>
#include <sstream>
#include <functional>
#include <stdexcept>
#include <format>
#include <cassert>

#include <windows.h>

#include "beacon_server.h"
#include "tbcommon.h"

using namespace std;

static void Usage() {
  cout << "Usage: tester.exe <what-in-where> <path/to/file> [/export] [/postfn]\n\n";
  cout << " * * * * * * * * * *  SEE case_generator.py  * * * * * * * * * *\n\n";
  cout << " ! Need to Batch REBUILD all prjs/configs when changing anything in testbin !\n\n";
}



// test for case where DllMain of dll that is being loaded returns FALSE
int testdll_dllmainfail(const string& binpath, bool force_dllmain_fail = true) {
  if (force_dllmain_fail) {
    cout << "Loading library with FORCE DLLMAIN FAIL\n";
    if (!SetEnvironmentVariableA("TESTBIN_DLLMAINFAIL", "1")) {
      cout << "ERROR: SetEnvironmentVariableA(TESTBIN_DLLMAINFAIL, 1) failed, error " << GetLastError() << "\n";
      return -1;
    }
  }
  else {
    cout << "Loading library without force dllmain fail\n";
  }
  HMODULE hDll = LoadLibraryA(binpath.c_str());
  if (force_dllmain_fail) {
    SetEnvironmentVariableA("TESTBIN_DLLMAINFAIL", NULL); // delete env var
    if (hDll) {
      cout << "ERROR: DLL loaded although force_dllmain_fail is set! Freeing...\n";
      FreeLibrary(hDll);
      cout << "Returning -1\n";
      return -1;
    }
    else {
      cout << "OK: not loaded\n";
      return 0;
    }
  }
  else {
    if (!hDll) {
      cout << "LoadLibraryA() failed, error " << GetLastError() << "\n";
      return -1;
    }
    else {
      // Warning, memleak now
      cout << "Freeing library...\n";
      if (FreeLibrary(hDll)) {
        cout << "Freeing success\n";
        return 0;
      }
      else {
        cout << "FreeLibrary failed, error " << GetLastError() << "\n";
        return -1;
      }
    }
  }
}

// test for dll
void testdll(const string& binpath,
  const list<string>& expected_envs_after_load,
  const list<string>& expected_beacons_after_load,
  bool                     call_export,
  int                      expected_export_ret,
  const list<string>& expected_envs_after_call_export = {},
  const list<string>& expected_beacons_after_call_export = {})
{
  //unset(all)
  for (auto& env : expected_envs_after_load) {
    UnsetEnvVarA(env.c_str());
  }
  for (auto& env : expected_envs_after_call_export) {
    UnsetEnvVarA(env.c_str());
  }

  BeaconManager beacmgr_afterload("after load dll");
  for (auto& beacon_name : expected_beacons_after_load) {
    beacmgr_afterload.add_beacon(beacon_name.c_str());
  }
  beacmgr_afterload.open_all();

  cout << "Doing LoadLibraryA(\"" << binpath << "\")\n";
  HMODULE hDll = LoadLibraryA(binpath.c_str());
  DWORD dwErr = GetLastError();
  if (!hDll) {
    throw runtime_error(format("LoadLibraryA failed, err {}", dwErr));
  }

  beacmgr_afterload.ensure_all_beacons_reported();
  beacmgr_afterload.close_all();


  // only after_load vars must be set, not after_call_export group,
  for (auto& env : expected_envs_after_load) {
    if (!IsEnvVarSetA(env.c_str())) {
      throw runtime_error(format("After load: Env var must BE set, but not set - {}", env));
    }
  }
  // ,not these I mean:
  for (auto& env : expected_envs_after_call_export) {
    if (IsEnvVarSetA(env.c_str())) {
      throw runtime_error(format("After load: Env var must NOT be set, but set - {}", env));
    }
  }

  if (call_export) {

    BeaconManager beacmgr_after_call_export("after call dll export");
    for (auto& beacon_name : expected_beacons_after_call_export) {
      beacmgr_after_call_export.add_beacon(beacon_name.c_str());
    }
    beacmgr_after_call_export.open_all();


    LPFN_DllInstall lpfnDllInstall = (LPFN_DllInstall)GetProcAddress(hDll, "DllInstall");
    if (!lpfnDllInstall) {
      throw runtime_error("DLL has no DllInstall export");
    }


    cout << "Calling EXPORT ...\n";
    // ---------- CALL Export FUNC ----------
    // We call it here like regsvr32 /e /n /i:CreateEvent xxx.dll

    int export_ret = lpfnDllInstall(TRUE, L"PszCmdLine.exE");//wsignature.c_str());


    beacmgr_after_call_export.ensure_all_beacons_reported();
    beacmgr_after_call_export.close_all();


    vector<string> upset_envvars;
    // Now these env vars must be set:
    for (auto& env : expected_envs_after_call_export) {
      if (!IsEnvVarSetA(env.c_str())) {
        upset_envvars.push_back(env);
      }
    }
    // ------- Check everything after running exported func --------
    bool babort = false;
    if (export_ret != expected_export_ret) {
      babort = true;
      cout << "[BUGBUGBUG] Export() return value: EXPECTED " << expected_export_ret << ", GOT " << export_ret << "\n";
    }
    if (upset_envvars.size()) {
      babort = true;
      cout << "[BUGBUGBUG] Export() unmatched envvar(s):\n";
      for (auto& envvar : upset_envvars) {
        cout << "  " << envvar << "\n";
      }
    }
    if (babort) {
      throw runtime_error(format("Something bad happened, check log\n"));
    }
  }

  printf("Freeing library...\n");
  FreeLibrary(hDll);

  cout << "ok, testdll SUCCEEDED for file " << binpath << "\n";
}



static int CheckExe2(const string& binpath,
  const vector<string>& beacon_names,
  int expect_ret)
{
#ifdef _WIN64
  cout << "Checking2 x64 EXE " << binpath << "\n";
#else
  cout << "Checking2 x86 EXE " << binpath << "\n";
#endif
  BeaconManager beacmgr("after exec exe");
  for (const auto& beacon_name : beacon_names) {
    beacmgr.add_beacon(beacon_name.c_str());
  }
  beacmgr.open_all();

  int r = system(binpath.c_str());

  beacmgr.ensure_all_beacons_reported();

  if (r != expect_ret) {
    cout << format("ERROR: EXE2 must return {}! returned {}\n", expect_ret, r) << "\n";
    return -1;
  }
  return 0; // success
}

static void chk(bool cond, const char* errmsg = nullptr) {
  if (!cond) {
    if (errmsg == nullptr) {
      errmsg = "<err msg not specified>";
    }
    printf("chk: CHECK FAILED!!! err msg: %s\n", errmsg);
    throw runtime_error("chk failed, see log");
  }
}

// throws exceptions, doesn't return value
void main_worker(int argc, char* argv[]) {
  if (argc < 3) {
    throw runtime_error("need at least 2 args");
  }
  string what_in_where = argv[1];
  string binpath = argv[2];
  bool call_export = false, postfn = false;
  for (int i = 3; i < argc; i++) {
    if (string(argv[i]) == "/export") {
      call_export = true;
    }
    else if (string(argv[i]) == "/postfn") {
      postfn = true;
    }
  }

  printf("tester: what_in_where=%s call_export=%s postfn=%s\n", what_in_where.c_str(), call_export ? "Y" : "N", postfn ? "Y" : "N");

  if (what_in_where == "sc-in-exe" || what_in_where == "exe-in-exe" || what_in_where == "dll-in-exe") {

    // --------------------- Working with  EXE  file ---------------------

    int ret;

    if (what_in_where == "sc-in-exe") {
      chk(!postfn, "shellcode can't have postfn (nowhere to get postfn rva)");
      chk(!call_export, "can't validate /export in EXE files");

      ret = CheckExe2(binpath, {}, 12000);
    }
    else if (what_in_where == "exe-in-exe") {
      chk(!postfn, "postfn doesn't work in EXEs because testbin.exe's CRT does ExitProcess after main returns");

      ret = CheckExe2(binpath, {"__@WINMAIN_CALLED"}, 10000);
    }
    else {
      assert(what_in_where == "dll-in-exe");
      chk(!call_export, "can'\t validate /export in EXE files");

      // We expect 1 here, e.g. TRUE. Because p2code returns what DllMain
      // returns and it's TRUE. WinMain's EVILPROC_POST will do return g_dwP2Ret
      // so we expect 1 here.
      if (!postfn) {
        ret = CheckExe2(binpath, { "__@DLLMAIN_CALLED" },
          1); // virlib's export returns what p2code returns - DllMain's TRUE
      }
      else {
        ret = CheckExe2(binpath, { "__@DLLMAIN_CALLED", "__@DLLINSTALL_CALLED"},
          0); // postfn (DllInstall) overrides result with S_OK
      }
    }

    if (ret != 0) {
      throw runtime_error(format("something failed, ret -> {}", ret));
    }
  }
  else if (what_in_where == "sc-in-dll" || what_in_where == "exe-in-dll" || what_in_where == "dll-in-dll") {

    // --------------------- Working with  DLL  file ---------------------

    list<string> check_envs_after_load;
    int expected_export_ret;
    list<string> check_envs_after_call_export;

    list<string> expected_beacons_after_load, expected_beacons_after_call_export;

#define IGNORED_RET (-227)
    if (what_in_where == "sc-in-dll") {
      chk(!postfn, "postfn doesn't work in EXEs");
      if (!call_export) {
        // FRM mode
        check_envs_after_load = { "__SHELLCODE_CALLED" };
        expected_export_ret = IGNORED_RET; // ignored by testdll()
      }
      else {
        check_envs_after_load = {};
        expected_export_ret = 12000;
        check_envs_after_call_export = {"__SHELLCODE_CALLED"};
      }
    }

    else if (what_in_where == "exe-in-dll") {
      chk(!postfn, "postfn doesn't work in EXEs");
      if (!call_export) {
        // FRM mode
        expected_export_ret = IGNORED_RET; // ignored by testdll()
        expected_beacons_after_load.push_back("__@WINMAIN_CALLED");
      }
      else {
        check_envs_after_load = {};
        expected_export_ret = 10000;
        expected_beacons_after_call_export.push_back("__@WINMAIN_CALLED");
      }
    }

    else if (what_in_where == "dll-in-dll") {

      // We're not calling export at all!
      check_envs_after_call_export = {};
      if (!call_export) {
        // FRM mode
        expected_export_ret = IGNORED_RET; // ignored by testdll()
        expected_beacons_after_load.push_back("__@DLLMAIN_CALLED");
      }
      else {
        // Expect 1 (TRUE). Export returns g_dwP2Ret, where p2code returns TRUE - what underlying DllMain returned
        expected_export_ret = (int)TRUE;
        expected_beacons_after_call_export.push_back("__@DLLMAIN_CALLED");
      }
      if (postfn) {
        if (!call_export) {
          // FRM mode with postfn
          expected_beacons_after_load.push_back("__@DLLINSTALL_CALLED");
        }
        else {
          expected_export_ret = (int)S_OK; // postfn (DllInstall) overrides
          expected_beacons_after_call_export.push_back("__@DLLINSTALL_CALLED");
        }
      }
    }
    else {
      throw runtime_error("not reached");
    }

    // --------- Actually call testdll() ---------

    testdll(
      binpath,
      check_envs_after_load,
      expected_beacons_after_load,
      call_export,
      expected_export_ret,
      check_envs_after_call_export,
      expected_beacons_after_call_export);

  }
  else {
    throw runtime_error(format("unknown what_in_where - {}", what_in_where));
  }
}


int main(int argc, char* argv[]) {
  int ret;

  try {

    main_worker(argc, argv);

    ret = 0;

  }
  catch (exception& e) {
    cout << "^^^^^^^^^^ Exception in tester!!! What: " << e.what() << "\n";

    ret = -1;
  }

  cout << "testbin TESTER: returning " << ret << "\n";
  return ret;
}


// wtf?
// tester --dll=test_bin.dll
// tester --exe=test_bin.exe

// set TESTBIN_DLLMAIN_FAIL=1
// 
// test_bin.dll 
// 
// test_bin.exe --return=992



