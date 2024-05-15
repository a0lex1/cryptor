#include "beacon_client.h"

#include "tbcommon.h"

void InformIPC(LPCSTR lpBeaconName) {
  char tester_uid[32];
  if (!GetEnvironmentVariableA("__#TESTER_UID", tester_uid, sizeof(tester_uid))) {
    Raise("GetEnvironmentVariableA(__#TESTER_UID) failed, err %d", GetLastError());
  }
  string event_name = "TesterBeacon_" + string(tester_uid) + "_" + lpBeaconName;

  HANDLE hEvent = OpenEventA(EVENT_ALL_ACCESS, FALSE, event_name.c_str());
  if (!hEvent) {
    Raise("OpenEventA(%s) failed, err %d", event_name.c_str(), GetLastError());
  }
  if (!SetEvent(hEvent)) {
    Raise("SetEvent(%p) failed, err %d", hEvent, GetLastError());
  }
  if (!CloseHandle(hEvent)) {
    Raise("CloseHandle(%p) failed, err %d", hEvent, GetLastError());
  }
}


