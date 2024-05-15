#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

void use_ordinal_imports() {

  if (GetTickCount() == -23) {
    WSADATA wd;
    WSAStartup(MAKEWORD(2, 2), &wd); // ordinal

    socket(0, 0, 0); // ordinal
  }
}

