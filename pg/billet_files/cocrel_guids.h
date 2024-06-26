#pragma once

#include <windows.h>

#define COCREL_NUM_GUIDPAIRS 4

static constexpr GUID COCREL_CLSID(int n)  {
  switch (n) {
  case 0: return { 0x46c166aa,0x3108,0x11d4,{0x93,0x48,0x00,0xc0,0x4f,0x8e,0xeb,0x71} };
  case 1: return { 0x9ba05972,0xf6a8,0x11cf,{0xa4,0x42,0x00,0xa0,0xc9,0x0a,0x8f,0x39} };
  case 2: return { 0xa25821b5,0xf310,0x41bd,{0x80,0x6f,0x58,0x64,0xcc,0x44,0x1b,0x78} };
  case 3: return { 0x0fb40f0d,0x1021,0x4022,{0x8d,0xa0,0xaa,0xb0,0x58,0x8d,0xfc,0x8b} };
  default: abort();
  }
}

static constexpr GUID COCREL_IID(int n)  {
  switch (n) {
  case 0: return { 0x85d18b6c,0x3032,0x11d4,{0x93,0x48,0x00,0xc0,0x4f,0x8e,0xeb,0x71} };
  case 1: return { 0x85cb6900,0x4d95,0x11cf,{0x96,0x0c,0x00,0x80,0xc7,0xf4,0xee,0x85} };
  case 2: return { 0xf9f55e6b,0x65cc,0x43b3,{0x9e,0x39,0xf6,0x2b,0xd1,0x8b,0x0b,0x9a} };
  case 3: return { 0xc4ab1fea,0xd0dd,0x44fd,{0x96,0xcb,0x41,0xb4,0x1b,0x5f,0x71,0x8a} };
  default: abort();
  }
}

