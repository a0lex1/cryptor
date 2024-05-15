#pragma once

#include <string>

namespace cmn {
namespace base {

// supports 0x notation
template <typename C>
static int str_to_integer(const std::basic_string<C>& input) {
  std::wstring ws(input.begin(), input.end());
  std::wstring new_ws;
  int radix;
  if (ws.substr(0, 2) == L"0x") {
    new_ws = ws.substr(2);
    radix = 16;
  }
  else {
    new_ws = ws;
    radix = 10;
  }
  size_t _idx;
  return std::stoul(new_ws, &_idx, radix);
}

#pragma warning(push)
#pragma warning(disable:4244) // include\xstring(2588,23): warning C4244: 'argument': conversion from 'const wchar_t' to 'const _Elem', possible loss of data
static std::string wstr2str(const std::wstring& s) {
  return std::string(s.begin(), s.end());
}
#pragma warning(pop)

static std::wstring str2wstr(const std::string& s) {
  return std::wstring(s.begin(), s.end());
}

}}

/*
  printf("%x\n", str_to_integer<wchar_t>(L"0x24f"));
  printf("%x\n", str_to_integer<wchar_t>(L"24"));
  printf("%x\n", str_to_integer<char>("0x24f"));
  printf("%x\n", str_to_integer<char>("24"));
*/
