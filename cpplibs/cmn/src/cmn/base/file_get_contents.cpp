#include "cmn/base/file_get_contents.h"

using namespace std;

namespace cmn {
namespace base {

bool file_get_contents(const string& path, string& bin_data) {
  wstring wpath(path.begin(), path.end());
  return file_get_contents(wpath, bin_data);
}

bool file_get_contents(const wstring& path, string& bin_data) {
  FILE* f;
  if (_wfopen_s(&f, path.c_str(), L"rb")) {
    return false;
  }

  bool ret = false;

  fseek(f, 0, SEEK_END);
  size_t sz = ftell(f);

  fseek(f, 0L, SEEK_SET);

  bin_data.resize(sz);

  size_t nread = fread((void*)bin_data.c_str(), 1, sz, f);

  if (nread == sz) {
    ret = true;
  }

  fclose(f);
  return ret;
}

}}
