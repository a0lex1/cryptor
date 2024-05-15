#include "cmn/base/file_put_contents.h"

using namespace std;

namespace cmn {
namespace base {

bool file_put_contents(const string& path, const string& bin_data) {
  wstring wpath(path.begin(), path.end());
  return file_put_contents(wpath, bin_data);
}

bool file_put_contents(const wstring& path, const string& bin_data) {
  FILE* f;
  if (_wfopen_s(&f, path.c_str(), L"wb")) {
    return false;
  }
  bool ret = false;
  size_t w = fwrite(bin_data.c_str(), 1, bin_data.length(), f);
  ret = (w == bin_data.length());
  fclose(f);
  return ret;
}

}}
