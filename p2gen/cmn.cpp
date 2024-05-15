#include "./cmn.h"

#include <stdexcept>
#include <cassert>

#include <fstream>

using namespace std;

void write_entire_file(const wstring& path, const string& data) {

  std::ofstream stm;
  stm.exceptions(ifstream::failbit | ifstream::badbit);
  stm.open(path, std::ios::out | std::ios::binary);
  stm.write(data.c_str(), data.length());
}

void write_entire_file(const string & path, const string & data) {

  wstring wpath(path.begin(), path.end());
  write_entire_file(wpath, data);
}

void read_entire_file(const wstring& path, string& data) {

  std::ifstream stm;
  stm.exceptions(ifstream::failbit | ifstream::badbit);
  stm.open(path, std::ios::in | std::ios::binary);
  stm.seekg(0, stm.end);
  size_t sz(stm.tellg());
  stm.seekg(0, stm.beg);
  data.resize(sz);
  stm.read(const_cast<char*>(data.c_str()), sz);
}

void read_entire_file(const string& path, string& data) {

  wstring wpath(path.begin(), path.end());
  read_entire_file(wpath, data);
}

// ---

void test_cmn() {
  write_entire_file("C:\\vs_build\\1.txt", "fuck");
  string data;
  read_entire_file("C:\\vs_build\\1.txt", data);
  assert(data == "fuck");
}