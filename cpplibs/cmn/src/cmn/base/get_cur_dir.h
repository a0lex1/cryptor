#pragma once

#include <filesystem>

namespace cmn {
namespace base {

static std::string get_cur_dir() {
  return std::filesystem::current_path().generic_string();
}

}}
