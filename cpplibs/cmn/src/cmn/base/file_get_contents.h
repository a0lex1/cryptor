#pragma once

#include <string>

namespace cmn {
namespace base {

bool file_get_contents(const std::string& path, std::string& bin_data);
bool file_get_contents(const std::wstring& path, std::string& bin_data);

}}
