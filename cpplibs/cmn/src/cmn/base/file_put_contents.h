#pragma once

#include <string>

namespace cmn {
namespace base {

bool file_put_contents(const std::string& path, const std::string& bin_data);
bool file_put_contents(const std::wstring& path, const std::string& bin_data);

}}

