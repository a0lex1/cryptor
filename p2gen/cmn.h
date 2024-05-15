#pragma once

#include <string>

void test_cmn();

#define ALIGN_UP(x, m) ALIGN_DOWN((uintptr_t)(x)+(uintptr_t)(m)-1, (m))
#define ALIGN_DOWN(x, n) ((uintptr_t)(x) - ((uintptr_t)(x) % (uintptr_t)(n)))


void write_entire_file(const std::wstring& path, const std::string& data);
void write_entire_file(const std::string& path, const std::string& data);
void read_entire_file(const std::wstring& path, std::string& data);
void read_entire_file(const std::string& path, std::string& data);

