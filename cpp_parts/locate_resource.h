#pragma once

// pub
#include "locate.h"
// priv
#include "../res.info.h"

// resource-specific // TODO: struct_fields
struct locate_resource_vars_t {
  HMODULE hSelf;
  HRSRC imageResHandle;
  HANDLE imageResDataHandle;
};

// no args for locate()

