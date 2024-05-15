#pragma once

#include "cmn/infra/cli_seed.h"

#include <string>

namespace cmn {
namespace infra {

std::string seed_get_or_generate(CLISeed& cli_seed, int seed_size);

}}

