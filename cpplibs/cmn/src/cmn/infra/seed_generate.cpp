#include "cmn/infra/seed_generate.h"

#include "cmn/base/rng.h"

using namespace std;

namespace cmn {
namespace infra {

string seed_generate(int seed_size) {
  string buf;
  buf.resize(seed_size);
  char* bufhack = (char*)buf.c_str();
  cmn::base::Rng rng;
  for (size_t i = 0; i < seed_size; i++) {
    bufhack[i] = rng.randint(0, 0xff);
  }
  return buf;
}

}}

