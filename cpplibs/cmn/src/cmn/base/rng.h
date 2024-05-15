#pragma once

#include <chrono>
#include <random>

namespace cmn {
namespace base {

class Rng {
public:
  Rng()
    :
#pragma warning(disable:4244) //cpplibs\cmn\src\cmn\base\rng.h(13,92): warning C4244: 'argument': conversion from '_Rep' to 'unsigned int', possible loss of data
    distrib_(0, 0xffffffff), gen_(std::chrono::system_clock::now().time_since_epoch().count())
  {

  }
  Rng(unsigned seed) : distrib_(0, 0xffffffff), gen_(seed) {
  }
  int randint(int min, int max) {
    return distrib_(gen_) % (max - min + 1) + min;
  }
private:
  std::mt19937 gen_;
  std::uniform_int_distribution<unsigned> distrib_; // uniform, unbiased
};

}}
