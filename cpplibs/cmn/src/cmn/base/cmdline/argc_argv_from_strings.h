#include "cmn/cpptypes.h"

#include <list>
#include <string>
#include <vector>
#include <memory>

namespace cmn {
namespace base {
namespace cmdline {

// Auxiliary class to help convert string list to argc/argv for C code
class ArgcArgvFromStrings {
public:
  // if |optional_progname| is nullptr, don't include it as first arg
  ArgcArgvFromStrings(Sptr<std::string> optional_progname,
    const std::list<std::string>& stringlist = {})
    :
    optional_progname_(optional_progname),
    stringlist_copy_(stringlist)
  {
    argc_ = static_cast<int>(stringlist_copy_.size());

    if (optional_progname_ != nullptr) {
      argc_ += 1;
      argv_.push_back(const_cast<char*>(optional_progname_->c_str()));
    }
    for (const auto& strin : stringlist_copy_) {
      argv_.push_back(const_cast<char*>(strin.c_str()));
    }
  }

  int argc() const { return argc_; }
  char** argv() {
    if (0 == argc_) {
      // Danger, this will crash argparser! argparser wants at least progname as the only arg.
      static char** noargs = {nullptr};
      return noargs;
    }
    return &argv_[0];
  }

private:
  Sptr<std::string> optional_progname_;
  int argc_;
  std::list<std::string> stringlist_copy_;
  std::vector<char*> argv_;
};


}}}

