#pragma once

#include "cmn/cpptypes.h"

#include <argparse/argparse.hpp>
#include <exception>

namespace cmn {
namespace infra {

class CLISeedException : public std::exception {
public:
  using std::exception::exception;
};

class CLISeed /*: public ArgProcessor*/ {
public:
  // work_dir is optional
  CLISeed(Uptr<std::string> work_dir, int seed_size);

  //# WARNING, add_to_argparser and set_parser_args are deprecated since
  //# we think about get_addargument_argtups in python
  //#
  void add_to_argparser(argparse::ArgumentParser&);
  void set_parsed_args(argparse::ArgumentParser&);

  bool is_specified() const;
  std::string get_seed();
  std::string get_or_generate_seed();

private:
  void validate();

private:
  Uptr<std::string> work_dir_;
  int seed_size_;

  Uptr<std::string> seed_file_;
  Uptr<std::string> seed_section_;
  Uptr<std::string> seed_string_;

  Uptr<std::string> seed_;

};

}}





