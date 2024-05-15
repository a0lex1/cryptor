#include "cmn/infra/cli_seed.h"
#include "cmn/infra/seed_db.h"

#include <filesystem>

#include <assert.h>

using namespace std;

namespace cmn {
namespace infra {

// work_dir is optional
CLISeed::CLISeed(Uptr<string> work_dir, int seed_size)
  : work_dir_(move(work_dir)), seed_size_(seed_size)
{

}

void CLISeed::add_to_argparser(argparse::ArgumentParser& parser) {
  parser.add_argument("--seed_file");
  parser.add_argument("--seed_section");
  parser.add_argument("--seed_string");
}


void CLISeed::set_parsed_args(argparse::ArgumentParser& parser) {
  seed_file_ = nullptr;
  seed_section_ = nullptr;
  seed_string_ = nullptr;
  if (parser.present("seed_file")) {
    seed_file_ = make_unique<string>(parser.get<string>("seed_file"));
  }
  if (parser.present("seed_section")) {
    seed_section_ = make_unique<string>(parser.get<string>("seed_section"));
  }
  if (parser.present("seed_string")) {
    seed_string_ = make_unique<string>(parser.get<string>("seed_string"));
  }

  validate();

  if (seed_string_ != nullptr) {
    seed_ = make_unique<string>(*seed_string_);
    return;
  }
  if (seed_section_ != nullptr) {
    if (seed_string_ != nullptr) {
      throw CLISeedException("seed_section can't be combined with seed_string");
    }
    if (seed_file_ == nullptr) {
      if (work_dir_ != nullptr) {
        seed_file_ = make_unique<string>(*work_dir_ + "/seedfile");
      }
      else {
        throw CLISeedException("both work dir and seed file is None");
      }
    }
    SeedDB seed_db(seed_size_);// DEFAULT_SEED_SIZE would need to introduce config.py analogue here, in cpp world
    std::ifstream sdbfile(*seed_file_);
    seed_db.read_from_file(sdbfile);
    Sptr<string> found_seed = seed_db.lookup_seed_for(*seed_section_);
    if (!found_seed){
      throw CLISeedException("section not found in loaded seed db");
    }
    seed_ = make_unique<string>(*found_seed); // duplicate as Uptr
    return;
  }
  // if we got here, seed is not specified
  assert(seed_ == nullptr);
  // OK.
}

bool CLISeed::is_specified() const {
  return seed_ != nullptr;
}

string CLISeed::get_seed() {
  assert(is_specified());
  return *seed_;
}

string CLISeed::get_or_generate_seed() {
  if (is_specified()) {
    return get_seed();
  }
  else {
    return seed_generate(seed_size_);
  }
}

void CLISeed::validate() {
  if (seed_file_ != nullptr) {
    if (seed_section_ == nullptr) {
      throw CLISeedException("--seed_file needs --seed_section");
    }
    if (seed_string_ != nullptr) {
      if (seed_section_ != nullptr || seed_file_ != nullptr) {
        throw CLISeedException("--seed_string can't be combined with --seed_section/--seed_file");
      }
    }
  }
}



}}




