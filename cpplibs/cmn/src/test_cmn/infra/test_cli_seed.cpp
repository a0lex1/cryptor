#include "cmn/base/cmdline/argc_argv_from_strings.h"

#include "cmn/infra/cli_seed.h"
#include "cmn/infra/seed_db.h"
#include "cmn/cpptypes.h"

#include <filesystem>


using namespace std;
using namespace cmn::infra;
using namespace cmn::base::cmdline;

static const int kDefaultSeedSize = 16;

namespace {
class Tester {
public:
  Tester(const string& work_dir, int seed_size) : work_dir_(work_dir), seed_size_(seed_size) {

  }

  // Don't include `progname` as argv[0], start right from first argument
  Sptr<CLISeed> test_expect(const list<string>& argv,
    const Sptr<string> expect_seed = nullptr)
  {
    Sptr<CLISeed> cli_seed(
      make_shared<CLISeed>(make_unique<string>(work_dir_), seed_size_)
    );
    auto dir_path(std::filesystem::path(__FILE__).filename().string());
    argparse::ArgumentParser parser(dir_path);
    cli_seed->add_to_argparser(parser);

    // do parser.parse_args() on |argv| through |helper|
    // C++ version of argparse requires progname as first arg (tested)
    ArgcArgvFromStrings helper(
      make_shared<string>("progname"),
      argv
    );
    parser.parse_args(helper.argc(), helper.argv());

    cli_seed->set_parsed_args(parser);
    if (expect_seed != nullptr) {
      // need to test
      if (*expect_seed != cli_seed->get_or_generate_seed()) {
        cout << "Seeds Not Equal!\n";
        cout << "Expected seed:\n";
        cout << expect_seed->c_str() << "\n";
        cout << "Got seed:\n";
        cout << cli_seed->get_seed() << "\n";
        throw runtime_error("Seeds not eq, see stdout");
      }
    }
    return cli_seed;
  }
private:
  string work_dir_;
  int seed_size_;
};
}


void test_cli_seed() {
  string seedfile = "./seedfile"; // TODO: crapping in unknown [current] dir

  //filesystem::create_directories(seedfile);
  SeedDB seed_db(kDefaultSeedSize);
  seed_db.clear_db();
  string expectedBigA(kDefaultSeedSize, 'A');
  string expectedBigB(kDefaultSeedSize, 'B');
  seed_db.put_seed_for("sec", expectedBigA);
  seed_db.put_seed_for("sec2", expectedBigB);
  {
    std::ofstream ofs(seedfile);
    seed_db.write_to_file(ofs);
  }

#define MKS make_shared<string>
  // Possible variants:
  //   (nothing); --seed_string; --seed_section; --seed_section AND --seed_file
  assert(Tester("./", kDefaultSeedSize).test_expect({})->is_specified() == false);

  Tester("./", kDefaultSeedSize).test_expect({ "--seed_string", "xxx" }, MKS("xxx"));
  Tester("./", kDefaultSeedSize).test_expect({ "--seed_section", "sec" }, MKS(expectedBigA));
  Tester("./", kDefaultSeedSize).test_expect({ "--seed_file", seedfile, "--seed_section", "sec2"}, MKS(expectedBigB));

  // bad cases
  // don't test them cuz they need to introduce some exception classes
}
