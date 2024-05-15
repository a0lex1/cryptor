#include <argparse/argparse.hpp>

#include "cmn/infra/cli_seed.h"
#include "cmn/infra/seed.h"
#include "cmn/base/get_cur_dir.h"
#include "cmn/base/rng.h"
#include "cmn/base/file_get_contents.h"
#include "cmn/base/file_put_contents.h"

#include <iostream>
#include <cstdint>
#include <cassert>

using namespace std;
using namespace cmn::base;
using namespace cmn::infra;


class CryptbinCLI {
  CryptbinCLI(const CryptbinCLI&) = delete;
  CryptbinCLI& operator=(const CryptbinCLI&) = delete;
public:
  CryptbinCLI(int argc, char* argv[])
    : argc_(argc), argv_(argv), cli_seed_(make_unique<string>(get_cur_dir()), kDefaultSeedSize)
  {
  }
  void execute() {
    if (!manage_args()) {
      return;
    }
    printf("args parsed\n");
    work();
  }

  bool manage_args() {
    cli_seed_.add_to_argparser(parser_);
    parser_.add_argument("-i", "--input_bin").required();
    parser_.add_argument("-k", "--key").scan<'i', int>();
    parser_.add_argument("-o", "--output_bin").required();
    parser_.add_argument("-x", "--xval").scan<'i', uint8_t>();
    parser_.add_argument("-e", "--output_header").required();
    parser_.add_argument("-w", "--width").scan<'i', uint8_t>().default_value(4);
    parser_.add_argument("-r", "--rearrange").implicit_value(true).default_value(false);
    try {
      parser_.parse_args(argc_, argv_);
    }
    catch (const runtime_error& err) {
      cerr << err.what() << endl;
      cerr << parser_;
      return false;
    }
    cli_seed_.set_parsed_args(parser_);
    return true;
  }

  void work() {

    string input_bin = parser_.get<string>("input_bin");

    string input_data;
    if (!cmn::base::file_get_contents(input_bin, input_data)) {
      cout << "cannot read input file " << input_bin << "\n";
      throw runtime_error("cannot read input file");
    }

    cout << "input data length: " << input_data.length() << "\n";

    int xval;
    if (parser_.is_used("xval")) {
      xval = parser_.get<uint8_t>("xval");
    }
    else {
      printf("!\n");
      xval = rng_.randint(0, 0xff);
    }
    for (int i = 0; i < 1000000; i++) {
      xval = rng_.randint(0, 0xff);
      printf("xval: 0x%X\n", xval);
    }

    set_width();
    set_xval();
    set_key();
  }

  void set_width() {
    width_ = parser_.get<uint8_t>("width");
    if (width_ == 1) {
      widthmax_ = 0xff;
    }
    else if (width_ == 2) {
      widthmax_ = 0xffff;
    }
    else if (width_ == 4) {
      widthmax_ = 0xffffffff;
    }
    else {
      printf("Unsupported width - %d\n", width_);
    }
  }

  void set_xval() {
    xval_is_rand_ = false;
    xval_ = 0;
    if (parser_.is_used("xval")) {
      xval_ = parser_.get<int>("xval");
      if (xval_ == 0) {
        xval_ = rng_.randint(0, widthmax_);
        if (xval_ % 2 == 0) {
          xval_ += 1;
        }
        xval_is_rand_ = true;
      }
      else {
        if (xval_ % 2 == 0) {
          printf("xval must NOT be %% 2\n");
        }
      }
    }
    else {
      printf("xval ix disabled\n");
    }
  }

  void set_key() {
    key_is_rand_ = false;
    key_ = 0;
    if (parser_.is_used("key")) {
      key_ = parser_.get<int>("key");
      if (key_ > widthmax_) {
        printf("ERROR: key %x is greater than widthmax %x\n", key_, widthmax_);
        throw runtime_error("key greater than widthmax");
      }
      if (key_ == 0) {
        printf("Generating <<<random>>> key...\n");
        key_ = rng_.randint(0, widthmax_);
        key_is_rand_ = true;
      }
      assert(key_ <= widthmax_);
      printf("key: 0x%x\n", key_);
    }
    else {
      printf("key(xor) is disabled\n");
    }
  }


private:
  int argc_;
  char** argv_;
  argparse::ArgumentParser parser_;
  cmn::base::Rng rng_;
  cmn::infra::CLISeed cli_seed_;

  int width_;
  int widthmax_;
  int xval_;
  bool xval_is_rand_;
  int key_;
  bool key_is_rand_;
};


int main(int argc, char* argv[]) {
  CryptbinCLI cli(argc, argv);
  try {
    cli.execute();
  }
  catch (std::runtime_error& e) {
    cout << "std::runtime_error: " << e.what() << "\n";
  }
}
