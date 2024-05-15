#pragma once

#include "cmn/infra/seed_generate.h"
#include "cmn/base/base64.h"
#include "cmn/base/rng.h"
#include "cmn/cpptypes.h"

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <map>
#include <fstream>

namespace cmn {
namespace infra {

static std::string seed_db_encode(const std::string& buffer) {
  return base64_encode(buffer);
}

static std::string seed_db_decode(const std::string& buffer) {
  return base64_decode(buffer);
}

class SeedDB {
public:
  bool operator==(const SeedDB& r) const {
    return this->proptree_ == r.proptree_;
  }

  SeedDB(int seed_size) {
    seed_size_ = seed_size;
  }

  std::vector<std::string> list_sections() const {
    std::vector<std::string> seed_list;
    for (const auto& it : proptree_) {
      seed_list.push_back(it.first);
      //it->second->data(); //value
    }
    return seed_list;
  }

  // Returns nullptr if no such |secname|
  Sptr<std::string> lookup_seed_for(const std::string& secname) const {
    boost::optional<const boost::property_tree::ptree&> child = proptree_.get_child_optional(secname);
    if (!child) {
      // child node is missing
      return nullptr;
    }
    return make_shared<std::string>(seed_db_decode(child.value().data()));
  }
  void put_seed_for(const std::string& secname, const std::string& seed) {
    auto encoded(seed_db_encode(seed));
    proptree_.put<std::string>(secname, encoded);
  }
  void clear_db() {
    proptree_.clear();
  }
  void generate(const std::vector<std::string>& sections) {
    clear_db();
    for (const auto& secname : sections) {
      put_seed_for(secname, seed_generate(seed_size_));
    }
  }
  //void read_from_dict(src_dict) do we need this?
  //void write_to_dict

  void read_from_file(std::ifstream& ifstm) {
    read_from_json(ifstm);
  }
  void write_to_file(std::ofstream& ofstm) {
    write_to_json(ofstm);
  }
private:
  void read_from_json(std::ifstream& ifstm, bool generate_where_empty = false) {
    boost::property_tree::read_json(ifstm, proptree_);
    // generate where empty
    // decode
  }
  void write_to_json(std::ofstream& ofstm) {
    boost::property_tree::write_json(ofstm, proptree_);
  }
private:
  int seed_size_;
  boost::property_tree::ptree proptree_;
};

}}

