#include "cmn/infra/seed_db.h"

#include <iostream>
#include <cassert>

using namespace std;
using namespace cmn::infra;

void _test_seed_db_generate_write_read_eq() {
  string seedfile = "./TheSeedFile"; // TODO: shitting in cur [unknown] dir
  int seedsize = 13;

  SeedDB sdb1(seedsize);
  sdb1.generate({ "AAA", "BBB", "CCC" });
  {
    std::ofstream osf(seedfile);
    sdb1.write_to_file(osf);
  }

  SeedDB sdb2(seedsize);
  {
    std::ifstream sf(seedfile);
    sdb2.read_from_file(sf);
  }
  //if (sdb.seed_dict() != )
  for (auto& it : sdb2.list_sections()) {
    Sptr<std::string> lookuped_seed = sdb2.lookup_seed_for(it);
    assert(lookuped_seed != nullptr);
    cout << it << ": " << lookuped_seed->length() << " bytes\n";
  }
  //assert(sdb1.seed_dict() == sdb2.seed_dict());
  assert(sdb1 == sdb2);
}

void test_seed_db() {
  _test_seed_db_generate_write_read_eq();
}
