import os, sys

from c2.test.paytest import get_paytest_repls
from c2.test.paytest_preparation import PaytestPreparation
from c2.test.paytest_case_generator import PaytestCaseGenerator, PAYTEST_GENTYPES
from c2.test.paytest import get_paytest_repls
from c2.test.casetest import CasetestCLI
from c2.test.tst_opts import tmp_dir_from_tst_argv


# hollowing PaytestCaseGenerator and its relatives


def rgold_paytest_main(argv):
  tmpdir = tmp_dir_from_tst_argv(argv) + '/rgold_paytest'

  PaytestPreparation(tmpdir).commit()

  ctcli = CasetestCLI(argv, PaytestCaseGenerator(tmpdir), PAYTEST_GENTYPES, '$jRGOldTest',
                      get_paytest_repls(),
                      os.path.basename(__file__))
  ctcli.execute()


if __name__ == '__main__':
  rgold_paytest_main(sys.argv[1:])


