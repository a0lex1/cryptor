import os, sys

from c2.test.paytest_preparation import PaytestPreparation
from c2.test.paytest_case_generator import PaytestCaseGenerator
from c2.test.paytest import get_paytest_repls
from c2.test.casetest import CasetestCLI
from c2.test.tst_opts import tmp_dir_from_tst_argv

#
# parttest is paytest
#   for dll_pfn_frm payload only (can still be expanded from cmdline)
#   using jen_tag $jPartTest
#
# e.g. parttest is  hollowing paytest's PaytestCaseGenerator  and its relatives
#                   ----------------------------------------
#

def parttest_main(argv):
  tmpdir = tmp_dir_from_tst_argv(argv) + '/parttest'

  PaytestPreparation(tmpdir).commit()

  ctcli = CasetestCLI(argv, PaytestCaseGenerator(tmpdir), ['dll_pfn_frm'], '$jPartTest',
                      get_paytest_repls(),
                      os.path.basename(__file__))
  ctcli.execute()


if __name__ == '__main__':
  parttest_main(sys.argv[1:])


