import os, sys

from c2._internal_config import get_cppbuild_dir, get_tmp_dir
from c2.test.paytest_preparation import PaytestPreparation
from c2.test.paytest_case_generator import PaytestCaseGenerator, PAYTEST_GENTYPES, get_tbdemo_path
from c2.test.casetest import CasetestCLI
from c2.test.tst_opts import tmp_dir_from_tst_argv

_sd = os.path.dirname(__file__)


def get_paytest_repls():
  TESTER_EXE_CONFIGURATION = 'Debug'
  return {
    '$tester32': f'{get_cppbuild_dir()}/tester/{TESTER_EXE_CONFIGURATION}/Win32/tester.exe',
    '$tester64': f'{get_cppbuild_dir()}/tester/{TESTER_EXE_CONFIGURATION}/x64/tester.exe'}


# --sc --exe --dll_pfn_frm   --opts_testbin_bitness 32 --opts_target_projects virprog
# --dry
def paytest_main(argv):
  tmpdir = tmp_dir_from_tst_argv(argv) + '/paytest'

  PaytestPreparation(tmpdir).commit()

  ctcli = CasetestCLI(argv, PaytestCaseGenerator(tmpdir), PAYTEST_GENTYPES,
                      '$jPayTest', get_paytest_repls(),
                      os.path.basename(__file__))

  ctcli.execute()


if __name__ == '__main__':
  paytest_main(sys.argv[1:])
