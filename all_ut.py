import os, sys

from c2.stub_tools.test.test_stubtools import test_stubtools_main
from c2.common.execcmd import execcmd
from c2.test.testbin.trivial_tests import testbin_trivial_tests_main 
from c2.ut import test_all
from c2.reskit.restest import ResTestCLI

_sd = os.path.dirname(__file__)

def all_ut_main(argv):
  test_stubtools_main(argv)

  execcmd(f'{_sd}/p2gen/test.bat')

  testbin_trivial_tests_main(argv)

  ResTestCLI(argv+['--repository_dir', f'{_sd}/reskit/td/testrep', '-u', '*']).execute()

  test_all(argv)

if __name__ == '__main__':
  all_ut_main(sys.argv[1:])

