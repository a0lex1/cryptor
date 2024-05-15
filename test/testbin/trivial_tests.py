import os, sys

from c2._internal_config import get_cppbuild_dir
from c2.common.execcmd import execcmd


# Can't have tests for xxx-in-dll because the way of working is different:
# virlib calls payload's (testbin's) both DllMain and DllInstall (if postfn)
# and DllInstall can't be directly accessed in virlib.dll, it can only be called with postfn mechanism

_sd = os.path.dirname(__file__)

def testbin_trivial_tests_main(argv):
  VSB = get_cppbuild_dir()

  print('* * * * * * * * * * * * * *')
  print('testbin solution MUST BE BUILT before running this program')
  print()
  print('* * * * * * * * * * * * * *')
  print()

  for TBCFG in ['Debug', 'Release']:
    for TBPLAT in ['Win32', 'x64']:
      print(f'\n+++ +++ +++ [ {TBCFG} / {TBPLAT} ] +++ +++ +++\n')

      r = execcmd(fr'{VSB}\tester\debug\x64\tester.exe exe-in-exe {VSB}\testbin\{TBCFG}\{TBPLAT}\testbin.exe')


if __name__ == '__main__':
  testbin_trivial_tests_main(sys.argv[1:])


