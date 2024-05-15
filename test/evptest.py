import os, sys

from c2.test.evptest_case_generator import EVPTestCaseGenerator, EVPTEST_GENTYPES
from c2.test.casetest import CasetestCLI
from c2.test.ldr_project import LdrProject
from c2.test.tst_opts import tmp_dir_from_tst_argv


def evptest_main(argv):
  tmpdir = tmp_dir_from_tst_argv(argv) + '/evptest'

  # Use ldrtest's LdrProject
  ldr_project = LdrProject(tmpdir)

  if not 'bla:noconstruct!' in argv:
    print('\n*** Constructing loader...\n')
    ldr_project.construct_project()


  if not 'bla:nobuild!' in argv:
    print('\n*** Building 32-bit loader...\n')
    ldr_project.build_loader(32)

    print('\n*** Building 64-bit loader...\n')
    ldr_project.build_loader(64)

    print('\n*** Loader has been built\n')


  ldrtest_dll32 = ldr_project.get_loader_exe_path(32, 'dll')
  ldrtest_dll64 = ldr_project.get_loader_exe_path(64, 'dll')
  ldrtest_exe32 = ldr_project.get_loader_exe_path(32, 'exe')
  ldrtest_exe64 = ldr_project.get_loader_exe_path(64, 'exe')


  ctcli = CasetestCLI(argv, EVPTestCaseGenerator(), EVPTEST_GENTYPES,
                      '$jEVPTest',
                      {
                        '$ldrtest_dll32': ldrtest_dll32,
                        '$ldrtest_dll64': ldrtest_dll64,
                        '$ldrtest_exe32': ldrtest_exe32,
                        '$ldrtest_exe64': ldrtest_exe64
                      },
                      os.path.basename(__file__))

  print('Executing CasetestCLI...')
  ctcli.execute()


if __name__ == '__main__':
  evptest_main(sys.argv[1:])





