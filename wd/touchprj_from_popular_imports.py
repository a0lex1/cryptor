import os, sys

from c2.trasher.popularimports2touchprj import PopularImportsCsvToTouchPrj


_sd = os.path.dirname(__file__)

def touchprj_from_popularimports_main(argv):
  dllexclude_file = f'{_sd}/blacklist_dlls.lst'
  fnexclude_file = f'{_sd}/blacklist_fns.lst'
  piargv = []
  piargv += ['--dllexclude_file', dllexclude_file]
  piargv += ['--fnexclude_file', fnexclude_file]
  piargv += ['--do_link', '--old_files', 'overwrite']

  # STEP 1  produce
  picli = PopularImportsCsvToTouchPrj(piargv)
  picli.execute()

  # STEP 2  adjust
  #adjuster = TouchPrjAdjuster( )
  #adjuster.execute()

  # STEP 3  test
  #



if __name__ == '__main__':
  touchprj_from_popularimports_main(sys.argv[1:])

