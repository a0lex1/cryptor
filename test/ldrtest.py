import argparse
import shutil, os, sys

from c2._internal_config import get_cppbuild_dir, get_tmp_dir
from c2.test.ldr_project import LdrProject

_sd = os.path.dirname(__file__)
_prjdir = f'{get_tmp_dir()}/ldrtest'

def ldrtest_main(argv):

  parser = argparse.ArgumentParser()
  parser.add_argument('--no_rebuild', action='store_true')
  args = parser.parse_args(argv)

  ldr_project = LdrProject(_prjdir)
  if not args.no_rebuild:
    ldr_project.construct_project()
    ldr_project.build_loader(32)
    ldr_project.build_loader(64)
  else:
    print('*** NO REBUILD MODE ***')


  CPPBUILD = get_cppbuild_dir()
  testshit = [
    (64, 'exe', f'{CPPBUILD}/lta1/Debug/x64/lta1.exe', 812739),
    (64, 'exe', f'{CPPBUILD}/lta1/Release/x64/lta1.exe', 812739),
    (32, 'exe', f'{CPPBUILD}/lta1/Debug/Win32/lta1.exe', 812739),
    (32, 'exe', f'{CPPBUILD}/lta1/Release/Win32/lta1.exe', 812739),

    (64, 'dll', f'{CPPBUILD}/lta1lib/Debug/x64/lta1lib.dll', 812739),
    (64, 'dll', f'{CPPBUILD}/lta1lib/Release/x64/lta1lib.dll', 812739),
    (32, 'dll', f'{CPPBUILD}/lta1lib/Debug/Win32/lta1lib.dll', 812739),
    (32, 'dll', f'{CPPBUILD}/lta1lib/Release/Win32/lta1lib.dll', 812739),

    #(32, 'exe', r'z:\win-tools-pt\pe\PEiD\PEiD.exe'), #no relocs
    #(32, 'exe', r'z:\win-tools-pt\thumbcache_viewer.exe'),
    #(64, 'exe', r'z:\win-tools-pt\Nirsoft\DriverView\DriverView.exe')#no relocs
  ]

  for bitness, filetype, filepath, expectret in testshit:
    print(f'Executing LDR PROJECT for {bitness=} {filetype=} {filepath=} {expectret=}')
    ldr_project.use_loader(bitness, filetype, filepath, expectret)

  print('PE loader tests done')


if __name__ == '__main__':
  ldrtest_main(sys.argv[1:])






