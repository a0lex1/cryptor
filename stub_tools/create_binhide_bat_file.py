# _binhide.bat file is used by VS (post-build event)
# it contains call to binhide_facade.py which calls binhide.exe /seed ...

import argparse, shutil, os, sys

from c2._internal_config import get_cppbuild_dir


# This tool can also create a portable copy of binhide.exe
def create_binhide_bat_file_main(argv):
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('-o', '--out_dir', required=True)
  parser.add_argument('--portable', action='store_true', help='Copy binhide.exe to evil dir')
  args = parser.parse_args(argv)

  _sda = os.path.abspath(os.path.dirname(__file__))
  #_tools = f'{_sda}'
  _evildir = os.path.abspath(args.out_dir)

  binhide_exe_path = f'{get_cppbuild_dir()}/binhide/Release/x64/binhide.exe'
  if not args.portable:
    # normal mode
    open(f'{args.out_dir}/_binhide.bat', 'w').write(
    fr'''{binhide_exe_path} -i %1 --seed_file {_evildir}\seedfile --seed_section bh && (echo OK!) || (echo !ERROR! && goto exit)
    :exit
    ''')
  else:
    # portable mode
    print('Copying binhide.exe to evil dir (--portable mode enabled) ...')
    shutil.copyfile(binhide_exe_path, f'{_evildir}/binhide_copy.exe')
    open(f'{args.out_dir}/_binhide.bat', 'w').write(
    fr'''%~dp0\binhide_copy.exe -i %1 --seed_file {_evildir}\seedfile --seed_section bh && (echo OK!) || (echo !ERROR! && goto exit)
    :exit
    ''')


if __name__ == '__main__':
  create_binhide_bat_file_main(sys.argv[1:])


