import argparse, random, os, sys
from pprint import pprint

from c2._internal_config import get_tmp_dir
from c2.trasher.popularimports2touchprj import PopularImportsCsvToTouchPrj
from c2.trasher.touchgen import TouchgenPicker


_sd = os.path.dirname(__file__)

def test_touchgen(argv):
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('--no_regenerate', action='store_true')
  args = parser.parse_args(argv)

  tmp_prj_dir = f'{get_tmp_dir()}/test_touchgen'
  tmp_csv_path = f'{_sd}/td/test_popularimports.csv'

  os.makedirs(tmp_prj_dir, exist_ok=True)
  dllinclude_file = tmp_prj_dir+'/dllinclude.lst'
  open(dllinclude_file, 'w').write('kernel32.dll\nUsEr32.dLl\n')

  if not args.no_regenerate:
    argv_extra = []
    carl_popper = PopularImportsCsvToTouchPrj(['--dllinclude_file', dllinclude_file,
                                               '--touchprj_dir', tmp_prj_dir,
                                               '--csv', tmp_csv_path,
                                               '--force_cleanup',
                                               *argv_extra
                                               ])
    carl_popper.execute()

  picker = TouchgenPicker('2..10', '5..15', random.Random(), tmp_prj_dir)
  picker.pick()
  pprint(picker.piece)


if __name__ == '__main__':
  test_touchgen(sys.argv[1:])
