import os, sys

from c2._internal_config import get_tmp_dir
from c2.trasher.popularimports2touchprj import PopularImportsCsvToTouchPrj


_sd = os.path.dirname(__file__)

def test_popularimports2touchprj(argv):
  tmp_prj_dir = f'{get_tmp_dir()}/test_popularimports2touchprj'
  os.makedirs(tmp_prj_dir, exist_ok=True)
  dllinclude_file = tmp_prj_dir+'/dllinclude.lst'
  open(dllinclude_file, 'w').write('kernel32.dll\nUsEr32.dLl\n')
  tmp_csv_path = f'{_sd}/td/test_popularimports.csv'
  PopularImportsCsvToTouchPrj(['--dllinclude_file', dllinclude_file,
                   '--touchprj_dir', tmp_prj_dir,
                   '--csv', tmp_csv_path,
                   '--force_cleanup',
                               # '--do_link',
                               # '--do_exec',
                               # '--old_files', 'overwrite',
                               ]).execute()

if __name__ == '__main__':
  test_popularimports2touchprj(sys.argv[1:])
