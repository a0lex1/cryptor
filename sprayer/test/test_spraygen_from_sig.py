import os, sys

from c2._internal_config import get_tmp_dir
from c2.sprayer.spraygen import SpraygenCLI
from c2.sprayer.test.spraytest_project import SpraytestProject

_sd = os.path.dirname(__file__)
_spraytest_dir = f'{get_tmp_dir()}/test_spraygen_from_sig'

def test_spraygen_from_sig_main(argv):
  st = SpraytestProject(_spraytest_dir)
  st.put(allow_exist=True)

  sgargv = ['-o', _spraytest_dir, '-s', '1,2,3:2', ]
  SpraygenCLI(sgargv).execute()


if __name__ == '__main__':
  test_spraygen_from_sig_main(sys.argv[1:])



