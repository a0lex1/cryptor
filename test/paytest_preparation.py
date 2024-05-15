import os

from c2._internal_config import get_cppbuild_dir
from c2.test.paytest_case_generator import get_tbdemo_path
from c2.common.execcmd import execcmd

_sd = os.path.dirname(__file__)


class PaytestPreparation:
  def __init__(self, tmpdir):
    self._tmpdir = tmpdir

  def commit(self):
    VSB = get_cppbuild_dir()

    p2gen32 = VSB + 'p2gen86/Release/Win32/p2gen86.exe'
    p2gen64 = VSB + 'p2gen64/Release/x64/p2gen64.exe'
    tbdemo32 = os.path.abspath(get_tbdemo_path(self._tmpdir, 32))
    tbdemo64 = os.path.abspath(get_tbdemo_path(self._tmpdir, 64))
    os.makedirs(os.path.dirname(tbdemo32), exist_ok=True)
    os.makedirs(os.path.dirname(tbdemo64), exist_ok=True)
    if not os.path.isfile(tbdemo32):
      execcmd(f'{p2gen32} gen-tbdemo {tbdemo32}')
      assert (os.path.isfile(tbdemo32))
    if not os.path.isfile(tbdemo64):
      execcmd(f'{p2gen64} gen-tbdemo {tbdemo64}')
      assert (os.path.isfile(tbdemo64))
