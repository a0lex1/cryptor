import os, sys

from c2._internal_config import get_tmp_dir
from c2.sprayer.test.funcgen_test import FuncGenTest, CLIConfigArgs
from c2.sprayer.fg.funcgen_min import FuncGenMin
from c2.infra.unischema import unischema_load

_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/../..'


def test_funcgen_min(argv):
  test = FuncGenTest(get_tmp_dir()+'/test_funcgen_min',
                     'test_funcgen_min',
                     lambda: FuncGenMin(),
                     CLIConfigArgs('fgmin_opts',
                                   unischema_load(f'{_sd}/../fgmin_opts.UNISCHEMA', _inclroot),
                                   "$jFGMinTest"),
                     argv
                     )
  test.execute()

if __name__ == '__main__':
  test_funcgen_min(sys.argv[1:])


