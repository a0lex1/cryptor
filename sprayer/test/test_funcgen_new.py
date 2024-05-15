import os, sys

from c2._internal_config import get_tmp_dir
from c2.sprayer.test.funcgen_test import FuncGenTest, CLIConfigArgs
from c2.sprayer.fg.funcgen_new import FuncGenNew
from c2.infra.unischema import unischema_load

_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/../..'


# Use --fgnew_jen_reverse to debug this test from maximum functionality to the minimum
# The minimum is when all the stmtgens disabled, etc.
def test_funcgen_new(argv):
  test = FuncGenTest(get_tmp_dir()+'/test_funcgen_new',
                     'test_funcgen_new',
                     lambda: FuncGenNew(),
                     CLIConfigArgs('fgnew',
                                   unischema_load(f'{_sd}/../fgnew_opts.UNISCHEMA', _inclroot),
                                   '$jFGNewTest'),
                     argv
                     )
  test.execute()

if __name__ == '__main__':
  test_funcgen_new(sys.argv[1:])


