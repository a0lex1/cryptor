import sys

from c2.sprayer.eg2.egtest_cli import EGTestCLI
from c2.test.tst_opts import TstOpts, tmp_dir_from_tst_argv
from c2.infra.cli_conf_to_argv import cli_conf_to_argv


# test_exprgens uses EGTestCLI that does all the tests

def test_exprgen_main(argv):
  tmpdir = tmp_dir_from_tst_argv(argv)
  # Passthrough only the tst_opts to EGTestCLI, other opts are filtered
  tst_opts = TstOpts()
  tst_opts.from_argv(argv)
  tst_argv = cli_conf_to_argv('tst', tst_opts.tst_opts)

  test = EGTestCLI(tmpdir, tst_argv)

  test.execute()

  

if __name__ == '__main__':
  test_exprgen_main(sys.argv[1:])


