import sys
from c2.reskit.restest import ResTestCLI


def test_resdbs_main(argv):
  rtargv = ['-u', '*', ]
  rtcli = ResTestCLI(rtargv)
  rtcli.execute()


if __name__ == '__main__':
  test_resdbs_main(sys.argv[1:])

