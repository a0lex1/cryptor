import sys

from c2.wd.test_resdbs import test_resdbs_main
from c2.wd.test_touchprjs import test_touchprjs_main


def wd_test_main(argv):
  test_touchprjs_main(argv)
  test_resdbs_main(argv)


if __name__ == '__main__':
  wd_test_main(sys.argv[1:])

