import sys

from c2.trasher.test_trash_add import TestTrashAddMainCLI


def test_touchprjs_main(argv):
  trargv = ['--real_touchprj', '--opts_use_all', 'true']
  trcli = TestTrashAddMainCLI(trargv)
  trcli.execute()


if __name__ == '__main__':
  test_touchprjs_main(sys.argv[1:])

