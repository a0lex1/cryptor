import sys

from c2.stub_tools.test.test_cryptbin import test_cryptbin_rearranger


def test_stubtools_main(argv):
  test_cryptbin_rearranger(argv)


if __name__ == '__main__':
  test_stubtools_main(sys.argv[1:])
