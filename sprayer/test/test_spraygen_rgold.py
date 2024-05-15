import sys
from c2.sprayer.test.test_spraygen import TestSpraygen


# This test can be for only 1 jen inst
def test_spraygen_rgold_main(argv):
  assert(not '--opts_rg' in argv)
  TestSpraygen(argv+['--opts_rg', '$jcs', 'old']).execute()


if __name__ == '__main__':
  test_spraygen_rgold_main(sys.argv[1:])

