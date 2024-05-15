import sys

from c2.sprayer.test.test_spraygen_from_sig import test_spraygen_from_sig_main
from c2.sprayer.test.test_spraygen import TestSpraygen
from c2.sprayer.test.test_spraygen_rgold import test_spraygen_rgold_main

from c2.sprayer.test.test_funcgen_min import test_funcgen_min

from c2.test.ldrtest import ldrtest_main

#from c2.pg.test_preset_matrices import test_preset_matrices_main
#from c2.test.test_cryptor import test_cryptor_main

from c2.test.test_backend import test_backend_main
from c2.test.simple_seed_test import simple_seed_test_main
from c2.test.full_seed_test import full_seed_test_main


def all_ct_main(argv):
  test_spraygen_from_sig_main(argv)

  TestSpraygen(argv).execute()

  # min funcgen is required for other tests like paytest so test it here, in CT
  test_funcgen_min(argv)

  # not a complete rgold test, the last one is in rgold_paytest.py
  test_spraygen_rgold_main(argv)

  ldrtest_main(argv)

  #test_preset_matrices_main(argv) #temporary moved out
  #test_cryptor_main(argv) #excessive

  test_backend_main(argv)

  simple_seed_test_main()
  full_seed_test_main()


if __name__ == '__main__':
  all_ct_main(sys.argv[1:])


