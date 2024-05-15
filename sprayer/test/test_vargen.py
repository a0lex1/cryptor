import random, os, sys
from pprint import pprint

from c2.sprayer.ccode.var import Var, VT, VarNameTable
from c2.sprayer.gens._make_random_var import make_random_var
from c2.sprayer.gens.var_list_generator import VarListGenerator, VLVarsGenFuncs


def _test_varlist_generator(with_RESERVED=False):
  rng = random.Random()

  # Test class VarListGenerator
  vlgen = VarListGenerator(VLVarsGenFuncs(), rng)
  vl_x = vlgen.gen_var_list(1, 10)
  assert(1 <= len(vl_x) <= 10)
  for vlx in vl_x:
    assert(len(vlx.values) >= 1)

  print(f'Generated {len(vl_x)} vars')

  rv = make_random_var(rng, nvuninit=(0, 0), nvunk=(0, 0), nvknown=(1, 5))
  assert(len(rv.values) == rv.num_knowns())
  assert(1 <= rv.num_knowns() <= 5)
  assert(rv.num_uninits() == 0)
  assert(rv.num_unknowns() == 0)

  rv = make_random_var(rng, nvuninit=(1, 5), nvunk=(1, 5), nvknown=(1, 5))
  assert(len(rv.values) == rv.num_knowns()+rv.num_uninits()+rv.num_unknowns())
  assert(1 <= rv.num_knowns() <= 5)
  assert(1 <= rv.num_uninits() <= 5)
  assert(1 <= rv.num_unknowns() <= 5)

  # Test class RandomVarPicker
  vls = [vl_x, [rv]]
  picker = VarPicker(vls, PickFlag.KNOWNS, rng) # may be fuckup here, after refactoring to PickFlags
  ivl, ivar, ival = picker.pick_var_ind()
  print(f'Picked random var indices {ivl=} {ivar=} {ival=}')
  print()



def test_vargen(argv):
  _test_varlist_generator(True)


if __name__ == '__main__':
  test_vargen(sys.argv[1:])

