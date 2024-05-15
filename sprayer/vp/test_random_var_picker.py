import random
from pprint import pprint

from c2.sprayer.vp._random_var_picker import RandomVarPicker, PICK_FLAG_ALL
from c2.sprayer.ccode.var import *


def test_random_var_picker():
  x1, x2, x3 = Var(VT.i8, [1]), Var(VT.u64, [2]), Var(VT.i16, [3])
  y1, y2, y3 = Var(VT.u8, [11]), Var(VT.i64, [12]), Var(VT.u16, [13])
  vl1 = [x1, x2, x3]
  vl2 = [y1, y2, y3]
  vls = [vl1, vl2]
  rng = random.Random()

  vp = RandomVarPicker(vls, PICK_FLAG_ALL, rng)

  vp.set_vl_weights([1, 3])
  vp.set_var_weights(0, [1,2,1])   # vl1 vars
  vp.set_var_weights(1, [10,5,1])  # vl2 vars

  vnt = VarNameTable(vl1, vl2)

  # #CheckWithEyes
  linecounts = {}
  for i in range(100):
    ivl, ivar, ival = vp.pick_var_ind()
    v = vp.get_vls()[ivl][ivar]
    vn = vnt.get_var_name(v)
    line = f'{vn} [ {ival} ]'
    print(line)
    linecounts.setdefault(line, 0)
    linecounts[line] += 1
  stups = sorted(linecounts.items(), key=lambda x: x[1])
  pprint(stups)


if __name__ == '__main__':
  test_random_var_picker()


