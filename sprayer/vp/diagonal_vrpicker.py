from typing import Tuple

from c2.sprayer.vp.vrpicker import *
from c2.sprayer.vp.stock import STOCK_diagonalvls_vls
from c2.sprayer.ccode.var import *


# Not a real VRPicker. This is used by tests. It doesn't support fn_isgood AT ALL; requires vls to be diagonal (equal number of vls, vars and values) (for the simplicity of the implementation)
# DiagonalVRPicker is not to be known by factory.
class DiagonalVRPicker(VRPicker):
  def __init__(self, vls):
    self.__vls = vls
    self.__i = 0
    self.__diagonal_size = len(self.__vls)
    assert(self.__diagonal_size > 0)
    self.__validate_diagonal_size()

  def __validate_diagonal_size(self):
    all_var_sizes = []
    for nvl in range(len(self.__vls)):
      vl = self.__vls[nvl]
      for nvar in range(len(vl)):
        v = vl[nvar]
        all_var_sizes.append(len(v.values))
    # Check we have the single repeating var size (the number of values) in |all_var_sizes|
    if set(all_var_sizes) != {all_var_sizes[0]}:
      print('Not a repeating same size:', all_var_sizes)
      raise RuntimeError()

  def set_fn_isgood(self, fn_isgood:FnIsGood):
    assert(fn_isgood == None)

  def set_fn_getwei(self, fn_getwei:FnGetWei):
    assert(fn_getwei == None)

  def pick_value_range(self,
                       use_purpose:UsePurpose,
                       requested_byte_count:int,
                       requested_item_count:int) -> RangeLocation:
    cur_i = self.__i
    self.__i += 1
    if self.__i == self.__diagonal_size:
      self.__i = 0 # circle it around
    rl = RangeLocation(cur_i, cur_i, cur_i, requested_byte_count, requested_item_count,
                       self.__vls[cur_i][cur_i].typ)
    return rl

  def commit_picked_value_range(self, use_purpose, rl:RangeLocation):
    # nothing to do
    pass

  def set_logfn(self, logfn:Callable[[str], None]):
    self._logfn = logfn



def test_diagonal_vrpicker():
  vrpd = DiagonalVRPicker(STOCK_diagonalvls_vls)
  for i in range(100):
    rl = vrpd.pick_value_range(None, 2, None)
    print(rl)


if __name__ == '__main__':
  test_diagonal_vrpicker()

