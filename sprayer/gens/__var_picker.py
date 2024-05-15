from typing import List, Tuple
from enum import Flag, auto

from c2.sprayer.ccode.var import Var, ValueUnknown, ValueUninitialized

class PickFlag(Flag):
  KNOWNS = auto()
  UNINITS = auto()
  UNKNOWNS = auto()

# all by default
PICK_FLAG_ALL = PickFlag.KNOWNS | PickFlag.UNINITS | PickFlag.UNKNOWNS

# TODO: Move it to var_picking/ (it can be renamed to df/) !!!!!!!!!!!!!
# VarPicker is under decision of how to split/interface it. The next refactoring
# will probably decide.
# Arguments can be None in __init__, set u later.
class VarPicker:
  # with_arrofs can be added
  def __init__(self,
               vls=None,
               pickflag:PickFlag=None,
               rng=None,
               vl_weights:List[int]=None,
               var_weigths:List[int]=None):
    self.__vls = vls
    self.__pickflag = pickflag
    self.__rng = rng
    self.__vl_weights = vl_weights
    self.__var_weights = {} # should always exist
    #self.__enable_var_distrib = False

  def get_vls(self) -> List[List[Var]]:
    return self.__vls

  def set_vls(self, vls:List[List[Var]]):
    self.__vls = vls

  def set_pick_flag(self, pickflag:PickFlag):
    self.__pickflag = pickflag

  # vl_weights -> [ 10, 20.5, 33,  ]
  def set_vl_weights(self, vl_weights:List[int]):
    self.__vl_weights = vl_weights

  # var_weights -> {0: [1, 2, 3.329, 4.45, ], 3: [...]}
  def set_var_weights(self, vl_idx:int, var_weights:List[int]):
    self.__var_weights[vl_idx] = var_weights

  # Returns tuple(ivl, ivar, ival)
  def pick_var_ind(self) -> Tuple[int, int, int]:
    def varlistfilter(vl):
      return len([v for v in vl if varfilter(v)]) > 0

    def varfilter(v):
      return ((self.__pickflag & PickFlag.UNKNOWNS) and v.num_unknowns() != 0) or \
             ((self.__pickflag & PickFlag.UNINITS) and v.num_uninits() != 0) or \
             ((self.__pickflag & PickFlag.KNOWNS) and v.num_knowns() != 0)
    def valuefilter(val):
      return ((self.__pickflag & PickFlag.UNKNOWNS) and type(val) == ValueUnknown) or \
             ((self.__pickflag & PickFlag.UNINITS) and type(val) == ValueUninitialized) or \
             ((self.__pickflag & PickFlag.KNOWNS) and type(val) == int)

    flt_vl_idxes = [idx for idx in range(len(self.__vls)) if varlistfilter(self.__vls[idx])]
    #flt_vls = [vl for vl in self.__vls if varlistfilter(vl)]
    if flt_vl_idxes == []:
      raise RuntimeError('no var lists to pick from after filtering (unknowns, uninits, knowns)')

    _ea = {}
    if self.__vl_weights != None:
      flt_vl_weights = tuple(self.__vl_weights[idx] for idx in flt_vl_idxes)
      _ea |= {'weights': flt_vl_weights}
    # -- Choose vl from vls --
    vl_idx = self.__rng.choices(flt_vl_idxes, k=1, **_ea)[0]
    vl = self.__vls[vl_idx]

    #if flt_vl == []: # can't be since we picked vl from vls that contains needed type of value
    #  raise RuntimeError('no VARS to pick from after filtering (unknowns, uninits, knowns)')

    # -- Choose var from vl --
    _ea = {}
    if vl_idx in self.__var_weights:
      _varweights = self.__var_weights[vl_idx]
      _ea |= {'weights': tuple([varwei for varwei in _varweights])}
    var_idxes = [idx for idx in range(len(vl)) if varfilter(vl[idx])]
    var_idx = self.__rng.choices(var_idxes, k=1, **_ea)[0]
    v = vl[var_idx]

    # -- Chose value from var --
    val_idxes = [i for i in range(v.valcount()) if valuefilter(v.values[i])]
    value_idx = self.__rng.choice(val_idxes) # pick random index if it's an array (otherwise, use index 0)

    return vl_idx, var_idx, value_idx




