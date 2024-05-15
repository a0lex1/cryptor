from functools import partial

from c2.sprayer.fg.replers.module import Module
from c2.sprayer.fg.replers.functions import FnCreateResult
from c2.sprayer.vp.vrpicker import VRPicker
from c2.sprayer.ccode.var import type_name2class


# A common base for modules that do var picking
class PickingModuleBase(Module):
  def __init__(self, vls, vrpicker:VRPicker):
    self.__vls = vls
    self.__vrpicker = vrpicker

  def _generic_pick(self, piece_loc, byte_count, item_count, fn_isgood, use_purpose) -> FnCreateResult:
    self.__vrpicker.set_fn_isgood(fn_isgood)
    #self.__vrpicker.set_fn_adjustwei() #TODO: adjustwei
    rl = self.__vrpicker.pick_value_range(use_purpose, byte_count, item_count)
    picked_var = self.__vls[rl.idx_vl][rl.idx_var]
    # return a function that creates the result
    return partial(self.__fn_create_var_result, picked_var, rl.idx_val)

  def _var_type_from_string(self, vtstr):
    if vtstr in type_name2class.keys():
      cls = type_name2class[vtstr]
      return cls
    else:
      return None

  def __fn_create_var_result(self, _var, _ival):
    self._host._add_fmt_obj(_var)
    return f'${self._host._get_next_fmt_obj_id()}[{_ival}]'

