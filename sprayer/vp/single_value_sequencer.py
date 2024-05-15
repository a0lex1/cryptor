from typing import Tuple

from c2.sprayer.vp.vrpicker import VRPicker, UsePurpose
from c2.sprayer.vp._random_var_picker import RandomVarPicker
from c2.sprayer.ccode.var import Var


class SingleValueSequencer:
  def pick_var_ind(self, pick_history) -> Tuple[Var, int]:
    raise NotImplementedError()


class SingleValueSequencerFromRandomPicker(SingleValueSequencer): #todo: ...FromOldPicker
  def __init__(self, random_var_picker:RandomVarPicker):
    self.__random_var_picker = random_var_picker

  def pick_var_ind(self, pick_history):
    i_vl, i_var, i_val = self.__random_var_picker.pick_var_ind()
    v = self.__random_var_picker.get_vls()[i_vl][i_var]
    return v, i_val


class SingleValueSequencerFromVRPicker(SingleValueSequencer):
  def __init__(self, use_purpose:UsePurpose, vrpicker:VRPicker, vls):
    self.__use_purpose = use_purpose
    self.__vrpicker = vrpicker
    self.__vls = vls

  def pick_var_ind(self, pick_history) -> Tuple[Var, int]:
    rl = self.__vrpicker.pick_value_range(self.__use_purpose, None, 1)
    pick_history.append((self.__use_purpose, rl))
    return self.__vls[rl.idx_vl][rl.idx_var], rl.idx_val


