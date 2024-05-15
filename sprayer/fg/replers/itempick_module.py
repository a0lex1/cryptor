from typing import Tuple

from c2.sprayer.fg.replers.picking_module_base import PickingModuleBase
from c2.sprayer.vp.vrpicker import UsePurpose
from c2.sprayer.ccode.var import type_classes


class ItempickModule(PickingModuleBase):
  def _get_handler_map(self):
    return {
      '_fin': self.__disp_fin,
      '_fout': self.__disp_fout,
      '_finout': self.__disp_finout
    }

  def __disp_fin(self, args, piece_loc:Tuple[int,int]):
    return self.__generic_item_pick(args, piece_loc, UsePurpose.WRITE, self._host.get_fn_isgood_in())

  def __disp_fout(self, args, piece_loc:Tuple[int,int]):
    return self.__generic_item_pick(args, piece_loc, UsePurpose.READ, self._host.get_fn_isgood_out())

  def __disp_finout(self, args, piece_loc:Tuple[int,int]):
    return self.__generic_item_pick(args, piece_loc, UsePurpose.WRITE, self._host.get_fn_isgood_inout())

  def __generic_item_pick(self, args, piece_loc, use_purpose, fn_isgood):
    # since VRPicker supports both byte_count and item_count (strictly one of them should be int, the other should be None),
    # we have no need to calculate the |byte_count| for the requested type.
    assert(len(args) in [1, 2])
    vt = self._var_type_from_string(args[0])
    assert(vt)
    if len(args) > 1:
      assert(len(args) == 2)
      item_count = int(args[1])
      assert(0 <= item_count)
    else:
      item_count = 1
    return self._generic_pick(piece_loc, None, item_count, fn_isgood, use_purpose)

