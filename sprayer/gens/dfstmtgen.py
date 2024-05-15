from enum import Enum, auto

from c2.sprayer.vp.var_picker2 import RWVarValueRangePicker
from c2.sprayer.ccode.node import *


class DFStmtForm(Enum):
  ASSIG = auto()
  MEMCPY = auto()
  #RTLCOPYMEMORY = auto()
  #FORLOOP = auto()


def get_includes_for_dfstmtfor(dfstmtform:DFStmtForm):
  if dfstmtform == DFStmtForm.ASSIG:
    return []
  elif dfstmtform == DFStmtForm.MEMCPY:
    return 'string.h'
  else: raise RuntimeError()


class DFStmtGen:
  # Need to provide vls because var_picker returns only indices, not Var object
  def __init__(self, vrpicker:VRPicker, vls):
    self.__vrpicker = vrpicker
    self.__vls = vls
    self.__df_corrector = DataFlowWeightCorrector(vrpicker.get_state())

  def gen_stmt(self, dfstmtform:DFStmtForm) -> Node:
    if dfstmtform == DFStmtForm.MEMCPY:
      return self.__gen_memcpy()
    elif dfstmtform == DFStmtForm.ASSIG:
      return self.__gen_assig()
    else: raise RuntimeError()
    
  def __gen_assig(self):
    self.__vrpicker.set_fn_getwei_list([self.__dfcorrector.fn_getwei, ])
    return node_assig()
    
  def __gen_memcpy(self):
    fn_val_filter_IN = lambda val: type(val) == int
    fn_val_filter_OUT = lambda val: type(val) == int or type(val) == ValueUninitialized() # ??

    item_count = 4
    out_vl_idx, out_var_idx, out_value_idx =\
      self.__vrpicker.pick_var_values_range(False, item_count, VT.i16, [ ], fn_val_filter_OUT)

    in_vl_idx, in_var_idx, in_value_idx =\
      self.__vrpicker.pick_var_values_range(True, item_count, VT.i8, [VT.u16, VT.i16, VT.u32, VT.i32, VT.u8],
                                            fn_val_filter_IN)
        
    in_v = self.__vls[in_vl_idx][in_var_idx]
    out_v = self.__vls[out_vl_idx][out_var_idx]
    return node_call('memcpy', [node_ref(node_arrofs(node_var(in_v), node_const(in_value_idx))),
                                node_ref(node_arrofs(node_var(out_v), node_const(out_value_idx))),
                                node_const(item_count) ####!!!!!!!!!!!!!!!!!!!
                                ])


