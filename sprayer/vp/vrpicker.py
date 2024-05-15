import io
import sys, math
from typing import Iterable, Tuple, Dict, List, Callable, Any, IO
from numbers import Number
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum, auto
from prettytable import PrettyTable

from c2.sprayer.vp.range_location import RangeLocation
from c2.sprayer.vp.vls_shape import *
from c2.sprayer.ccode.var import type_names, type_classes


class UsePurpose(Enum):
  READ = auto()
  WRITE = auto()

# User fn that returns good/not good at item-level (Var.values[]) level; for example, some of values can be uninitialized
#                         i_vl i_var i_value
FnIsGood = Callable[[Tuple[int, int,  int],], bool]

# User fn that returns (normalized) Var-level weight
#                    i_vl i_var
# Can return None, in this case Var will not be used
FnGetWei = Callable[[int, int], float|None]

# Abstract classes

# if |fn_isgood| is None, all cells are treated good
class VRPicker:
  def set_fn_isgood_r(self, fn_isgood_r:FnIsGood): raise NotImplementedError()
  def set_fn_isgood_w(self, fn_isgood_w:FnIsGood): raise NotImplementedError()
  def set_fn_getwei(self, fn_getwei:FnGetWei): raise NotImplementedError()
  # only one of |requested_byte_count| and |requested_item_count| should be int (the other should be None)
  def pick_value_range(self,
                       use_purpose:UsePurpose,
                       requested_byte_count:int,
                       requested_item_count:int) -> RangeLocation: raise NotImplementedError()
  def commit_picked_value_range(self, use_purpose, rl:RangeLocation): raise NotImplementedError()
  def set_logfn(self, logfn:Callable[[str], None]): raise NotImplementedError()


class VRPickerState:
  pass

class VRPickerStateInitializer:
  def init_state_from_vls(self, state:VRPickerState, vls): raise NotImplementedError()

class VRPickerStatePrinter:
  def set_enable_hidden_fields(self, enable:bool): raise NotImplementedError()
  def set_enable_debug_layers(self, enable:bool): raise NotImplementedError()
  def set_precision(self, points:int): raise NotImplementedError()
  # vls can be passed to highlight var types in table
  def print(self, state:VRPickerState, stream:IO, vls): raise NotImplementedError()

#--------------------------------------------------------------------------------------

# A base VRPickerStatePrinter, every cell's values are in different shape instances ("layers")
# Cells should contain str or int (condition for being printed); int(s) are rounded optionally
# is_hidden is RESERVED and now ignored
class LayeredVRPickerState(VRPickerState):
  def __init__(self, vls_shape:VlsShape):
    self._vls_shape = vls_shape
    self.__layers = OrderedDict() #{'seq': (VlsShapeInstance(), is_hidden),
    self.__debug_layers = OrderedDict() #same

  # registration order in both debug and non-debug layers, but the non-debug goes first
  def register_instance_layer(self, layer_name:str, inst:VlsShapeInstance, is_hidden:bool):
    assert(not layer_name in self.__layers)
    assert(not layer_name in self.__debug_layers)
    self.__layers[layer_name] = (inst, is_hidden)

  def register_debug_instance_layer(self, layer_name:str, inst:VlsShapeInstance, is_hidden):
    assert(not layer_name in self.__layers)
    assert(not layer_name in self.__debug_layers)
    self.__debug_layers[layer_name] = (inst, is_hidden)

  #                                   layer_name inst              is_hidden
  def get_layers(self) -> OrderedDict[str, Tuple[VlsShapeInstance, bool]]:
    return self.__layers

  def get_debug_layers(self) -> OrderedDict[str, Tuple[VlsShapeInstance, bool]]:
    return self.__debug_layers

  def layer_by_name(self, layer_name:str) -> Tuple[VlsShapeInstance, bool]:
    if layer_name in self.__layers:
      return self.__layers[layer_name]
    else:
      assert(layer_name in self.__debug_layers)
      return self.__debug_layers[layer_name]

# cur_seqnum is in state object, so several VRPickers which are bound to a single state will use the shared counter
class SeqbasedVRPickerState(LayeredVRPickerState):
  def __init__(self, vls_shape:VlsShape):
    super().__init__(vls_shape)
    self.cur_seqnum = 1 # all cells (cells on all state inst(s)) are initially 0, we're gonna put (cur_seqnum++)
    # An instance of vls shape that stores the seqnums, initialized with zeroes
    self.seqnums_inst = vls_shape.instantiate_with_static_value(0)
    self.asterisks_inst = vls_shape.instantiate_with_static_value('')
    self.dbg_candwei_inst = vls_shape.instantiate_with_static_value(None)
    # register layers
    self.register_instance_layer('seq', self.seqnums_inst, is_hidden=False)
    self.register_instance_layer('aster', self.asterisks_inst, is_hidden=False)
    self.register_debug_instance_layer('dbg_candwei', self.dbg_candwei_inst, is_hidden=True)

# TODO:!!!!!!!!!!!!!!!!!!!!!!!!! not 1 !!!!!!!!!! greater num!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# for non-empty initial vls, state needs to be initialized
class SeqbasedVRPickerStateInitializer(VRPickerStateInitializer):
  def init_state_from_vls(self, state: VRPickerState, vls):
    assert(isinstance(state, SeqbasedVRPickerState))
    at_least_one_put = False
    for i_vl in range(len(vls)):
      vl = vls[i_vl]
      for i_var in range(len(vl)):
        v = vl[i_var]
        for i_value in range(len(v.values)):
          if v.is_elem_init(i_value):
            state.seqnums_inst[i_vl][i_var][i_value] = 1 # put seqnum=1 on initialized values
            at_least_one_put = True
          else:
            state.seqnums_inst
    if at_least_one_put:
      state.cur_seqnum = 2
    else:
      state.cur_seqnum = 1
    return


class InsularVRPickerStateInitializer(SeqbasedVRPickerStateInitializer):
  def init_state_from_vls(self, state: VRPickerState, vls):
    assert(isinstance(state, InsularVRPickerState))
    super().init_state_from_vls(state, vls)
    self.__make_coasts()
    #TODO: edge coasts!!!!!!!!!!!!!!!!!!!!

  def __make_coasts(self):
    ##############
    # TODO
    ##############
    return


class InsularVRPickerState(SeqbasedVRPickerState):
  def __init__(self, vls_shape:VlsShape):
    super().__init__(vls_shape)
    # 1  1/2  1/3  0 ...
    self.Lcoast_inst = vls_shape.instantiate_with_static_value(0)
    self.Rcoast_inst = vls_shape.instantiate_with_static_value(0)
    self.coastness_inst = vls_shape.instantiate_with_static_value(None) # 1 when L/R best match
    self.dbg_final_candwei_inst = vls_shape.instantiate_with_static_value(None)
    # register layer
    self.register_instance_layer('Lcoast', self.Lcoast_inst, is_hidden=False)
    self.register_instance_layer('Rcoast', self.Rcoast_inst, is_hidden=False)
    self.register_instance_layer('coastness', self.coastness_inst, is_hidden=True)
    self.register_debug_instance_layer('dbg_final_candwei', self.dbg_final_candwei_inst, is_hidden=True)
    # TODO: coasts on edges

#--------------------------------------------------------------------------------------

# A LayeredVRPickerState-compatible VRPickerStatePrinter
class LayeredVRPickerStatePrinter(VRPickerStatePrinter):
  def __init__(self):
    self.__enable_hidden_fields = False
    self.__enable_debug_layers = False
    self._precision_points = 10

  def set_enable_hidden_fields(self, enable:bool):
    self.__enable_hidden_fields = enable

  def set_precision(self, points:int):
    self._precision_points = points

  def print(self, state:VRPickerState, stream:IO, vls=None):
    assert(isinstance(state, LayeredVRPickerState)) #dynamic type check
    # get the longest Var (max items in .values); padding will be added
    max_value_count = self.__get_max_value_count(state._vls_shape)
    for i_vl in range(len(state._vls_shape.lists)):
      vl = state._vls_shape.lists[i_vl]
      table = PrettyTable([f'VL{i_vl}'] + ['LAY'] + [f'#{n}' for n in range(max_value_count)])
      for i_var in range(len(vl)):
        valcount = vl[i_var]
        valtexts = []
        # first row is for LAY
        laynames = []
        for layname in state.get_layers().keys():
          laynames.append(layname)
        if self.__enable_debug_layers:
          for debug_layname in state.get_debug_layers().keys():
            laynames.append(debug_layname)
        valtexts.append('\n'.join(laynames))
        # append every cell
        for i_value in range(valcount):
          # print cell data from all layers, \n-separated (vertical in ASCII)
          buf = io.StringIO()

          for layer_name in state.get_layers().keys():
            self.__print_cell(state, False, layer_name, i_vl, i_var, i_value, buf)
          if self.__enable_debug_layers:
            for debug_layer_name in state.get_debug_layers().keys():
              self.__print_cell(state, True, debug_layer_name, i_vl, i_var, i_value, buf) # debug layers

          #bufstr = buf.getvalue().rstrip() # remove the last \n
          bufstr = buf.getvalue() #don't remove; let it be the space to see better
          valtexts.append(bufstr)
        pad_texts = ['' for _ in range(max_value_count - valcount)]
        _ti = ''
        if vls != None:
          _ti = f' {type_names[vls[i_vl][i_var].typ]}'
        table.add_row([f'[{i_vl}][{i_var}]{_ti}', *valtexts, *pad_texts])
      stream.write(str(table))
      stream.write('\n')
      pass # next i_vl

  def set_enable_debug_layers(self, enable:bool):
    self.__enable_debug_layers = enable

  # print all layers' values for one cell, separated by \n
  def __print_cell(self, state:LayeredVRPickerState, use_debug_list:bool,
                   layer_name, i_vl, i_var, i_val, buf:IO):
    if use_debug_list:
      layer_inst, layer_is_hidden = state.get_debug_layers()[layer_name]
    else:
      layer_inst, layer_is_hidden = state.get_layers()[layer_name]
    # TODO: HIDDEN FIELDS?
    _xvalue = layer_inst[i_vl][i_var][i_val]
    if type(_xvalue) == int or type(_xvalue) == float:
      _xvalue = round(_xvalue, self._precision_points)
    elif type(_xvalue) == str:
      pass
    elif _xvalue == None:
      _xvalue = 'None'
    else:
      raise RuntimeError(f'cells need to be str or int/float,  not {type(_xvalue)=}')
    buf.write(f'{_xvalue}\n')

  def __get_max_value_count(self, vls_shape:VlsShape):
    cur_max = 0
    for vl in vls_shape.lists:
      for l in vl:
        if cur_max < l:
          cur_max = l
    return cur_max


class SeqbasedVRPickerStatePrinter(LayeredVRPickerStatePrinter):
  pass

class InsularVRPickerStatePrinter(LayeredVRPickerStatePrinter):
  pass


#--------------------------------------------------------------------------------------

# Base for seqnum-counting based VRPicker(s).
# weight_type -> natural|hyperbola
class SeqbasedVRPickerBase(VRPicker):
  def __init__(self, vls, state:SeqbasedVRPickerState, read_weight_type, write_weight_type, rng):
    assert(read_weight_type in ['natural', 'hyperbola', 'linear'])
    assert(write_weight_type in ['natural', 'hyperbola', 'linear'])
    self._vls = vls
    self._state = state
    self._read_weight_type = read_weight_type
    self._write_weight_type = write_weight_type
    self._rng = rng

    self._fn_isgood_r = None
    self._fn_isgood_w = None
    self._fn_getwei = None

  def set_logfn(self, logfn:Callable[[str], None]):
    self._logfn = logfn

  def set_fn_isgood_r(self, fn_isgood_r:FnIsGood):
    self._fn_isgood_r = fn_isgood_r

  def set_fn_isgood_w(self, fn_isgood_w:FnIsGood):
    self._fn_isgood_w = fn_isgood_w

  def set_fn_getwei(self, fn_getwei:FnGetWei):
    self._fn_getwei = fn_getwei

  # we don't split locations and rates to different lists, we use a list of records which has location and rate
  # for every candidate because it's easier to sort them with a single call to sorted().
  @dataclass
  class _Candidate:
    loc: Tuple[int,int,int] = None
    rate: Any = None
    needed_items: int = None
    props: dict = field(default_factory=dict) # use this to associate opaque data with candidate #not needed yet
  #                            i_vl i_var i_val needed_items
  _FnCalcRate = Callable[[Tuple[int, int,  int], int], Any]
  def _make_candidates(self, fn_isgood:FnIsGood, fn_calcrate:_FnCalcRate,
                       requested_byte_count, requested_item_count # one of them
                       ) ->  List[_Candidate]:
    assert((requested_byte_count == None and type(requested_item_count) == int) or
           (type(requested_byte_count) == int and requested_item_count == None)) # only one of them
    # Collect candidates (possible locations that can hold requested_byte_count)
    cand_locs, cand_rates = [], []
    need_items_arr = [] # temporary list in which we store the need_items
    for idx_vl in range(len(self._vls)):
      vl = self._vls[idx_vl]
      for idx_var in range(len(vl)):
        value_count = len(vl[idx_var].values)
        item_vt = self._vls[idx_vl][idx_var].typ
        if requested_item_count != None:
          assert(requested_byte_count == None)
          need_items = requested_item_count
        else:
          assert(requested_byte_count != None)
          item_size = type_classes[item_vt].byte_size
          need_items = math.ceil(requested_byte_count / item_size)
        max_item = value_count - need_items
        idx_value = 0
        while idx_value <= max_item:
          can_be_placed = True
          for ntryvalue in range(need_items):
            offset = idx_value + ntryvalue
            if fn_isgood != None and not fn_isgood((idx_vl, idx_var, offset)):
              # exit scanning block, set cur value idx to the next item after bad item
              can_be_placed = False
              idx_value = offset
              break  # next space or next var
            # weight is the sum of wprobabs
          if can_be_placed:
            calculated_rate = fn_calcrate((idx_vl, idx_var, idx_value), need_items)
            if calculated_rate != None:
              cand_locs.append((idx_vl, idx_var, idx_value))
              cand_rates.append(calculated_rate)
              need_items_arr.append(need_items)
          # continue looping through values
          idx_value += 1
        # all values of this var have been checked
        pass
      # all vars in this vl have been checked
      pass
    # convert collected separated arrays (cand_locs and cand_rates) to a single list of _Candidate(s)
    _Candidate = SeqbasedVRPickerBase._Candidate
    cands = [_Candidate(cand_locs[i], cand_rates[i], need_items_arr[i]) for i in range(len(cand_locs))]
    return cands

  # multiply the sum of seqnums to bytes_in_item so less items of greater size relates to more items of smaller size
  def _fn_calcrate_seqnum_sum_mul_type_size(self, loc:Tuple[int,int,int], needed_items:int) -> float:
    ivl, ivar, ival = loc
    bytes_in_item = type_classes[self._vls[ivl][ivar].typ].byte_size
    return sum(self._state.seqnums_inst[ivl][ivar][ival:ival+needed_items]) * bytes_in_item

  def _fn_isgood_r_initialized(self, loc: Tuple[int, int, int]) -> bool:
    if self._state.seqnums_inst[loc[0]][loc[1]][loc[2]] == 0:
      return False
    if self._fn_isgood_r != None:
      return self._fn_isgood_r(loc)
    return True # if there is no _fn_isgood set by user

  def _make_weights(self, cands, weight_type, reverse=False) -> List[Number]:
    if weight_type == 'natural':
      # use inverted (max_rate-rate) rates as weights
      max_rate = max(map(lambda c: c.rate, cands)) #todo: remove, use (cur_seqnum-1) ?
      if reverse:
        weights = [max_rate-c.rate for c in cands]
      else:
        weights = [c.rate for c in cands]
    elif (weight_type == 'hyperbola' or weight_type == 'linear'):
      # to replace rates with 1/x hyperbola, sort cands by rates, and use the index of that list as x, weight will be 1/x
      indices_rates = [(i, cands[i].rate) for i in range(len(cands))] # [(0, 343), (1, 441), (2, 994), (3, 239), ]
      sorted_indices_rates = sorted(indices_rates, reverse=reverse, key=lambda item: item[1]) # by rate
      prev_rate = None
      cur_weight_pos = 0
      for index, rate in sorted_indices_rates:
        if prev_rate != None:
          if rate != prev_rate:
            #  the rate has changed
            cur_weight_pos += 1
        # can contain same numbers (which means equal rate):
        cands[index].props['weight_pos'] = cur_weight_pos
        prev_rate = rate
      if weight_type == 'hyperbola':
        # 1/x formula for hyperbola
        weights = [round(1/(c.props['weight_pos']+1), 2) for c in cands]
      elif weight_type == 'linear':
        max_weight_pos = max(map(lambda c: c.props['weight_pos'], cands))
        weights = [round(max_weight_pos-c.props['weight_pos'], 2) for c in cands]
      else: raise
    else: raise
    return weights

  def _pick_rangelocation(self, cands, weights:list, requested_byte_count, requested_item_count):
    picked_cand = self._rng.choices(cands, weights=tuple(weights))[0]
    i_vl, i_var, i_val = picked_cand.loc
    range_loc = RangeLocation(i_vl, i_var, i_val,
                              requested_byte_count, requested_item_count,
                              self._vls[i_vl][i_var].typ)
    return range_loc

  def _write_commit_asterisks(self, rl:RangeLocation, chars):
    # clear current asterisks
    for i_vl in range(len(self._state.asterisks_inst)):
      for i_var in range(len(self._state.asterisks_inst[i_vl])):
        inst_values = self._state.asterisks_inst[i_vl][i_var]
        for i_val in range(len(inst_values)):
          self._state.asterisks_inst[i_vl][i_var][i_val] = ''
    # write new asterisks
    for i in range(rl.value_count()):
      self._state.asterisks_inst[rl.idx_vl][rl.idx_var][rl.idx_val + i] = chars

  def _increase_seqnums(self, rl:RangeLocation):
    # update seqnums and wipe wprobabs
    for i in range(rl.value_count()):
      self._state.seqnums_inst[rl.idx_vl][rl.idx_var][rl.idx_val+i] = self._state.cur_seqnum
      self._state.cur_seqnum += 1

  def _fix_if_all_zeroes(self, list_of_ints:List[int], fix_val=1):
    if set(list_of_ints) == {0}:
      for i in range(len(list_of_ints)):
        list_of_ints[i] = fix_val

  # helps to save weights on a dbg_ layer(s) to see them after picking (before commit)
  def _write_weights_to_layer(self, layer_name, cands, weights):
    for ncand in range(len(cands)):
      weight = weights[ncand]
      i_vl, i_var, i_val = cands[ncand].loc
      layer_inst, _is_hidden = self._state.layer_by_name(layer_name)
      layer_inst[i_vl][i_var][i_val] = weight

  def _fill_layer_with(self, layer_name, value):
    inst, _is_hidden = self._state.layer_by_name(layer_name)
    for vl in inst:
      for v in vl:
        for x in range(len(v)):
          v[x] = value

  def _write_dbg_candweights(self, cands, weights):
    self._fill_layer_with('dbg_candwei', None)
    self._write_weights_to_layer('dbg_candwei', cands, weights)

  def _commit_seqbased(self, use_purpose, rl):
    if use_purpose == UsePurpose.WRITE:
      self._increase_seqnums(rl)
      self._write_commit_asterisks(rl, 'WWW')
    elif use_purpose == UsePurpose.READ:
      self._write_commit_asterisks(rl, 'RRR')
    else: raise

#-----------------------------------------------------------------------

# A VRPicker with seqnum couting
# SeqbasedVRPicker allows to specify both read_weight_type and write_weight_type
class SeqbasedVRPicker(SeqbasedVRPickerBase):
  def __init__(self, vls, state:SeqbasedVRPickerState, sb_opts, rng):
    super().__init__(vls, state, sb_opts['read_weight_type'], sb_opts['write_weight_type'], rng)
    self.__sb_opts = sb_opts

  def pick_value_range(self, use_purpose, requested_byte_count, requested_item_count) -> RangeLocation:
    if use_purpose == UsePurpose.WRITE:
      fn_isgood = self._fn_isgood_w
      weight_type = self._write_weight_type
      reverse = False
    elif use_purpose == UsePurpose.READ:
      # IMPORTANT. Event if the cell is fn_isgood_r->True, we apply limitation: it should be initialized in our model (state inst)
      fn_isgood = self._fn_isgood_r_initialized
      weight_type = self._read_weight_type
      reverse = True
    else: raise
    cands = self._make_candidates(fn_isgood, self._fn_calcrate_seqnum_sum_mul_type_size,
                                  requested_byte_count, requested_item_count)
    assert(len(cands)!=0)
    weights = self._make_weights(cands, weight_type, reverse=reverse)
    self._fix_if_all_zeroes(weights)
    self._write_dbg_candweights(cands, weights)

    return self._pick_rangelocation(cands, weights, requested_byte_count, requested_item_count)

  def commit_picked_value_range(self, use_purpose, rl:RangeLocation):
    self._commit_seqbased(use_purpose, rl)


#---------------

# A VRPicker with seqnum couting and coasts support
# InsularVRPicker allows only to specify read_weight_type; write_weight_type is made hyperbola; without
#   this, the coasts multiplying produces very imbalanced values
class InsularVRPicker(SeqbasedVRPickerBase):
  def __init__(self, vls, state:InsularVRPickerState, ins_opts, rng):
    super().__init__(vls, state, ins_opts['read_weight_type'], 'hyperbola', rng)
    assert(ins_opts['coast_increase_type'] == 'proportional') # the only supported
    self.__ins_opts = ins_opts

  def pick_value_range(self, use_purpose, requested_byte_count, requested_item_count) -> RangeLocation:
    # do same things as our sibling class SeqbasedVRPicker does (not Base!), but take coasts into account (add weights)
    if use_purpose == UsePurpose.WRITE:
      fn_isgood = self._fn_isgood_w
      assert(self._write_weight_type == 'hyperbola')
      weight_type = self._write_weight_type
      reverse = False
    elif use_purpose == UsePurpose.READ:
      # IMPORTANT. Event if the cell is fn_isgood_r->True, we apply limitation: it should be initialized in our model (state inst)
      fn_isgood = self._fn_isgood_r_initialized
      weight_type = self._read_weight_type
      reverse = True
    else: raise
    cands = self._make_candidates(fn_isgood, self._fn_calcrate_seqnum_sum_mul_type_size,
                                  requested_byte_count, requested_item_count)
    assert(len(cands)!=0)
    weights = self._make_weights(cands, weight_type, reverse=reverse)
    self._fix_if_all_zeroes(weights)
    self._write_dbg_candweights(cands, weights)

    if use_purpose == UsePurpose.WRITE:
      self.__apply_coasts_to_weights(cands, weights)
    self.__write_dbg_final_candweights(cands, weights)

    return self._pick_rangelocation(cands, weights, requested_byte_count, requested_item_count)

  def __apply_coasts_to_weights(self, cands, weights):
    # calculate len of coasts and non-coasts of candidates
    #num_coast_cands = len([c for c in cands if c.props['coastness'] != None and c.props['coastness'] > 0])
    #num_noncoast_cands = len(cands) - num_coast_cands

    # first, need to determine coastness for all cands (we save it to _state.coastness_inst[] for every cand);
    # we can't begin generating weights until we find out the relation of the amounts of coast (when coastness>0) and non-coast (when coastness=0)
    self._fill_layer_with('coastness', None)
    for ncand in range(len(cands)):
      cand = cands[ncand]
      i_vl, i_var, i_val = cand.loc
      # see how does the beginning of the area much Rcoast and how does the end of the area much Lcoast
      # (e.g. vise versa: we need our R to match the existing L and we need our L to match the existing R)
      Lcoast = self._state.Rcoast_inst[i_vl][i_var][i_val]
      Rpos = i_val+cand.needed_items-1
      if Rpos < len(self._state.Rcoast_inst[i_vl][i_var]):
        Rcoast = self._state.Lcoast_inst[i_vl][i_var][Rpos]
      else:
        # R coast is out of range, count as it's 0
        Rcoast = 0
      # we're saving value in coastness_inst
      coastness = (0.5*Lcoast + 0.5*Rcoast) # coastness = 0..1
      self._state.coastness_inst[i_vl][i_var][i_val] = coastness

    # calculate the ratio of amount of `coast` and `non-coast` cands (cand.coastness>1 means cand is `coast`)
    _coastness_cands = [c for c in cands if self._state.coastness_inst[c.loc[0]][c.loc[1]][c.loc[2]] > 1]
    num_coast_cands = len(_coastness_cands)
    del _coastness_cands
    num_noncoast_cands = len(cands) - num_coast_cands
    coast_noncoast_ratio = num_noncoast_cands/(num_coast_cands+1)

    # generate weights using every cands' costness, and the relation of amount
    for ncand in range(len(cands)):
      c = cands[ncand]
      coastness = self._state.coastness_inst[c.loc[0]][c.loc[1]][c.loc[2]] # restore the saved value
      if self.__ins_opts['coast_increase_type'] == 'proportional':
        weights[ncand] += weights[ncand]*(coast_noncoast_ratio * coastness)
      else: raise

  def __write_dbg_final_candweights(self, cands, weights):
    self._fill_layer_with('dbg_final_candwei', None)
    self._write_weights_to_layer('dbg_final_candwei', cands, weights)


  def commit_picked_value_range(self, use_purpose, rl:RangeLocation):
    self._commit_seqbased(use_purpose, rl)
    if use_purpose == UsePurpose.WRITE:
      self.__update_coasts(rl)

  def __update_coasts(self, rl:RangeLocation):
    vl = self._vls[rl.idx_vl]
    value_count = len(vl[rl.idx_var].values)
    opts = self.__ins_opts

    coast_items_left, coast_items_right = opts['coast_items_left'], opts['coast_items_right']

    have_left = rl.idx_val # index = num of bytes we have before position
    have_right = value_count - (rl.idx_val+rl.value_count())
    commit_left = min(coast_items_left, have_left)
    commit_right = min(coast_items_right, have_right)
    outplaced_left = coast_items_left - commit_left
    outplaced_right = coast_items_right - commit_right

    # prepare progression arrays of hyperbolic sequences with needed length
    #ScaleCoastQuestion (now: don't scale)
    # Parabolic decrease (**2)
    l_coasts = [round(1/(((i+1)**2) ), 2) for i in range(coast_items_left-outplaced_left)]
    r_coasts = [round(1/(((i+1)**2) ), 2) for i in range(coast_items_right-outplaced_right)]
    # (over)write [normalized] wprobabs so they'll be used as new coasts
    for i in range(commit_left): # FROM FIRST-1, LEFTWARDS
      cur_val_idx = rl.idx_val - 1 - i
      cur_seqnum = self._state.seqnums_inst[rl.idx_vl][rl.idx_var][cur_val_idx]
      cur_lcoast = self._state.Lcoast_inst[rl.idx_vl][rl.idx_var][cur_val_idx]
      new_lcoast = l_coasts[i]
      if cur_seqnum == 0: #CoastIfNotAlreadyIsland
        if cur_lcoast < new_lcoast: # Another coast is higher, don't lower it
          self._state.Lcoast_inst[rl.idx_vl][rl.idx_var][cur_val_idx] = new_lcoast

    for i in range(commit_right): # FROM LAST+1, RIGHTWARDS
      cur_val_idx = rl.idx_val + rl.value_count() + i
      cur_seqnum = self._state.seqnums_inst[rl.idx_vl][rl.idx_var][cur_val_idx]
      cur_rcoast = self._state.Rcoast_inst[rl.idx_vl][rl.idx_var][cur_val_idx]
      new_rcoast = r_coasts[i]
      if cur_seqnum == 0: #CoastIfNotAlreadyIsland
        if cur_rcoast < new_rcoast:
          self._state.Rcoast_inst[rl.idx_vl][rl.idx_var][cur_val_idx] = new_rcoast

    # wipe Rcoast and Lcoast cells behind the commited portion
    for i in range(rl.value_count()):
      self._state.Lcoast_inst[rl.idx_vl][rl.idx_var][rl.idx_val+i] = 0
      self._state.Rcoast_inst[rl.idx_vl][rl.idx_var][rl.idx_val+i] = 0



