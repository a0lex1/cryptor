from enum import Enum, auto

from c2.sprayer.ccode.machine_int import *


#from .machine_float import *
class FLOAT:
  pass

class DOUBLE:
  pass

class VT(Enum):
  u8 = auto()
  u16 = auto()
  u32 = auto()
  u64 = auto()
  i8 = auto()
  i16 = auto()
  i32 = auto()
  i64 = auto()
  #String?
  floa = auto()
  doub = auto()
  pvoid = auto()

type_names = {c: c.name for c in VT}
type_name2class = {c.name: c for c in VT}

integer_var_types = [VT.u8, VT.u16, VT.u32, VT.u64, VT.i8, VT.i16, VT.i32, VT.i64]
floating_point_var_types = [VT.floa, VT.doub]

all_var_types = integer_var_types +\
                floating_point_var_types +\
                [VT.pvoid]

type_classes = {VT.u8: UINT8, VT.u16: UINT16, VT.u32: UINT32, VT.u64: UINT64,
                VT.i8: INT8, VT.i16: INT16, VT.i32: INT32, VT.i64: INT64,
                VT.floa: FLOAT, VT.doub: DOUBLE,
                VT.pvoid: None }
integer_var_classes = [type_classes[vt] for vt in integer_var_types]

#type_class2enum = { type_classes[en]: en for en in type_classes.keys() }

# a base class for markers
class ValueMarker:
  pass

# User can extend this set with your own markers
class ValueUninitialized(ValueMarker):
  pass
class ValueUnknown(ValueMarker):
  pass
class NullPtr(ValueMarker):
  pass

class Var:
  # values is [ ValueUninitialized(), MachineInteger(), ValueUnknown, MachineInteger() ]
  # values is [ ValueUninitialized() ]
  # values is []
  #
  # ###values is [ ValueUnknown(), ValueUnknown(), r'Raw C String!\n' ]              # TODO
  #
  # values is [ MachineFloat(), MachineDouble(), MachineDouble(), MachineDouble() ]  # VT.floa VT.doub
  # values is [ NullPtr, NullPtr, Var(VT.i16, [0]), NullPtr, NullPtr ]               # VT.pvoid
  #
  # +Var().is_const() TODO

  def __init__(self, typ:VT, values=None):
    if values == None:
      values = []
    self.typ = typ
    self.values = values
    if values:
      for val in self.values:
        if issubclass(type(val), ValueMarker):
          pass
        elif type(val) == float:
          pass # IS THIS POSSIBLE????????????????????????????????????????
        elif type(val) == int:
          pass #???????????????????????
        else:
          raise RuntimeError()
    self.cmnt = None

  # sugar
  def make_class_obj(self, value):
    return type_classes[self.typ](value)

  def valcount(self):
    return len(self.values)
  def is_elem_known(self, idx):
    return type(self.values[idx]) != ValueUnknown
  def is_elem_init(self, idx): # initialized implies known
    #return len(self.values) != 0 if self.is_known() else False
    return type(self.values[idx]) == int
  def is_array(self):
    return self.valcount() > 1
  def count_values(self, value_types:list):
    return len([val for val in self.values if type(val) in value_types])
  def num_knowns(self):
    return self.count_values([int])
  def num_uninits(self):
    return self.count_values([ValueUninitialized])
  def num_unknowns(self):
    return self.count_values([ValueUnknown])


# prints TYPE VAR (adds [] if array)
def make_var_decl(v, varname):
  bracks = f'[{v.valcount()}]' if v.is_array() else ''  # add [%d] for arrays
  return f'{type_names[v.typ]} {varname}{bracks}'

# declaration printers
class ValPrintType(Enum):
  WITHOUT_VALUE = 0
  VALUE_AS_COMMENT = 1
  WITH_VALUE = 2


def decl_arglist(vl, varnames):
  # IMPROV: args can have initializers in C++, no need to disable it here
  l = _decl_list(vl, varnames, True, 0, ValPrintType.WITHOUT_VALUE, '')
  #ret = '\n'.join(l)
  return l


# override_values -> every var's value list for single var list -> [ [1,2,3], [0x33, 0x22] ]
def decl_varlist(vl, varnames, tabs=0, valprn=ValPrintType.VALUE_AS_COMMENT, line_prefix='',
                 override_values:list=None):
  l = _decl_list(vl, varnames, False, tabs, valprn, line_prefix, override_values)
  #ret = '\n'.join(l)
  return l


def _decl_list(vl, varnames, func_decl, tabs, valprn, line_prefix, override_values=None):
  assert(not func_decl or (tabs == 0 and valprn == ValPrintType.WITHOUT_VALUE and line_prefix == ''))
  tbs = '  '*tabs
  retlines = []
  buf = ''
  for varidx in range(len(vl)):
    v = vl[varidx]
    comment = ''
    valsstr = ''
    d = make_var_decl(v, varnames[v])
    is_last = varidx >= len(vl)-1
    if func_decl:
      buf += d
      if not is_last:
        buf += ', '
    else:
      extrastr = ';'
      if valprn != ValPrintType.WITHOUT_VALUE:
        # add values to comment or initialization string
        assert (not func_decl)
        assert (len(v.values) > 0)
        for validx in range(len(v.values)):

          if override_values != None:
            assert(type(override_values) == list)
            val = override_values[varidx][validx]
          else:
            val = v.values[validx]

          tn = type_names[v.typ]
          if type(val) == int:
            valsstr += f'({tn})0x{val:x}'
          elif type(val) == ValueUninitialized:
            valsstr += f'({tn})UNINIT'
          elif type(val) == ValueUnknown:
            valsstr += f'({tn})UNK'
          else:
            raise RuntimeError('bad value type')
          if validx < len(v.values) - 1:
            valsstr += ', '
        if valprn == ValPrintType.VALUE_AS_COMMENT:
          extrastr = f'; // values=[ {valsstr} ]'
        else:
          extrastr = f' = {{ {valsstr} }};'
      if v.cmnt != None:
        extrastr += ' '+v.cmnt
      retlines.append(tbs + line_prefix + d + extrastr)
  if func_decl:
    return [buf]
  else:
    return retlines


class VarNameTable:
  def __init__(self, vl_g=None, vl_a=None, vl_l=None, fixed_var_names=None):
    self.vl_g, self.vl_a, self.vl_l = vl_g, vl_a, vl_l
    if fixed_var_names == None:
      fixed_var_names = {}
    self.fixed_var_names = fixed_var_names
    # public, the result of update()ing:
    self.names_g, self.names_a, self.names_l =  {}, {}, {}
    self.update()

  def get_var_name(self, v):
    if self.vl_g and v in self.vl_g:
      return self.names_g[v]
    elif self.vl_a and v in self.vl_a:
      return self.names_a[v]
    elif self.vl_l and v in self.vl_l:
      return self.names_l[v]
    raise RuntimeError('var name is not in glob/arg/loc dicts or not .update()')

  def update(self):
    # { Var(), 'varname' }
    if self.vl_g:
      self._add_varlist(self.vl_g, 'g_', self.names_g)
    if self.vl_a:
      self._add_varlist(self.vl_a, 'a', self.names_a)
    if self.vl_l:
      self._add_varlist(self.vl_l, '', self.names_l)

  def _add_varlist(self, vl, prefix, vardict):
    vlcount = len(vl)
    for i in range(vlcount):
      v = vl[i]
      if self.fixed_var_names != None and v in self.fixed_var_names:
        varname = self.fixed_var_names[v]
      else:
        varname = self._make_var_name(v, i, prefix)
      vardict[v] = varname

  def _make_var_name(self, v, varid:int, prefix):
    type_prefixes = {VT.u8: 'b', VT.u16: 'w', VT.u32: 'dw', VT.u64: 'qw',
                     VT.i8: 'sb', VT.i16: 'sw', VT.i32: 'sdw', VT.i64: 'sqw',
                     VT.floa: 'f', VT.doub: 'doub',
                     VT.pvoid: 'pv'}
    return f'{prefix}{type_prefixes[v.typ]}{varid}'

