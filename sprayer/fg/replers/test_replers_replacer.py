import re
from typing import List, Tuple

from c2.sprayer.fg.replers.replers_replacer import *
from c2.sprayer.fg.replers.exceptions import *
from c2.sprayer.fg.replers.itempick_module import ItempickModule
from c2.sprayer.fg.replers.bytepick_module import BytepickModule
from c2.sprayer.vp.vrpicker import *
from c2.sprayer.vp.stock import STOCK_diagonalvls_vls
from c2.sprayer.vp.diagonal_vrpicker import DiagonalVRPicker
from c2.sprayer.ccode.var import *


def _test_with(num_slots, input_text, modules:list, expected_exception_type=None, fn_checkresult=None):
  replacer = ReplersReplacer(num_slots, modules)
  try:
    pick_history = []
    result = replacer.replace_in(input_text, pick_history)
    assert(len(pick_history) == 0)
  except Exception as e:
    if expected_exception_type == None:
      print('UNEXPECTED EXCEPTION', e)
      raise
    if type(e) != expected_exception_type:
      print('BAD TYPE OF EXPECTED EXCEPTION', e)
      raise
    print('OK, expected exception', e)
    return
  if expected_exception_type != None:
    raise RuntimeError('EXPECTED EXCEPTION NOT OCURRED')
  if fn_checkresult != None:
    if not fn_checkresult(result):
      raise RuntimeError('fn_checkresult returned False')




def test_replers_replacer_basic():
  vrpicker = DiagonalVRPicker(STOCK_diagonalvls_vls)
  mk_itempickmod = lambda: ItempickModule(STOCK_diagonalvls_vls, vrpicker)
  # without modules
  ns = 5
  _test_with(ns, '', [], None, lambda r: r == '')
  _test_with(ns, 'abc', [], None, lambda r: r == 'abc')
  # with module(s)
  _test_with(ns, '', [mk_itempickmod()], None, lambda r: r == '')
  _test_with(ns, 'abc', [mk_itempickmod()], None, lambda r: r == 'abc')

### TODO: byte-level _f(s)
def test_replers_replacer_vars():
  vrpicker = DiagonalVRPicker(STOCK_diagonalvls_vls)
  mk_itempickmod = lambda: ItempickModule(STOCK_diagonalvls_vls, vrpicker)
  ns = 5
  # every test_* can have its own ResultChecker for the convenience
  class ResultChecker:
    def __init__(self, min_bytesizes, re_pat=r'!\$\d+\[(.+?)\]!\$\d+\[(.+?)\]!\$\d+\[(.+?)\]!', samevar=False):
      self.__min_bytesizes = min_bytesizes
      self.__re_pat = re_pat
      self.__samevar = samevar
    def f(self, r):
      if type(r)!=NameBindString:
        return False
      if not re.match(self.__re_pat, r.format_string):
        return False
      if not (len(r.argument_list)==3 and type(r.argument_list[0])==Var and type(r.argument_list[1])==Var and type(r.argument_list[2])==Var):
        return False
      #TODO: check min_bytesizes
      if self.__min_bytesizes != None:
        assert(len(self.__min_bytesizes) == len(r.argument_list))
      if self.__samevar:
        # check all same var
        for i in range(len(r.argument_list)):
          if not r.argument_list[0] is r.argument_list[i]:
            raise RuntimeError(f'not all objects in r.argument_list are same, first at index {i}')
      return True
  _test_with(ns, '!_fin(i8)!_fout(u8)!_finout(i32)!', [], None, lambda r: r=='!_fin(i8)!_fout(u8)!_finout(i32)!')
  _test_with(ns, '!_fin(i8)!_fout(u8)!_finout(i32)!', [mk_itempickmod()], None, ResultChecker([1, 2, 4]).f)
  # without `!`
  _test_with(ns, '_fin(i8) _fout(u8) _finout(i32)!', [mk_itempickmod()], None, ResultChecker([1, 2, 4], r'\$\d+\[(.+?)\] \$\d+\[(.+?)\] \$\d+\[(.+?)\]!').f)
  # non-default (non-1) item counts
  _test_with(ns, '!_fin(i8, 2)!_fout(u8, 3)!_finout(i32, 5)!', [mk_itempickmod()], None, ResultChecker([2, 3, 20]).f)
  # remove spaces between args
  _test_with(ns, '!_fin(i8,2)!_fout(u8,3)!_finout(i32,5)!', [mk_itempickmod()], None, ResultChecker([2, 3, 20]).f)
  # now add \n
  _test_with(ns, '\n_fin(i8,2)\n_fout(u8,3)\n_finout(i32,5)\n', [mk_itempickmod()], None, ResultChecker([2, 3, 20], r'\n\$\d+\[(.+?)\]\n\$\d+\[(.+?)\]\n\$\d+\[(.+?)\]\n').f)
  # test slots
  _test_with(ns, '!_fin0(i8)!_fin0(i8)!_fin0(i8)!', [mk_itempickmod()], BadSlotIdError)
  _test_with(ns, '!_fin6(i8)!_fin6(i8)!_fin6(i8)!', [mk_itempickmod()], BadSlotIdError)

  _test_with(ns, '!_fin1(i8)!_fin1(i8)!_fin1(i8)!', [mk_itempickmod()], None, ResultChecker([1,1,1],samevar=True).f)
  _test_with(ns, '!_fin3(i8)!_fin3(i8)!_fin3(i8)!', [mk_itempickmod()], None, ResultChecker([1,1,1],samevar=True).f)
  _test_with(ns, '!_finout5(u16,3)!_finout5(i16,7)!_finout5(u32,9)!', [mk_itempickmod()], None, ResultChecker([6, 14, 36]).f)
  _test_with(ns, '!_finout5(u16,3)!_finout5(i16,7)!_finout5(u32,9)!', [mk_itempickmod()], None, ResultChecker([6, 14, 36]).f)


def test_replers_replacer():
  test_replers_replacer_basic()
  test_replers_replacer_vars()

if __name__ == '__main__':
  test_replers_replacer()



