# Temporary program
import random
from typing import List
from collections import namedtuple
from pprint import pprint

from c2.sprayer.eg2.core.random_expression_generator import RandomExpressionGenerator, EGFlag
from c2.sprayer.vp.single_value_sequencer import SingleValueSequencer, SingleValueSequencerFromRandomPicker
from c2.sprayer.vp._random_var_picker import RandomVarPicker, PICK_FLAG_ALL
from c2.sprayer.gens.constgen import ConstGenRandom
from c2.sprayer.ccode.node import Node
from c2.sprayer.ccode.textualizer import Textualizer
from c2.sprayer.ccode.var import *


class _Test:
  def __init__(self, rng):
    self.__rng = rng
    self.__vl0 = [Var(VT.i8, [1, 2, 3, 4, 5, 6, 7, 8]), Var(VT.u16, [10, 20]), Var(VT.i32, [0, 15, 25, 39])]
    self.__vl1 = [Var(VT.u32, [55, 66, 77, 88, 99]), Var(VT.i8, [230, 240])]
    self.__vls = [self.__vl0, self.__vl1]

  def execute(self):
    for consts in [True, False]:
      for allow_compile_time_consts in [True, False]:
        #print(f'{consts=} {allow_compile_time_consts=} {allow_naked_consts=}')
        egflag = EGFlag(0)
        if consts:
          egflag |= EGFlag.CONSTS
        if allow_compile_time_consts:
          egflag |= EGFlag.ALLOW_COMPILE_TIME_CONSTS
        self.__test_egflag(500, egflag)
        print()

  def __test_egflag(self, count, egflag):
    print(f'--- generating 10 exprs with {egflag=}')
    exprs = self.__generate_exprs(count, egflag)

    vnt = VarNameTable(self.__vl0, self.__vl1)
    texer = Textualizer(lambda v: vnt.get_var_name(v))
    for expr in exprs:
      textexpr = texer.visit(expr)
      print(textexpr)

    self.__check_egflag_matching(exprs, egflag)


  def __generate_exprs(self, count, egflag):
    picker = RandomVarPicker(self.__vls, PICK_FLAG_ALL, self.__rng)
    svsequencer = SingleValueSequencerFromRandomPicker(picker)
    constgen = ConstGenRandom(self.__rng)
    randexprgen = RandomExpressionGenerator(3, self.__rng, egflag, svsequencer, constgen)
    pick_history = []
    ret_exprs = []
    for nexpr in range(count):
      expr = randexprgen.gen_random_expr(pick_history)
      ret_exprs.append(expr)
    assert(pick_history == [])
    return ret_exprs


  UseInfo = namedtuple('CheckResult', ['consts_used', 'compile_time_consts_used', 'naked_consts_used'])
  def __get_use_info(self, exprs:List[Node]) -> UseInfo:
    use_info = UseInfo()
    node_types = set(map(lambda x: x.nt, exprs))
    if node_types == {NT.NodeConst}: # only consts
      use_info.compile_time_consts_used = True
    if NT.NodeConst in node_types:
      use_info.consts_used = True

    for expr in exprs:
      if expr.nt == NT.NodeConst:
        use_info.consts_used = True


  def __check_egflag_matching(self, exprs:List[Node], egflag):
    for expr in exprs:
      pass


def egflag_matching_test():
  test = _Test(random.Random())
  test.execute()

if __name__ == '__main__':
  egflag_matching_test()



