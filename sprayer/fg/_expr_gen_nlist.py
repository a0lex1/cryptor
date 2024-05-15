from typing import List

from c2.sprayer.eg2.expr_gen import ExprGen
from c2.sprayer.eg2.egflag import *
from c2.sprayer.eg2.core.bijective_expression_generator import BijectiveExpressionGenerator

#TODO: test for this shit

# Not a factory-supported ExprGen, e.g. this class is derived from ExprGen, not from ConfigurableExprGen.
# We don't need ExprGenBijective's features, we just need to aggregate a "core" class BijectiveExpressionGenerator.
# Will raise if nlist is exhausted.
class ExprGenNList(ExprGen):
  def __init__(self, bijective_eg:BijectiveExpressionGenerator):
    self.bijective_eg = bijective_eg

  def set(self, nlist: List[int]):  # rename
    self.__nlist = nlist
    self.__cur_idx = 0

  # ExprGen impl

  def prefer_arridx_to_arrofs(self, enable:bool):
    self.bijective_eg.prefer_arridx_to_arrofs(enable)

  def set_svsequencer(self, svsequencer=None):
    self.bijective_eg.svsequencer = svsequencer

  def set_constgen(self, constgen=None):
    self.bijective_eg.constgen = constgen

  def set_egflag(self, egflag:EGFlag):
    self.bijective_eg.set_egflag(egflag)

  def get_egflag(self) -> EGFlag:
    return self.bijective_eg.get_egflag()

  def gen_expr(self, pick_history):
    if self.__cur_idx == len(self.__nlist):
      raise RuntimeError(f'nlist is exhausted ({self.__cur_idx=})')
    N = self.__nlist[self.__cur_idx]
    self.__cur_idx += 1
    return self.bijective_eg.gen_bijective_expr(N, pick_history)

  ''' #Not used anywhere
  # |count| elems from 0 to max_n
  def set_increasing_nlist(self, count: int):
    coeff = self.max_n() / count
    self.set([round(i * coeff) for i in range(count)])'''


