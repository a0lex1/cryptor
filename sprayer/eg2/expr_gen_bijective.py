from c2.sprayer.eg2.expr_gen import ConfigurableExprGen
from c2.sprayer.eg2.egflag import *
from c2.sprayer.eg2.core.bijective_expression_generator import BijectiveExpressionGenerator

from c2.sprayer.eg2._sticky_random_function import StickyRandomFunction


# |opts| [that comes from UNISCHEMA] are NOT validated. Should they be?
class ExprGenBijective(ConfigurableExprGen):
  def _create_objects(self, svsequencer, constgen):
    opts = self._opts
    self.__bijexprgen = BijectiveExpressionGenerator(
      self._maxlev, opts['core_opts'], self._rng, svsequencer, constgen)

    if opts['funct'] == 'rand':
      assert(opts['rand']['reserved'] == 0)
      self.__f = lambda: self._rng.randint(0, self.__bijexprgen.max_n()) ## Our function

    elif opts['funct'] == 'sticky':

      # calculate max_change from %
      assert(0 <= opts['sticky']['max_change_percent'] <= 100)
      max_change = (self.__bijexprgen.max_n() * opts['sticky']['max_change_percent']) // 100

      self.__sticky = StickyRandomFunction(
        self.__bijexprgen.max_n(),
        opts['sticky']['probab_change_percent'],
        max_change,
        self._rng)
      self.__f = self.__sticky.f ## Our function

    else:
      raise RuntimeError(f'unknown {opts["funct"]=}')

  def prefer_arridx_to_arrofs(self, enable):
    self.__bijexprgen.prefer_arridx_to_arrofs(enable)

  def set_svsequencer(self, svsequencer=None):
    self.__bijexprgen.set_svsequencer(svsequencer)

  def set_constgen(self, constgen=None):
    self.__bijexprgen.set_constgen(constgen)

  def set_egflag(self, egflag:EGFlag):
    self.__bijexprgen.set_egflag(egflag)

  def get_egflag(self) -> EGFlag:
    return self.__bijexprgen.get_egflag(egflag)

  def gen_expr(self, pick_history):
    # Generate N with functi and pass it to bijective exprgen
    N = self.__f()
    assert(0 <= N <= self.__bijexprgen.max_n())
    return self.__bijexprgen.gen_bijective_expr(N, pick_history)

