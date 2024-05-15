from c2.sprayer.eg2.expr_gen import ConfigurableExprGen
from c2.sprayer.eg2.egflag import *
from c2.sprayer.eg2.core.random_expression_generator import RandomExpressionGenerator, RandomExpressionGeneratorFuncs


# |opts| [that comes from UNISCHEMA] are NOT validated. Should they be?
class ExprGenRandom(ConfigurableExprGen):
  def _create_objects(self, svsequencer, constgen):
    self.__core_eg = RandomExpressionGenerator(self._maxlev, self._rng)
    self.__core_eg.svsequencer = svsequencer
    self.__core_eg.constgen = constgen
    #self.__core_eg.egflag =  #NotUsingEGFlag

  def prefer_arridx_to_arrofs(self, enable):
    self.__core_eg.prefer_arridx_to_arrofs(enable)

  def set_svsequencer(self, svsequencer=None):
    self.__core_eg.svsequencer = svsequencer

  def set_constgen(self, constgen=None):
    self.__core_eg.constgen = constgen

  def set_egflag(self, egflag:EGFlag):
    self.__core_eg.egflag = egflag

  def get_egflag(self) -> EGFlag:
    return self.__core_eg.egflag

  def gen_expr(self, pick_history):
    return self.__core_eg.gen_random_expr(pick_history)






