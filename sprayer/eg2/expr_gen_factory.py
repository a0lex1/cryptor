import random
from dataclasses import dataclass

from c2.sprayer.eg2.expr_gen import ConfigurableExprGen
from c2.sprayer.eg2.expr_gen_random import ExprGenRandom
from c2.sprayer.eg2.expr_gen_bijective import ExprGenBijective
from c2.sprayer.gens.constgen import ConstGen
from c2.sprayer.vp.single_value_sequencer import SingleValueSequencer

EG_RANDOM_NAME = 'random'
EG_BIJECTIVE_NAME = 'bijective'


# The factory should support only ExprGen(s) derived from ConfigurableExprGen
@dataclass
class ExprGenFactory:
  __eg_name: str

  def create_expr_gen(self, maxlev:int, opts, rng, svsequencer=None, constgen=None) -> ConfigurableExprGen:
    args = [maxlev, opts,  rng, svsequencer, constgen]
    if self.__eg_name == EG_RANDOM_NAME:
      return ExprGenRandom(*args)
    elif self.__eg_name == EG_BIJECTIVE_NAME:
      return ExprGenBijective(*args)
    else: raise RuntimeError()


