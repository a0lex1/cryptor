import random

from c2.sprayer.eg2.egflag import *
from c2.sprayer.vp.single_value_sequencer import SingleValueSequencer
from c2.sprayer.gens.constgen import ConstGen
from c2.sprayer.ccode.node import Node


# Pure abstract
# maxlev is the level of node_op(s)
class ExprGen:
  def __init__(self, maxlev:int):
    self._maxlev = maxlev
  def get_maxlev(self):
    return self._maxlev
  def prefer_arridx_to_arrofs(self, enable:bool): raise NotImplementedError()
  def set_svsequencer(self, svsequencer:SingleValueSequencer=None): raise NotImplementedError()
  def set_constgen(self, constgen=None): raise NotImplementedError()
  def set_egflag(self, egflag:EGFlag): raise NotImplementedError()
  def get_egflag(self) -> EGFlag: raise NotImplementedError()
  def gen_expr(self, pick_history) -> Node: raise NotImplementedError()


# BASE for implementing  FACTORY-SUPPORTED  ExprGen(s). You CAN invent another custom ExprGen(s)
# not inheriting this class (you can inherit only ExprGen).
# |svsequencer| and |constgen| can be changed later, before call to gen_expr
# |opts| can NOT be changed (impl can use it to construct objects)
class ConfigurableExprGen(ExprGen):
  def __init__(self, maxlev, opts, rng, svsequencer:SingleValueSequencer=None, constgen=None):
    super().__init__(maxlev)
    self._opts = opts
    self._rng = rng
    self._create_objects(svsequencer, constgen)

  def _create_objects(self, svsequencer, constgen):
    raise NotImplementedError()

