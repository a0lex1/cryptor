import random
from typing import Tuple

from c2.sprayer.eg2.core._bijective_filler import BijectiveFiller
from c2.sprayer.eg2.egflag import *
from c2.sprayer.vp.single_value_sequencer import SingleValueSequencer
from c2.sprayer.gens.constgen import ConstGen
from c2.sprayer.misc.bin_tree_from_n import BinTreeFromN
from c2.sprayer.ccode.var import *
from c2.sprayer.ccode.node import *


# A core bijective generator
class BijectiveExpressionGenerator:
  def __init__(self, maxlev, bijectivecore_opts, rng, svsequencer=None, constgen=None):
    self.__maxlev = maxlev
    self.__bijectivecore_opts = bijectivecore_opts
    self.__rng = rng
    opts = self.__bijectivecore_opts
    self.__create_and_configure_filler(svsequencer, constgen)
    self.__filler.set_gravitation(opts['term_gravitate_right'], opts['op_gravitate_outer'])
    self.__filler.set_prerotate(opts['prerotate_bits_term'], opts['prerotate_bits_op'])

  def prefer_arridx_to_arrofs(self, enable:bool):
    assert(self.__filler != None)
    self.__filler.prefer_arridx_to_arrofs(enable)

  def set_svsequencer(self, svsequencer): #required
    # Returns (v, idx)
    def fn_pickvar(pick_hist) -> Tuple[Var, int]:
      return svsequencer.pick_var_ind(pick_hist)
    self.__filler.set_fn_pickvar(fn_pickvar if svsequencer != None else None)

  def set_constgen(self, constgen):
    self.__filler.set_constgen(constgen)

  def set_egflag(self, egflag):
    self.__filler.set_egflag(egflag)

  def get_egflag(self):
    self.__filler.get_egflag()

  def bitcount(self): return self.__treegen.bitcount
  def max_n(self): return self.__treegen.max_n

  def __create_and_configure_filler(self, svsequencer, constgen):
    # Adapt ccode.Node as tree type for BinTreeFromN through lambdas
    def _fn_makeleaf(children: list):
      return Node(children=children)
    def _fn_setchildren(node, children:list):
      node.children = children
    self.__treegen = BinTreeFromN(self.__maxlev, _fn_makeleaf, _fn_setchildren)
    # you can set_gravitation, etc. to filler yourself, it's public
    self.__filler = BijectiveFiller(self.__treegen.bitcount, root_node=None)
    self.set_svsequencer(svsequencer)
    self.set_constgen(constgen)
    self.set_egflag(EG_FLAG_DEFAULT)


  def gen_bijective_expr(self, N:int, pick_history) -> Node:
    # tree and fill CAN use different Ns
    Ntree = N
    Nfill = N
    tree = self.__treegen.tree(Ntree)
    self.__filler.root_node = tree
    self.__filler.fill(Nfill, pick_history)
    return tree


### TEST CODE ###

import os
from c2.sprayer.vp._random_var_picker import RandomVarPicker, PICK_FLAG_ALL
from c2.sprayer.vp.single_value_sequencer import SingleValueSequencerFromRandomPicker
from c2.sprayer.gens.constgen import ConstGenRandom
from c2.sprayer.ccode.textualizer import Textualizer
from c2.infra.unischema import unischema_load

_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/../../..'

def demo_bijective_expression_generator():
  vl0 = [Var(VT.i8, [1,2,3,4,5,6,7,8]), Var(VT.u16, [10, 20]), Var(VT.i32, [0, 15, 25, 39])]
  vl1 = [Var(VT.u32, [55, 66, 77, 88, 99]), Var(VT.i8, [230, 240])]
  vls = [vl0, vl1]
  rng = random.Random()
  p = RandomVarPicker(vls, PICK_FLAG_ALL, rng)
  s = SingleValueSequencerFromRandomPicker(p)
  u = unischema_load(f'{_sd}/bijectivecore_opts.UNISCHEMA', _inclroot)
  bijectivecore_opts = u.make_default_config()
  r = BijectiveExpressionGenerator(4, bijectivecore_opts, rng, s, ConstGenRandom(rng))
  pick_history = []
  e = r.gen_bijective_expr(r.max_n()//2, pick_history)   # how to know max_n.. maybe normalize to 1 ???
  vnt = VarNameTable(vl0, vl1, [])
  texer = Textualizer(lambda v: vnt.get_var_name(v))
  print(texer.visit(e))


if __name__ == '__main__':
  demo_bijective_expression_generator()

