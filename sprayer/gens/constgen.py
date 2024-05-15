import random

from c2.sprayer.ccode.node import Node, node_const


class ConstGen:
  pass


#PossibleImprovements.
# gens only NT.Const Node-s
class ConstGenRandom:
  def __init__(self, rng):
    self._rng = rng

    self.frm = 0
    self.to = 0xffffffff

  def gen_const(self) -> Node:
    return node_const(self._rng.randint(self.frm, self.to))


