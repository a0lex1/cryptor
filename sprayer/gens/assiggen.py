import random

from c2.sprayer.eg2.expr_gen import ExprGen
from c2.sprayer.vp.single_value_sequencer import SingleValueSequencer

from c2.sprayer.ccode.evaluator import Evaluator
from c2.sprayer.ccode.node import *

#TODO: FLAGS

class AssigGen:
  # TODO: disable repeated same assigs (log previous)
  # NOTE: add_comment enabled Evaluator-ion of R
  def __init__(self, l_svseq:SingleValueSequencer, r_exprgen:ExprGen, rng,
               with_arrofs:bool, enable_samevar=True, add_comment=False):
    self.l_svseq = l_svseq
    self.r_exprgen = r_exprgen
    self.with_arrofs = with_arrofs
    self._rng = rng
    self.enable_samevar = enable_samevar
    self.add_comment = add_comment

    self._selfassig_replace_gen = None

  # you can use ConstGen for example
  def disable_selfassig(self, gen:ExprGen):
    self._selfassig_replace_gen = gen

  def gen_assig(self, pick_history) -> Node:
    # make L and R
    lnode = self._pick_lvalue('=', pick_history) # NT.Var or NT.ArrOfs
    rnode = self.r_exprgen.gen_expr(pick_history)
    if self._selfassig_replace_gen != None:
      if self._is_same(lnode, rnode):
        rnode = self._selfassig_replace_gen.gen_expr(pick_history)
    # glue L and R as op
    comment = ''
    if self.add_comment:
      ev = Evaluator()
      #mi_old = ev.visit(lnode)
      mi = ev.visit(rnode)
      assert(issubclass(type(mi), MachineInteger))
      comment += f'// ASSIG -> {mi.value:x}'
    return node_assig('=', lnode, rnode, comment)

  def _pick_lvalue(self, aop, pick_history) -> Node:
    v, arridx = self.l_svseq.pick_var_ind(pick_history)
    return node_var_or_arrofs(v, arridx)

  def _is_same(self, node_a, node_b):
    if node_a.typ == NT.Const and node_b.typ == NT.Const:
      # Compare consts
      if node_a.props['integer'] == node_b.props['integer']:
        return True

    elif node_a.typ == NT.Var and node_b.typ == NT.Var:
      # Compare vars
      if node_a.props['v'] == node_b.props['v']:
        return True

    elif node_a.typ == NT.ArrOfs and node_b.typ == NT.ArrOfs:
      # Compare ArrOfs
      var_node_a, byteofs_node_a = node_a.children
      var_node_b, byteofs_node_b = node_b.children
      if var_node_a.props['v'] == var_node_b.props['v']:
        assert(byteofs_node_a.typ == NT.Const and byteofs_node_b.typ == NT.Const)
        return self._is_same(byteofs_node_a, byteofs_node_b) # recursion

    return False



