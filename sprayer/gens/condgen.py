import random
from typing import Callable

from c2.sprayer.eg2.expr_gen import ExprGen
from c2.sprayer.misc._ensure_objvars_set import ensure_objvars_set
from c2.sprayer.ccode.evaluator import Evaluator
from c2.sprayer.ccode.machine_int import *
from c2.sprayer.ccode.textualizer import Textualizer
from c2.sprayer.ccode.node import Node
from c2.sprayer.ccode.node import NT, node_op, node_relop, node_const


# all fields public.. maybe do something
class CondGen:
  class Funcs:
    def __init__(self):
      self.fn_prob_greater = None
      self.fn_prob_less = None
      self.fn_prob_greater_eq = None
      self.fn_prob_less_eq = None
      self.fn_prob_eq = None
      self.fn_prob_neq = None
      #self.last_action = None
      # TODO: logops ||, &&, !,

    def ensure_all_set(self):
      ensure_objvars_set(self, 'fn_')

  def __init__(self, funcs, exprgen_a:ExprGen, exprgen_b:ExprGen, constgen, rng,
               evaler=None, autocheck_enabled=False):
    funcs.ensure_all_set()
    self.funcs = funcs
    self.exprgen_a = exprgen_a
    self.exprgen_b = exprgen_b
    self.constgen = constgen
    if evaler == None:
      evaler = Evaluator()
    self.evaler = evaler
    self._rng = rng
    self._autocheck_enabled = autocheck_enabled
    self._enable_compile_time_consts = False
    self.__logfn = lambda msg: None
    self.set_thruthness(None)

  def set_logfn(self, logfn:Callable[[str], None]):
    self.__logfn = logfn

  def compile_time_consts(self, enable:bool):
    self._enable_compile_time_consts = enable

  # call set_thruthness, then gen_expr
  # thruthness -> True|False|None
  def set_thruthness(self, thruthness):
    assert(type(thruthness) == bool or thruthness==None)
    self.thruthness = thruthness

  def gen_cond(self, pick_history) -> Node:
    assert(type(self.thruthness) == bool or self.thruthness==None)
    # == and != must be 50%/50% probability
    #code = random.choice(relop_codes)
    f = self.funcs
    reldict = {}
    #reldict['>'] = f.fn_prob_greater()
    #reldict['<'] = f.fn_prob_less()
    #reldict['>='] = f.fn_prob_greater_eq()
    #reldict['<='] = f.fn_prob_less_eq()
    reldict['=='] = f.fn_prob_eq()
    reldict['!='] = f.fn_prob_neq()

    code = self._rng.choices([a for a in reldict.keys()], weights=tuple(reldict[a] for a in reldict.keys()), k=1)[0]

    # Generate A and B
    A = self.exprgen_a.gen_expr(pick_history)

    allow_consts_in_b = self._enable_compile_time_consts or A.typ != NT.Const

    old_B_eflags = self.exprgen_b.get_egflag()
    if not allow_consts_in_b:
      self.exprgen_b._egflag &= ~EGFlag.CONSTS

    B = self.exprgen_b.gen_expr(pick_history)

    self.exprgen_b._egflag = old_B_eflags

    # Create node
    relop_node = node_relop(code, A, B)

    if self.thruthness != None:
      if code == '==' or code == '!=':  # need eq or !eq
        relop_node = self._create_equity(self.thruthness, relop_node)
      else:
        # > < >= <=
        raise RuntimeError('TODO')

    return relop_node


  def _create_equity(self, thruthness:bool, relop_node):
    # TODO: A and B can be the same var (a == a) or even const == const
    A, B, code = relop_node.children[0], relop_node.children[1], relop_node.props['op_code']
    assert (code == '==' or code == '!=')
    evA = self.evaler.visit(A)
    evB = self.evaler.visit(B)
    use_old_method = True
    if use_old_method:
      # old method as it was
      defconv_typeA = INT32 if evA.byte_size < 4 else type(evA)
      defconv_typeB = INT32 if evB.byte_size < 4 else type(evB)
    else:
      # new method, 6 dec 2023
      biggest_type = type(evA) if evA.byte_size > evB.byte_size else type(evB)
      defconv_typeA = INT32 if biggest_type.byte_size < 4 else biggest_type
      defconv_typeB = INT32 if biggest_type.byte_size < 4 else biggest_type
    evA = defconv_typeA(0).assign(evA)
    evB = defconv_typeB(0).assign(evB)
    prntypes = lambda: f'type A: {type(evA).__name__}->{defconv_typeA.__name__}, type B: {type(evB).__name__}->{defconv_typeB.__name__}'
    if thruthness == True:
      if code == '==':
        if evA.value == evB.value:
          logstr = f'want True ==, now ==, ok ({prntypes()})'
        else:
          A, B = self._equate(A, B, evA, evB)
          logstr = f'want True ==, now !=, equated ({prntypes()})'
      else:
        # code: !=
        if evA.value != evB.value:
          logstr = f'want True !=, now !=, ok ({prntypes()})'
        else:
          A, B = self._unequate(A, B, evA, evB)
          logstr = f'want True !=, now ==, unequated ({prntypes()})'
        pass
    elif thruthness == False:
      # user wants FALSE condition
      if code == '!=':
        if evA.value == evB.value:
          logstr = f'want False !=, now ==, ok ({prntypes()})'
        else:
          A, B = self._equate(A, B, evA, evB)
          logstr = f'want False !=, now !=, equated ({prntypes()})'
      else:
        # code: ==
        if evA.value != evB.value:
          logstr = f'want False ==, now !=, ok ({prntypes()})'
        else:
          A, B = self._unequate(A, B, evA, evB)
          logstr = f'want False ==, now ==, unequated ({prntypes()})'
        pass
    else:
      raise RuntimeError('to get unpredicted result generation behaviour, use disable_calculations')


    relop_node.children[0], relop_node.children[1] = A, B

    self.__logfn('_create_equity: '+logstr)

    if self._autocheck_enabled:
      self._autocheck(relop_node, expect_true=self.thruthness)

    return relop_node


  def _autocheck(self, relop_node, expect_true:bool):
    evaler = Evaluator()
    m_int = evaler.visit(relop_node)
    if expect_true:
      expect = 1
    else:
      expect = 0
    if m_int.value != expect:
      #_text = Textualizer().visit(relop_node)
      raise RuntimeError(f'condgen autocheck: unexpected boolean result\nrelop_node ->\n{_text}')


  def _equate(self, A, B, evA, evB):
    # evA, evB are just cached values (to eliminate re-evaluating A and B)
    assert(evA.value != evB.value)
    # TODO: not only +, other ops, a lot of them...
    bigger_int_class = type(evA) if type(evA).byte_size > type(evB).byte_size else type(evB)
    # example (int) + (int64), substract in bigger type register, sign is important
    is64bit = (bigger_int_class(0).byte_size == 8)
    c = node_const(bigger_int_class(0).assign(evA).sub(evB).value, is64bit)
    self.__logfn(f'_equate: evA={evA.value:x}, evB={evB.value:x},'
                 f' will add c={c.props["integer"]:x} (64-bit: {c.props["is64bit"]}) to B')
    B = node_op('+', B, c)
    return A, B

  def _unequate(self, A, B, evA, evB):
    # evA, evB are just cached values (to eliminate re-evaluating A and B)
    assert(evA.value == evB.value)
    # TODO: not only +, other ops, a lot of them...
    # TODO: 64-bit consts
    # use expr generator B to generate const
    konst = self.constgen.gen_const().props['integer']
    assert(konst >= 0)
    if konst == 0:
      # The minimum is 1 because we don't want 0 here
      konst = 1
    rv = INT32(konst)
    c = node_const(rv.value)
    assert(c.props['integer'] != 0)
    self.__logfn(f'_unequate: evA={evA.value}, evB={evB.value}, will add c={c.props["integer"]} to B')
    B = node_op('+', B, c)
    return A, B



class CondGenFuncs(CondGen.Funcs):
  def __init__(self,
               fn_prob_greater=lambda: 1,
               fn_prob_less=lambda: 1,
               fn_prob_greater_eq=lambda: 1,
               fn_prob_less_eq=lambda: 1,
               fn_prob_eq=lambda: 1,
               fn_prob_neq=lambda: 1):
    super().__init__()
    self.fn_prob_greater = fn_prob_greater
    self.fn_prob_less = fn_prob_less
    self.fn_prob_greater_eq = fn_prob_greater_eq
    self.fn_prob_less_eq = fn_prob_less_eq
    self.fn_prob_eq = fn_prob_eq
    self.fn_prob_neq = fn_prob_neq



