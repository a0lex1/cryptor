from typing import Callable, Tuple, Any

from c2.sprayer.eg2.egflag import *
from c2.sprayer.ccode.node import *
from c2.sprayer.ccode.var import Var
from c2.sprayer.ccode.node import NT
from c2.common.bit_rotate import ror, rol

 
class BijectiveFiller:
  # TODO: Shuffle L-R like in human code!
  # root_node - a root of a tree of empty Node()s to fill
  # if op_gravitate_outer == False, gravitate deeper
  def __init__(self, bitcount, root_node=None):
    self.bitcount = bitcount
    self.root_node = root_node

    self.term_gravitate_right = None # required
    self.op_gravitate_outer = None # required

    self.subgen = None
    self.subgen_probab_percent = None
    self.subgen_rng = None

    self.__egflag = None
    self.__constgen = None
    self.__fn_pickvar = None # (pick_history)

    self._prerotate_bits_term = 0 # set_prerotate
    self._prerotate_bits_op = 0

    self._iterm = 0

    #self._enable_naked_consts = True

    self._prev_node = None

    self.__prefer_arridx_to_arrofs = False

  def prefer_arridx_to_arrofs(self, enable:bool):
    self.__prefer_arridx_to_arrofs = enable

  def set_constgen(self, constgen):
    self.__constgen = constgen

  def set_egflag(self, egflag):
    self.__egflag = egflag

  def get_egflag(self):
    return self.__egflag

  # fn_pickvar = None means don't use vars in expressions
  #                                             pick_history
  def set_fn_pickvar(self, fn_pickvar:Callable[[Any, ], Tuple[Var, int]]):
    self.__fn_pickvar = fn_pickvar

  # Requied to be called before fill()
  def set_gravitation(self, term_gravitate_right:bool, op_gravitate_outer:bool):
    self.term_gravitate_right = term_gravitate_right
    self.op_gravitate_outer = op_gravitate_outer

  # Helps to make more random by starting TERM and OP iteration from random bit position of N
  def set_prerotate(self, prerotate_bits_term:int, prerotate_bits_op:int):
    self._prerotate_bits_term = prerotate_bits_term
    self._prerotate_bits_op = prerotate_bits_op

  def set_subgen(self, subgen, probab_percent, subgen_rng):
    self.subgen = subgen
    self.subgen_probab_percent = probab_percent
    self.subgen_rng = subgen_rng

  def fill(self, n, pick_history):
    self._n_term = n # low X bits used, rotated N bits right
    self._n_op = n # ...
    self._n_term = ror(self._n_term, self._prerotate_bits_term, self.bitcount)
    self._n_op = ror(self._n_op, self._prerotate_bits_op, self.bitcount)
    self.__iop = 0 # internal counter
    self._prev_node = None
    self.__pick_history = pick_history # it will be used while visit()ing
    self.__visit(self.root_node)
    self.__pick_history = None


  def __visit(self, node, lev=0):
    # Depth-first mode: first recurse, than process; so we go from bottom to top of tree
    assert(len(node.children) in [0, 2]) #check binary tree limitation
    for child in node.children:
      self.__visit(child, lev + 1) # recursion

    if 0 == len(node.children):
      # reached empty node when going backwards
      # this is a bottom node and it has no children
      termchoices = []
      if self.__fn_pickvar != None:
        termchoices += ['V', ]

      include_consts = False
      if self.__egflag & EGFlag.ALLOW_COMPILE_TIME_CONSTS:
        #assert(self.__egflag & EGFlag.CONSTS) #we decided not to check this combinations in outer code, e.g. in test code
        include_consts = True
      else:
        if self.__egflag & EGFlag.CONSTS:
          if self._prev_node == None:
            self._prev_node = node
            if lev > 0:
              include_consts = True
          else:
            assert(self._prev_node.typ in [NT.Const, NT.Var, NT.ArrOfs, NT.ArrIdx])
            if self._prev_node.typ != NT.Const:
              include_consts = True #if breakpoint here, #PyCharmC0000005Crash
            # next pair will be _prev==None again
            self._prev_node = None

      if include_consts:
        termchoices += ['K']

      if self.subgen and self.subgen_rng.randint(0, 99) < self.subgen_probab_percent:
        # Include subgen in dice
        termchoices += ['$']

      # Roll the dice
      newterm, term = self._nextchoice(2, self._n_term, termchoices, self.term_gravitate_right)
      self._n_term = newterm

      if term == 'V':
        v, idx = self.__fn_pickvar(self.__pick_history)
        # no deep copy because we need only one node, it's children is referenced
        if self.__prefer_arridx_to_arrofs:
          node.__dict__ = node_var_or_arridx(v, idx).__dict__ # assig object
        else:
          node.__dict__ = node_var_or_arrofs(v, idx).__dict__ # assig object
      elif term == 'K':
        node.__dict__ = self.__constgen.gen_const().__dict__
      elif term == '$':
        # subgen
        assert(self.subgen)
        subexpr = self.subgen.gen_expr()
        node.__dict__ = subexpr.__dict__ # assign object to another object
      else:
        raise RuntimeError()

      self._iterm += 1
    else:
      # have children when going backwards
      # this is some Op ndoe
      # we use `4` rbits here, so for 16-bit |n| the pattern will repeat after 3'th level op
      # this is reserved for future extending of ops

      opchoices = ['+', '-', '*']

      # IMPROV:
      # Don't allow division by ZERO. Add div op if the evaluation result of the right side is not 0.
      #if not Evaluator().visit(node.children[1]).integer == 0:
      #  opchoices.append('/')

      newop, op = self._nextchoice(4, self._n_op, opchoices, self.op_gravitate_outer)

      self._n_op = newop

      node.typ = NT.Op
      node.props['op_code'] = op

      self.__iop += 1


  # rbits can cover more than len(choices), in this case, the index is %ed to len(choices)
  # Can be made public, useful func, no depends
  def _nextchoice(self, rbits, curval, choices, from_highest:bool, trace=False):
    assert(len(choices))
    if from_highest: # gravitate right, outer
      #  Similar numbers produces similar right side
      #  Get bits from lower to highest: get lower nbits, then rotate right
      #                vvvv  (rbits->4)
      #  111010011101001001
      #  ----------------->  ror
      mask = 2**rbits - 1
      ch = curval & mask
      newval = ror(curval, rbits, self.bitcount)
    else:
      #  Gravitate to the left side. Similar numbers produces similar left
      #  side (or outer in case of ops) side
      #  Get bits from highest to lower: get highest nbits, then rotate left
      #  vvvv
      #  111010011101001001
      #  <-----------------  rol
      #
      # Rotate mask:
      #  000000001111 ror 4 =
      #  111100000000 rol 4 =
      #  000000001111
      mask = ror(2**rbits - 1, rbits, self.bitcount)
      ch = curval & mask
      ch = rol(ch, rbits, self.bitcount)
      newval = rol(curval, rbits, self.bitcount)
      #if trace:
      #  print(f'curval {curval:016b}\n'
      #        f'newval {newval:016b}\n'
      #        f'mask   {mask:016b}\n'
      #        f'ch     {ch:016b}')
      #  print(f'ch {ch:x}, mask {mask:x} curval {curval:x} newval {newval:x}')

    ret = choices[ch % len(choices)]
    return newval, ret







