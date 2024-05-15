import random
from typing import List
from enum import Flag, auto
from dataclasses import dataclass

from c2.sprayer.eg2.core.random_expression_generator_funcs import RandomExpressionGeneratorFuncs
from c2.sprayer.eg2.egflag import *
from c2.sprayer.vp.single_value_sequencer import SingleValueSequencer, SingleValueSequencerFromRandomPicker
from c2.sprayer.vp._random_var_picker import RandomVarPicker, PICK_FLAG_ALL
from c2.sprayer.gens.constgen import ConstGen
from c2.sprayer.ccode.node import Node
from c2.sprayer.ccode.var import Var, VT
from c2.sprayer.ccode.node import *


@dataclass
class RandomExpressionGenerator:
  __maxlev: int
  __rng: random.Random
  egflag: EGFlag = EG_FLAG_DEFAULT
  svsequencer: SingleValueSequencer = None # if None, vars not used, only consts (if both off, raise)
  constgen: ConstGen  = None
  __funcs = RandomExpressionGeneratorFuncs()
  __lev = 0
  __prefer_arridx_to_arrofs: bool = False


  def __post_init__(self):
    self.__limit_depth_probab(self.__maxlev)

  def prefer_arridx_to_arrofs(self, enable:bool):
    self.__prefer_arridx_to_arrofs = enable

  def has_vars(self):
    # Note: it doesn't check whether there are actual Var(s) in lists or the lists are empty
    return self.svsequencer != None

  def gen_random_expr(self, pick_history) -> Node:
    if not self.has_vars() and not self.egflag & EGFlag.CONSTS:
      raise RuntimeError('No vars (sequencer is None) and no consts (disabled). What to generate exprs from?')
    return self.__do_gen_expr(pick_history)


  def __limit_depth_probab(self, depth_limit):
    self.__funcs.fn_probab_op = lambda lev: 1/(lev+1) if lev < depth_limit else 0

  def __do_gen_expr(self, pick_history):
    # arrofs var const op
    f = self.__funcs
    lev = self.__lev
    acts = {}
    if self.has_vars() or self.egflag & EGFlag.ALLOW_COMPILE_TIME_CONSTS:
      # we can do some op between var/const or const/const if compile time consts enabled
      acts[self.__gen_op] = f.fn_probab_op(lev)
    if (self.egflag & EGFlag.CONSTS):
      if lev > 0 or self.egflag & EGFlag.ALLOW_COMPILE_TIME_CONSTS:
        acts[self.__gen_const] = f.fn_probab_const(lev)
    if self.has_vars():
      acts[self.__gen_var_or_arrofs] = f.fn_probab_var(lev)
    chosen = self.__rng.choices([a for a in acts.keys()], weights=tuple(acts[a] for a in acts.keys()), k=1)
    g = chosen[0](pick_history)
    return g

  def __gen_var_or_arrofs(self, pick_history):
    v, arridx = self.svsequencer.pick_var_ind(pick_history)
    if self.__prefer_arridx_to_arrofs:
      return node_var_or_arridx(v, arridx)
    else:
      return node_var_or_arrofs(v, arridx)
    '''if v.valcount() > 1:
      ofs = arridx * type_classes[v.typ].byte_size
      return node_arrofs(node_var(v), node_const(ofs))
    else:
      assert(arridx == 0)
      return node_var(v)'''

  '''
  # This code works fine, but it's not yet needed since we've just switched to using ExprGen.constgen.
  # This code will be probably used in flag-like constgens.
  def __gen_const_value(self, min_value, ):
    # TODO: x64 consts
    # gen const value using probability Funcs
    f = self.__funcs
    lev = self.__lev
    maxes = {0xff: f.fn_probab_const_byte(lev), 0xffff: f.fn_probab_const_word(lev), 0xffffffff: f.fn_probab_const_dword(lev)}
    w = tuple(m for m in maxes.values())
    max = self.__rng.choices([m for m in maxes.keys()], weights=w, k=1)[0]
    probab_isflag = f.fn_probab_const_isflag(lev)
    isflag = self.__rng.choices([True, False], weights=(probab_isflag, 1 - probab_isflag), k=1)[0]
    if isflag == True:  # if flag, clear less bits
      shiftleft = self.__rng.randint(min_value, max.bit_length() - 1)
      ret = (1 << shiftleft) & max
      assert(ret != 0)
    else:
      ret = self.__rng.randint(min_value, max)
    return ret'''

  def __gen_const(self, pick_history):
    return self.constgen.gen_const()

  def __gen_op(self, pick_history):
    f = self.__funcs
    lev = self.__lev
    opcodes = { '+': f.fn_probab_op_plus(lev),
                '-': f.fn_probab_op_minus(lev),
                '*': f.fn_probab_op_mul(lev) }
    op_ = self.__rng.choices([_ for _ in opcodes.keys()], weights=tuple(opcodes[_] for _ in opcodes.keys()), k=1)
    op = op_[0]
    return self.__gen_op_for_code(op, pick_history)

  def __gen_op_for_code(self, opcode, pick_history):
    self.__lev += 1

    A = self.__do_gen_expr(pick_history)

    # Check if CONSTS in B are allowed
    allow_consts_in_B = self.egflag & EGFlag.ALLOW_COMPILE_TIME_CONSTS or A.typ != NT.Const

    old_egflag = self.egflag

    if not allow_consts_in_B:
      # Disable CONSTS just for the next call to _gen_expr()
      self.egflag &= ~EGFlag.CONSTS

    B = self.__do_gen_expr(pick_history)

    # restore flags
    self.egflag = old_egflag

    self.__lev -= 1

    #if not (type(A) == node_const and type(B) == node_const):
    #  # never substract constants, append if not const<op>const
    #  ops.append('-')
    return node_op(opcode, A, B)


### TEST CODE ###

from c2.sprayer.vp._random_var_picker import RandomVarPicker, PICK_FLAG_ALL
from c2.sprayer.vp.single_value_sequencer import SingleValueSequencerFromRandomPicker
from c2.sprayer.gens.constgen import ConstGenRandom
from c2.sprayer.ccode.textualizer import Textualizer
from c2.sprayer.ccode.var import Var, VarNameTable

_vl0 = [Var(VT.i8, [1,2,3,4,5,6,7,8]), Var(VT.u16, [10, 20]), Var(VT.i32, [0, 15, 25, 39])]
_vl1 = [Var(VT.u32, [55, 66, 77, 88, 99]), Var(VT.i8, [230, 240])]
_vls = [_vl0, _vl1]

def demo_random_expression_generator():
  rng = random.Random()
  p = RandomVarPicker(_vls, PICK_FLAG_ALL, rng)
  s = SingleValueSequencerFromRandomPicker(p)
  r = RandomExpressionGenerator(4, rng, EG_FLAG_DEFAULT, s, ConstGenRandom(rng))
  pick_history = []
  e = r.gen_random_expr(pick_history)
  vnt = VarNameTable(_vl0, _vl1, [])
  texer = Textualizer(lambda v: vnt.get_var_name(v))
  print(texer.visit(e))


if __name__ == '__main__':
  demo_random_expression_generator()

