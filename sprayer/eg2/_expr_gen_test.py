from dataclasses import dataclass
from typing import List

from c2.sprayer.eg2.egflag import EGFlag
from c2.sprayer.eg2.expr_gen_factory import ExprGenFactory, ConfigurableExprGen
from c2.sprayer.gens.var_list_generator import VarListGenerator, VLVarsGenFuncs
from c2.sprayer.gens._make_random_var import make_random_var
from c2.sprayer.gens.constgen import ConstGenRandom
from c2.sprayer.vp._random_var_picker import RandomVarPicker, PickFlag
from c2.sprayer.vp.single_value_sequencer import SingleValueSequencerFromRandomPicker
from c2.sprayer.ccode.var import *
from c2.sprayer.ccode.node import NT, Node
from c2.sprayer.ccode.textualizer import Textualizer
from c2.sprayer.ccode.evaluator import Evaluator
from c2.sprayer.test.helper_main_cpp import HelperMainCPP
from c2.sprayer.test.srcexec import srcexec


@dataclass
class ExprGenTestParams:
  num_lines: int = None #TODO: move out
  with_consts: bool = None # controls EGFlag
  with_vars: bool = None
  with_arrofs: bool = None
  with_int64vars: bool = None
  with_compile_time_consts: bool = None # controls EGFlag


class ExprGenTest:
  def __init__(self, maxlev, opts, eg_fac:ExprGenFactory, prj_dir, pars:ExprGenTestParams, rng):
    self.__maxlev = maxlev
    self.__opts = opts
    self.__eg_fac = eg_fac
    self.__prj_dir = prj_dir
    self.__pars = pars
    self.__rng = rng
    self.__eg = None # see init()

  # after init() you can yse get_varpicker()
  def init(self):
    self.__init_vars()
    vls = [self.__vtbl.vl_g, self.__vtbl.vl_a]
    if self.__pars.with_vars:
      random_picker = RandomVarPicker(vls, PickFlag.KNOWNS, self.__rng)
      svsequencer = SingleValueSequencerFromRandomPicker(random_picker)
    else:
      svsequencer = None
    # also we should now manage constgen since we moved its support out of blabla bla (lazy to think)
    constgen = ConstGenRandom(self.__rng)
    # set these objects to __eg and forget about them, we don't need them
    self.__init_egflag()
    self.__eg = self.__eg_fac.create_expr_gen(self.__maxlev, self.__opts, self.__rng, svsequencer, constgen)
    self.__eg.set_egflag(self.__egflag)

  def get_exprgen(self) -> ConfigurableExprGen:
    return self.__eg

  # uses: with_arrofs, with_int64vars
  def __init_vars(self):
    self.__vl_g = [Var(VT.u8, [10]), Var(VT.i8, [12]),
                   Var(VT.u16, [14]), Var(VT.i16, [16]),
                   Var(VT.u32, [18]), Var(VT.i32, [20])]
    self.__vl_a = [Var(VT.u8, [60]), Var(VT.i8, [62]),
                   Var(VT.u16, [64]), Var(VT.i16, [66]),
                   Var(VT.u32, [68]), Var(VT.i32, [70])]
    if self.__pars.with_int64vars:
      self.__vl_g += [Var(VT.u64, [22]), Var(VT.i64, [24])]
      self.__vl_a += [Var(VT.u64, [72]), Var(VT.i64, [74])]
    if self.__pars.with_arrofs:
      _cnt = 100
      for v in self.__vl_g:
        v.values += [_cnt]
        _cnt += 1
    self.__vtbl = VarNameTable(self.__vl_g, self.__vl_a, [])
    vtbl = self.__vtbl
    # for srcexec template
    self.__glob_decls = decl_varlist(vtbl.vl_g, vtbl.names_g, line_prefix='static ', valprn=ValPrintType.WITH_VALUE)
    self.__loc_decls = decl_varlist(vtbl.vl_l, vtbl.names_l, tabs=1, valprn=ValPrintType.WITH_VALUE)
    self.__arg_decls = decl_arglist(vtbl.vl_a, vtbl.names_a)
    self.__call_args = ', '.join([f'({type_names[v.typ]})0x{v.values[0]:x}' for v in vtbl.vl_a])

  def __init_egflag(self):
    self.__egflag = EGFlag(0)
    if self.__pars.with_consts:
      self.__egflag |= EGFlag.CONSTS
    if self.__pars.with_compile_time_consts:
      self.__egflag |= EGFlag.ALLOW_COMPILE_TIME_CONSTS

  def get_exprs(self) -> List[Node]:
    return self.__exprs

  def run(self):
    # Prepare for expr generation loop
    vtbl = self.__vtbl
    texer = Textualizer(lambda v: vtbl.get_var_name(v), tabs=0)
    evaler = Evaluator()
    # generate a lot of random expressions and ASSERT()s for its values
    code = ''
    self.__exprs = []
    for i in range(self.__pars.num_lines):
      #logfn = lambda msg: print(f'expr {i}: {msg}')
      logfn = lambda msg: None
      evaler.set_logging(texer, logfn)

      unused_pick_history = []
      e = self.__eg.gen_expr(unused_pick_history)
      assert(len(unused_pick_history) == 0)

      self.__exprs.append(e)

      expr_text = texer.visit(e)
      #print(f'Textualized: {expr_text}')

      evaled = evaler.visit(e)

      defconv_type = INT32 if evaled.byte_size < 4 else type(evaled)
      # defconvert = type(evaled) # doesn't work
      evaleddef = defconv_type(0).assign(evaled)
      line = f'ASSERT({expr_text} == 0x{evaleddef.value:x}); // # {i} evaled is {type(evaled).__name__}, defconv is {defconv_type.__name__}'
      code += '  ' + line + '\n'
      #print()

    # generate cpp template
    RET_CODE = 90177030
    helper_cpp = HelperMainCPP([],
                               '\n'.join(self.__glob_decls),
                               '\n'.join(self.__loc_decls),
                               ', '.join(self.__arg_decls),
                               self.__call_args,
                               code,
                               RET_CODE)
    # execute generated cpp template
    print(f'executing helper cpp...')
    srcexec(self.__prj_dir, 'test_exprgen', helper_cpp, RET_CODE)
