import random, sys, os
from typing import List, Set
from dataclasses import dataclass, field

from c2.sprayer.eg2._expr_gen_test import ExprGenTest, ExprGenTestParams
from c2.sprayer.eg2.expr_gen import ConfigurableExprGen
from c2.sprayer.eg2.expr_gen_factory import ExprGenFactory, EG_RANDOM_NAME, EG_BIJECTIVE_NAME
from c2.sprayer.ccode.node import *
from c2.sprayer.ccode.var import *
from c2.infra.tool_cli import ToolCLI
from c2.infra.unischema import unischema_load
from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE, textualize_seed
from c2.infra.seed_get_or_generate import seed_get_or_generate
from c2.infra.testloop_runner import TestloopRunner
from c2.infra.dynjen_from_aggregator import dynjen_from_aggregator
from c2.test.tst_opts import tmp_dir_from_tst_argv

_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/../..'

_ALL_EGS = [EG_RANDOM_NAME, EG_BIJECTIVE_NAME]


# EGTestCLI is a test for  FACTORY-SUPPORTED  ExprGen(s)
class EGTestCLI(ToolCLI):
  DEFAULT_MAXLEVELS = [5, 0]

  def __init__(self, tmpdir:str, *args, **kwargs):
    super().__init__(*args, *kwargs)
    self.__tmpdir = tmpdir

  def _initialize(self):
    self._progname = os.path.basename(__file__)

  def _setup_args(self):
    self._parser.add_argument('--egs', choices=_ALL_EGS, action='append', nargs='*')
    self._parser.add_argument('--num_lines', type=int, default=50)
    self._parser.add_argument('--maxlevels', nargs='*', action='append', type=int, help=f'default is {EGTestCLI.DEFAULT_MAXLEVELS}')

    # for TestLoopRunner
    self._agr.add_config('tst', unischema_load(f'{_sd}/../../test/tst_opts.UNISCHEMA', _inclroot))

    self._agr.add_config(EG_RANDOM_NAME, unischema_load(f'{_sd}/egrandom_opts.UNISCHEMA', _inclroot),
                         jen_tag='$jdefault') # generate
    self._agr.add_config(EG_BIJECTIVE_NAME, unischema_load(f'{_sd}/egbijective_opts.UNISCHEMA', _inclroot),
                         jen_tag='$jdefault') # generate

    self.__cli_seed = CLISeed(os.getcwd(), DEFAULT_SEED_SIZE)
    self._add_arg_processor(self.__cli_seed)


  def _do_work(self):
    maxlevs = sum(self._args.maxlevels, []) if self._args.maxlevels else EGTestCLI.DEFAULT_MAXLEVELS
    seed = seed_get_or_generate(self.__cli_seed, DEFAULT_SEED_SIZE)
    print(f'{os.path.basename(__file__)}._do_work(): using seed {textualize_seed(seed)}')
    rng = random.Random(seed)
    num_lines = self._args.num_lines
    egs = sum(self._args.egs, []) if self._args.egs else _ALL_EGS
    for eg_name in egs:
      print(f'==EG {eg_name}  testing eg with several opts (dynjen)')
      dj = dynjen_from_aggregator(self._agr, eg_name)

      def fn_dispatch_inst(eg_opts_inst:dict):
        eg_fac = ExprGenFactory(eg_name)
        prj_dir = f'{self.__tmpdir}/test_exprgen/{eg_name}'
        for maxlev in maxlevs:
          print(f'====EG {eg_name}] testing with maxlevel={maxlev} (total {len(maxlevs)} maxlevels to test)')
          title = f'exprgen={eg_name},maxlevel={maxlev}'
          multitest = _EGMultiTest(title, eg_fac, prj_dir, maxlev, eg_opts_inst, num_lines, rng)
          print(f'====maxlevel {maxlev} has been tested.')
          multitest.execute()
        print('==_EGMultiTest completed for eg opts instance')
        print()

      lr = TestloopRunner(self._agr.config('tst'), dj, fn_dispatch_inst)
      lr.run()

      print(f'==Exprgen `{eg_name}` has been tested')
      print()
      print()
    return


@dataclass
class _EGMultiTest:
  __title: str
  __eg_fac: ExprGenFactory # svsequencer and condgen should be None
  __prj_dir: str
  __maxlev: int
  __opts: dict
  __num_lines: int
  __rng: random.Random

  def execute(self):
    nl = self.__num_lines
    Params = ExprGenTestParams
    #BadCombinationsOfEGParams are listed here (if ...: continue)
    pars = ExprGenTestParams()
    pars.num_lines = 1000 #RandomnessDependency #INCREASE!!!!!! but first try lower and ensure error emerged
    for pars.with_consts in [True, False]:
      for pars.with_vars in [False, True]:
        if not pars.with_consts and not pars.with_vars:
          continue
        for pars.with_arrofs in [False, True]:
          if pars.with_arrofs and not pars.with_vars:
            continue
          for pars.with_int64vars in [False, True]:
            if pars.with_int64vars and not pars.with_vars:
              continue
            for pars.with_compile_time_consts in [False, True]:
              if not pars.with_vars and not pars.with_compile_time_consts:
                continue
              if pars.with_compile_time_consts and not pars.with_consts:
                continue
              print(f'-=-=-=-=- Doing ExprGenTest (title: {self.__title}) with params {pars}')
              tst = ExprGenTest(self.__maxlev, self.__opts, self.__eg_fac, self.__prj_dir, pars, self.__rng)
              tst.init() #PyCharmBug if bp here
              tst.run()
              assert(self.__maxlev == tst.get_exprgen().get_maxlev())
              checkfn = self.__check_params_match_results
              checkfn(tst.get_exprs(), pars)

  # RandomnessDependency - we're expecting everything possible variants to emerge at least once
  def __check_params_match_results(self, exprs:List[Node], params:ExprGenTestParams):
    # -- our visitor to collect information
    class InfoCollectVisitor(NodeVisitor):
      def __init__(self):
        super().__init__()
        self.max_op_level = 0
        self.nts = set() # collected node types
        self.vts = set() # collected var types
        self.is_compile_time = True
        self.num_consts_used = 0 # smart const detection - don't count arrofs'es [] consts
        self.__visit_nodes = []
      def visit(self, node):
        self.__manage_max_rec_lev()
        self.__visit_nodes.append(node)
        self.nts.add(node.typ)
        if node.typ == NT.Var:
          self.vts.add(node.props['v'].typ)
          self.is_compile_time = False
        if node.typ == NT.Const:
          if 0==len(self._parent_node_stack) or self._parent_node_stack[-1].typ != NT.ArrOfs:
            self.num_consts_used += 1
        ret = super().visit(node)
        return ret
      def __manage_max_rec_lev(self):
        # We don't use cur_recursion_level(). It gives recursion level, not the level of node_op(s) (which is required by ExprGen rules, read its comments)
        parent_node_types = list(map(lambda item: item.typ, self._parent_node_stack))
        num_parent_ops = parent_node_types.count(NT.Op) # other NT(s) ...?
        if num_parent_ops > self.max_op_level:
          self.max_op_level = num_parent_ops

    # -- end of class InfoCollectVisitor
    # now collect information; every expr gets its own visitor in visitors list
    visitors = []
    for expr in exprs:
      vis = InfoCollectVisitor()
      vis.visit(expr)
      visitors.append(vis)
    # now map fields of all visitors for further checking
    all_max_op_levels = list(map(lambda item: item.max_op_level, visitors))
    all_nts = set(sum(map(lambda item: list(item.nts), visitors), []))
    all_vts = set(sum(map(lambda item: list(item.vts), visitors), []))
    all_is_compile_times = list(map(lambda item: item.is_compile_time, visitors))
    total_num_consts_used = sum(list(map(lambda item: item.num_consts_used, visitors)))
    # now check
    greatest_of_level = max(all_max_op_levels)
    assert(greatest_of_level == self.__maxlev) #need exact match since we've generated tons of exprs
    if params.with_consts:
      if self.__maxlev == 0 and not params.with_compile_time_consts:
        # Yet another special case.
        # maxlev==0 forbids to use node_op. In this case, the only way to provide a node_const is when compile time consts enabled. So if they're disabled,...
        pass # ok
      else:
        # we should see node_const
        assert(total_num_consts_used > 0)
    else:
      assert(total_num_consts_used == 0)
    ###
    if params.with_vars:
      assert(NT.Var in all_nts)
    else:
      assert(NT.Var not in all_nts)
    ###
    if params.with_arrofs:
      assert(NT.ArrOfs in all_nts)
    else:
      assert(NT.ArrOfs not in all_nts)
    ###
    if params.with_int64vars:
      assert(VT.u64 in all_vts)
      assert(VT.i64 in all_vts)
    else:
      assert(VT.u64 not in all_vts)
      assert(VT.i64 not in all_vts)
    ###
    if params.with_compile_time_consts:
      assert(True in all_is_compile_times)
    else:
      assert(True not in all_is_compile_times)
    return

from c2._internal_config import get_tmp_dir

if __name__ == '__main__':
  #import faulthandler #DELETEME
  #faulthandler.enable()
  raise RuntimeError('don\'t run this file directly, run test_exprgens.py instead')
  tmpdir = get_tmp_dir() + '/egtest_cli'
  EGTestCLI(tmpdir, sys.argv[1:]).execute()





























