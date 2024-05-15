import random, os, sys
from typing import List
from collections import namedtuple

from c2.sprayer.test.roletest_bundle import BasicRoletestBundle
from c2.sprayer.test.srcexec import srcexec
from c2.sprayer.test.helper_main_cpp import HelperMainCPP
from c2.sprayer.fg.func_ast import FuncAST
from c2.sprayer.fg.var_storage import *
from c2.sprayer.ccode.textualizer import Textualizer
from c2.sprayer.gens.var_list_generator import VLVarsGenFuncs
from c2.sprayer.ccode.var import Var, VT, VarNameTable, ValPrintType, decl_varlist, decl_arglist
from c2.sprayer.ccode.node import node_var
from c2.infra.tool_cli import ToolCLI
from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE, textualize_seed
from c2.infra.seed_get_or_generate import seed_get_or_generate
from c2.infra.dynjen_from_aggregator import dynjen_from_aggregator
from c2.infra.testloop_runner import TestloopRunner
from c2.infra.unischema import unischema_load

_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/../../'

CLIConfigArgs = namedtuple('CLIConfigArgs', ['conf_name', 'unischema', 'jen_tag'])


# Customizable ToolCLI
# Not parallelable (uses single tmp dir)
class FuncGenTest(ToolCLI):
  def __init__(self, prj_dir, progname, fn_fgfac, ccargs: CLIConfigArgs, argv:List[str]):
    super().__init__(argv)
    self.__prj_dir = prj_dir
    self.__progname = progname
    self.__fn_fgfac = fn_fgfac
    self.__ccargs = ccargs

  def _initialize(self):
    self._progname = os.path.basename(__file__)

  def _setup_args(self):
    agr = self._agr
    parser = self._parser

    self.__cli_seed = CLISeed(os.getcwd(), DEFAULT_SEED_SIZE)
    self._add_arg_processor(self.__cli_seed)

    # TODO
    #self.__rule_argproc = RuleArgProcessor()
    #self._add_arg_processor(self.__rule_argproc)
    #

    agr.add_config(self.__ccargs.conf_name, self.__ccargs.unischema, jen_tag=self.__ccargs.jen_tag)

    agr.add_config('tst', unischema_load(f'{_sd}/../../test/tst_opts.UNISCHEMA', _inclroot))


  def _do_work(self):
    agr = self._agr
    tst_opts = agr.config('tst')

    seed = seed_get_or_generate(self.__cli_seed, DEFAULT_SEED_SIZE)
    print(f'FuncGenTest._do_work() using seed: {textualize_seed(seed)}')
    self.__rng = random.Random(seed)
    print(f'<FuncGenTest._do_work() rng probe: {self.__rng.randint(0, sys.maxsize)}>')

    conf_name = self.__ccargs.conf_name
    dj = dynjen_from_aggregator(agr, conf_name)

    loop_runner = TestloopRunner(tst_opts, dj, self.__fn_dispatch_inst)
    loop_runner.run()


  # fgopts is either fgmin_opts or fgfull_opts
  def __fn_dispatch_inst(self, fgopts):
    bundle = BasicRoletestBundle(3, False, 1, 1, 3, False)
    #vlgenfuncs = VLVarsGenFuncs() #WHAT WAS THIS FOR?
    #vlgenfuncs.only_knowns().fixed_count(1)  # no arrofs
    _vl_g = [Var(VT.u8, [7])]
    _vl_a = [Var(VT.u32, [1])]
    _vl_l = []
    bundle.set_cool_arg(node_var(_vl_a[0]))
    varstor = make_var_storage(vl_g=_vl_g, vl_a=_vl_a, vl_l_ctl_u=_vl_l)

    # Create FG
    func_ast = FuncAST()
    funcgen = self.__fn_fgfac()
    funcgen.configure(func_ast, bundle.get_roles(), varstor, fgopts, self.__rng)

    #funcgen._enable_assiggen_comments(True)!!!

    #
    # Do all the FG stages
    # <maybe some human-displaying graphs/logs here>
    #
    funcgen.all_stages(fn_prn=print)
    #TODO---------------------
    #Now self.__rule_argproc.rules contains the rules: [Rule( ), Rule( ), ...] - we'll pass it to StageRunnerExecutor
    #from c2.base.stage.stage_runner_executor import StageRunnerExecutor
    #from c2.base.stage.handler import HandlerTable
    ###from c2.base.stage.register_text_handlers import register_text_handlers
    ###from c2.base.stage.register_graph_handlers import register_graph_handlers
    ###
    #htable = HandlerTable()
    ##register_text_handlers(htable)
    ##register_graph_handlers(htable)
    #executor_rules = self.__rule_argproc.rules # these rules were parsed from cmdline
    #executor = StageRunnerExecutor(htable, executor_rules, allow_unhandled=False)
    #executor.all_stages(funcgen)

    # Textualize code
    vnt = VarNameTable(sum(get_globvar_vls(varstor), []),
                       sum(get_argvar_vls(varstor), []),
                       sum(get_locvar_vls(varstor), []))
    texer = Textualizer(lambda v: vnt.get_var_name(v))
    code = texer.visit(func_ast.stmtlist)
    checkcode = Textualizer().visit(bundle.get_checkcode())
    #callargs = ', '.join(['0' for _ in range(len(get_argvar_vls(varstor))])
    callargs = '1'

    # textualize vars
    decllines_vl_g = decl_varlist(sum(get_globvar_vls(varstor), []), vnt.names_g, valprn=ValPrintType.WITH_VALUE)
    decllines_vl_a = decl_arglist(sum(get_argvar_vls(varstor), []), vnt.names_a)
    decllines_vl_l = decl_varlist(sum(get_locvar_vls(varstor), []), vnt.names_l, valprn=ValPrintType.WITHOUT_VALUE, tabs=1)
    decls_vl_g = '\n'.join(decllines_vl_g+bundle.get_globvardef())
    decls_vl_a = '\n'.join(decllines_vl_a)
    decls_vl_l = '\n'.join(decllines_vl_l)

    # Compile and exec textualized code
    ret       = srcexec(self.__prj_dir, self.__progname,
                        HelperMainCPP(glob_vars=decls_vl_g,
                                      loc_vars=decls_vl_l,
                                      args_funcdecl=decls_vl_a,
                                      args_funccall=callargs,
                                      code=code + '\n' + checkcode,
                                      retcode=463761,
                                      includes=['windows.h']))
    print(f'srcexec returned {ret}')
    print()







