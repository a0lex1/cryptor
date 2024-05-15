import os
from typing import List
from functools import partial

from c2.sprayer._wave import RandomSinWaveCoeff, adjust_sinwaves
from c2.sprayer.fg.var_storage import *
from c2.sprayer.fg._replacing_visitor import ReplacingVisitor
from c2.sprayer.fg._expr_gen_nlist import ExprGenNList, BijectiveExpressionGenerator
from c2.sprayer.vp.vrpicker_factory import create_vrpicker_factory
from c2.sprayer.vp.vrp_default_opts import vrp_default_opts
from c2.sprayer.vp.single_value_sequencer import *
from c2.sprayer.vp.vls_shape import vls_shape_from_vls
from c2.sprayer.eg2.expr_gen_factory import ExprGenFactory
from c2.sprayer.eg2.eg_default_opts import eg_default_opts
from c2.sprayer.gens.assiggen import AssigGen
from c2.sprayer.gens.constgen import ConstGenRandom
from c2.sprayer.gens.condgen import CondGen, CondGenFuncs
from c2.sprayer.misc.role import Role
from c2.sprayer.misc.flow import Flow
from c2.sprayer.ccode.textualizer import Textualizer
from c2.sprayer.ccode.var import *
from c2.sprayer.ccode.node import NT, Node, node_relop, node_const, node_line
from c2.sprayer.ccode.evaluator import Evaluator
from c2.sprayer.ccode.name_bind_string import NameBindString
from c2.infra.unischema import unischema_load
from c2.common.utils import parsemac

_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/../..'
_bijectivecore_opts_unischema = unischema_load(f'{_sd}/../eg2/core/bijectivecore_opts.UNISCHEMA', _inclroot)


# Current STATUS:
#  It now generates assigs without fn_isgood limitations,
#  and test_funcgen_full crashes cuz those assigs not executed/calculated/etc. Time to develop
# through fixing. But test_funcgen_new.cpp looks cool...
#
# You should call create_objects() before calling visit().
# TODO: should FG pass |opts| or pass only its fields as variables? Now passing |opts|.
class NewFinalizer(ReplacingVisitor):
  def __init__(self, fgnew_opts, varstor:VarStorage, roles:List[Role], rng):
    super().__init__()
    self.__opts = fgnew_opts
    self.__varstor = varstor
    self.__roles = roles
    self.__rng = rng
    self.__flow = Flow.EXEC
    self.enable_add_eval_comment(False)
    self._ncond = 0  # helps debug
    #self._nflowchg = 0  # helps debug

  '''def __fn_isgood_r(self, loc:Tuple[int,int,int]) -> bool:
    # value must be initialized in vls
    if not self.__varstor.vls[loc[0]][loc[1]].is_elem_init(loc[2]):
      return False
    if self.__flow == Flow.EXEC:
      # pick only proper known values for cond's exprs
      return loc[0] in [VLI_G, VLI_L_CTL, VLI_L_CTL_U, VLI_A]
    elif self.__flow == Flow.MAYBE:
      ### No trashvars for conds, they can be SPOILED by roles/etc; except for NOT_EXEC. their calculations are always not 100% sure;
      return loc[0] in [VLI_G, VLI_L_CTL, VLI_L_CTL_U, VLI_L_TRASH, VLI_L_TRASH_U, VLI_A]
    elif self.__flow == Flow.NOT_EXEC:
      return loc[0] in [VLI_G, VLI_L_CTL, VLI_L_CTL_U, VLI_L_TRASH, VLI_L_TRASH_U, VLI_A]
    else: raise

  def __fn_isgood_w(self, loc: Tuple[int,int,int]) -> bool:
    if self.__flow == Flow.EXEC:
      # pick only proper known values for cond's exprs
      return loc[0] in [VLI_G, VLI_L_CTL, VLI_L_CTL_U, VLI_A]
    elif self.__flow == Flow.MAYBE:
      ### No trashvars for conds, they can be SPOILED by roles/etc; except for NOT_EXEC. their calculations are always not 100% sure;
      return loc[0] in [VLI_L_TRASH, VLI_L_TRASH_U]
    elif self.__flow == Flow.NOT_EXEC:
      return loc[0] in [VLI_G, VLI_L_CTL, VLI_L_CTL_U, VLI_L_TRASH, VLI_L_TRASH_U, VLI_A]
    else: raise'''

  def create_objects(self, num_if_trues, num_if_falses):
    vrpname = 'insular'
    vrpfac = create_vrpicker_factory(vrpname)
    self.__vrpstate = vrpfac.create_vrpicker_state(vls_shape_from_vls(self.__varstor.vls))
    vrpiniter = vrpfac.create_vrpicker_state_initializer()
    vrpiniter.init_state_from_vls(self.__vrpstate, self.__varstor.vls)
    vrpopts = vrp_default_opts(vrpname)
    self.__vrpicker = vrpfac.create_vrpicker(self.__varstor.vls, self.__vrpstate, vrpopts, self.__rng)
    self.__vrpicker.set_fn_isgood_r(self.__fn_isgood_r)
    self.__vrpicker.set_fn_isgood_w(self.__fn_isgood_w)
    # self.__replers_replacer = ReplersReplacer(
    #     self.__varstor.vls(), self.__vrpicker,
    #     self.__fn_isgood_in, self.__fn_isgood_out, self.__fn_isgood_inout)

    self.__constgen = ConstGenRandom(self.__rng)
    # Our condgen is using prepared NList. We keep this code complex wave-pregen code cuz it can be necessary in future.
    cg_svsequencer = SingleValueSequencerFromVRPicker(UsePurpose.READ, self.__vrpicker, self.__varstor.vls)
    lconf = _bijectivecore_opts_unischema.make_default_config()
    rconf = _bijectivecore_opts_unischema.make_default_config()
    lmaxlev = self.__opts['condgen_eg_l_maxlev']
    rmaxlev = self.__opts['condgen_eg_r_maxlev']
    BijExprGen=BijectiveExpressionGenerator
    cg_eg_l = ExprGenNList(BijExprGen(lmaxlev, lconf, self.__rng, cg_svsequencer, self.__constgen))
    cg_eg_r = ExprGenNList(BijExprGen(rmaxlev, rconf, self.__rng, cg_svsequencer, self.__constgen))
    if self.__opts['condgen_prefer_arridx']:
      cg_eg_l.prefer_arridx_to_arrofs(True)
      cg_eg_r.prefer_arridx_to_arrofs(True)
    def _mkwaves(max_n):
      coeffs = RandomSinWaveCoeff(rng=self.__rng)
      return adjust_sinwaves(coeffs, num_if_trues+num_if_falses, max_n, True, True, None)
    _wavesL = _mkwaves(cg_eg_l.bijective_eg.max_n())
    _wavesR = _mkwaves(cg_eg_r.bijective_eg.max_n())
    cg_eg_l.set(_wavesL)
    cg_eg_r.set(_wavesR)
    self.__condgen = CondGen(CondGenFuncs(), cg_eg_l, cg_eg_r,
                             self.__constgen, self.__rng, autocheck_enabled=False)  # WHY?
    # setup assiggen
    ag_l_svsequencer = SingleValueSequencerFromVRPicker(UsePurpose.WRITE, self.__vrpicker, self.__varstor.vls)
    ag_r_svsequencer = SingleValueSequencerFromVRPicker(UsePurpose.READ, self.__vrpicker, self.__varstor.vls)
    ag_r_exprgen = ExprGenFactory('random').create_expr_gen(
      4, eg_default_opts('random'), self.__rng, ag_r_svsequencer, self.__constgen
    )
    if self.__opts['condgen_prefer_arridx']:
      ag_r_exprgen.prefer_arridx_to_arrofs(True)
    self.__assiggen = AssigGen(ag_l_svsequencer, ag_r_exprgen, self.__rng, True)

  def enable_add_eval_comment(self, enable: bool):
    self._add_eval_comment = enable

  def check_done(self):
    super().check_done()

  def fn_line(self, node:Node) -> List[Node]:            ### REPLACER: node_line ###
    mac = parsemac(node.props['line'])
    assert(mac)
    if mac[0] == 'not_reached':
      # mechanism `dbgbreak_elses`
      return [node_line('DebugBreak(/*NOTREACHED2*/)')]
    if mac[0] == 'block_bef' or mac[0] == 'block_aft':
      newnodes = []
      if self.__flow == Flow.NOT_EXEC and self.__opts['dbgbreak_notreached']:
        # mechanism `dbgbreak_notreached`
        newnodes += [node_line('DebugBreak(/*NOTREACHED1*/)')]
      if self.__opts['trash_stmts']:
        newnodes += self.__make_trash_stmts()
      return newnodes
    elif mac[0] == 'roleact':
      _, nrole, swkey, nact = mac
      nrole, nact = int(nrole), int(nact)
      if swkey == '':
        swkey = None
      else:
        swkey = int(swkey)
      return self.__handle_roleact(nrole, swkey, nact)
    else:
      raise RuntimeError(f'unknown {mac=}')

  # This routine modifies (replaces replers (_f, etc.) using line_behind_getter/setter AND returns
  # role's node_line for PX_LX node (inserted by RoleGen with a help of
  # spraygen's fn_create_pxlx_line_node).
  # Returned node_line object is the object from roles, not a copy.
  def __handle_roleact(self, nrole, swkey, nact):
    # this functionality is also in RoleActExpander
    act_node = self.__roles[nrole].switchdict[swkey][nact]
    pick_history = []
    if act_node.typ == NT.Line:
      if 'line_behind_getter' in act_node.props:
        # This line node has special way of modifying line contents. I'll double the comments here so we won't spend anymore time on this hell. You see, act_node.props['line'] (the default storage for line contents) will contain PX_LX + comment which is a line from spraytab. We change line in spraytab by calling setter. We don't touch the act_node.props['line']. It will be updated by spraygen.
        # Moreover, there is a rhpxlx_inline mode in spraygen which changes the mentioned behavior so [in this mode] the act_node.props['line'] will have inlined line from spraytab without PX_LX macro. Spraygen handles both cases with the scheme that FG writes to spraytab and then the spraytab are postprocessed.        # So we don't change act_node.props['line']. We only change the line behind (which is spraytab's line).
        new_line = self.__replace_replers(act_node.props['line_behind_getter'](), pick_history)
        act_node.props['line_behind_setter'](new_line)
      else:
        # Modify line at place (in role act, e.g. in roles)
        new_line = self.__replace_replers(act_node.props['line'], pick_history)
        act_node.props['line'] = new_line
    assert (len(pick_history) == 0)#TODO: commit pick history
    return [act_node]

  def __replace_replers(self, line:str, pick_history) -> str:
    line = line.replace('/*%hi_dear_fg*/', '/*HI_DEAR_ALL!IT_WORKS!*/')
    #repl_result = self.__replers_replacer.replace_in(line, pick_history)
    #assert(type(repl_result) in [str, NameBindString])
    new_line = line
    return new_line

  def __make_trash_stmts(self) -> List[Node]:
    # Just demo. Program will fail.
    stmts = []
    for i in range(self.__rng.choice([1, 2, 3])):
      pick_history = []
      assig_stmt = self.__assiggen.gen_assig(pick_history)
      for use_purpose, rangeloc in pick_history:
        self.__vrpicker.commit_picked_value_range(use_purpose, rangeloc)
      stmts.append(assig_stmt)
    return stmts


  # Go into if that has expr of type node_line
  def __handle_if_lineexpr(self, ifnod):
    # The .expr of |ifnod| is node_line. Parse it and handle it.
    condline = ifnod.children[0].props['line']
    mac = parsemac(condline)

    condgen_log_strings = None
    if self.__opts['condgen_logging']:
      condgen_log_strings = []

    if mac[0] == 'true':

      truthness = None
      if self.__flow == Flow.EXEC or self.__flow == Flow.MAYBE:
        truthness = True

      cond = self.__generate_cond(truthness, condgen_log_strings)  # NT.RelOp
      self._ncond += 1

      if self.__flow == Flow.EXEC:
        new_flow = Flow.EXEC
      else:
        # MAYBE,NOT
        new_flow = self.__flow

      ifnod.comment = '// True'

    elif mac[0] == 'false':

      truthness = None
      if self.__flow == Flow.EXEC or self.__flow == Flow.MAYBE:
        truthness = False

      cond = self.__generate_cond(truthness, condgen_log_strings)  # gen logic expr
      self._ncond += 1

      new_flow = Flow.NOT_EXEC
      ifnod.comment = f'// False'

    elif mac[0] == 'rolecond':

      assert (self.__flow == Flow.EXEC)
      nrol, swkey = int(mac[1]), int(mac[2])

      # INSERT <expr> == <switchval> FOR ROLE (ALTERNATIVE: switch-case mode)
      swacts = self.__roles[nrol].switchdict[swkey]
      if self.__roles[nrol].expr != None and swkey != None:
        cond = node_relop('==', self.__roles[nrol].expr, node_const(swkey))
      else:
        # insert always true
        cond = node_const(1)
      self._ncond += 1

      new_flow = Flow.MAYBE
      ifnod.comment = f'// Role {nrol} swkey {swkey}'

    elif mac[0] == 'role_impl':
      raise RuntimeError("cannot be")
    else:
      raise RuntimeError(f'bad <if> condition macro - {condline}')

    ifnod.comment = f'// ncond {self._ncond - 1} ' + ifnod.comment
    if self._add_eval_comment:
      assert (cond.typ == NT.RelOp)
      ev = Evaluator()
      node_a, node_b = cond.children
      mi_a = ev.visit(node_a)
      mi_b = ev.visit(node_b)
      ifnod.comment += f'//< ({mi_a.value:x} == {mi_b.value:x})'
    if condgen_log_strings != None:
      ifnod.comment += '\n' + ('\n'.join(['//'+l for l in condgen_log_strings]))

    # replace line condition to real node
    ifnod.children[0] = cond
    old_flow = self.__flow

    self.__flow = new_flow
    self.visit(ifnod.children[1])  # recursion # true_stmtlist
    self.__flow = old_flow

    ####### ELSE #######
    if ifnod.children[2]:  # else_stmtlist
      ### Visit else block ###
      # invert
      if mac[0] == 'true':
        # was true, else = false
        # -> NOT_EXEC always
        new_flow = Flow.NOT_EXEC
        # comment the else statement list
        ifnod.children[2].comment = f'// True\'s else'
      elif mac[0] == 'false':
        # was false, else = true
        # -> EXEC, but only if we were EXEC
        new_flow = Flow.EXEC if self.__flow == Flow.EXEC else self.__flow
        ifnod.children[2].comment = f'// False\'s else'
      elif mac[0] == 'rolecond':
        # EXEC -> MAYBE, but only if we were EXEC
        new_flow = Flow.MAYBE if self.__flow == Flow.EXEC else self.__flow
        ifnod.children[2].comment = f'// Role\'s else'
      else:
        raise RuntimeError()

      old_flow = self.__flow
      self.__flow = new_flow

      self.visit(ifnod.children[2])  # recursion # else_stmtlist

      self.__flow = old_flow
    # end of `else` stmtlist processing
    return

  def fn_if(self, ifnod:Node) -> List[Node]:             ### REPLACER: node_if ###
    if ifnod.children[0].typ == NT.Line:
      # we met node_line in if's .expr; process it
      self.__handle_if_lineexpr(ifnod)
    else:
      # some unknown type if if, we still need to maintain recursion, go into this if without any actions
      self.visit(ifnod.children[1])  # recursion # true_stmtlist
      if ifnod.children[2]:  # else_stmtlist
        self.visit(ifnod.children[2])  # recursion # else_stmtlist


  def __fn_isgood_r(self, loc:Tuple[int, int, int]) -> bool:
    # The check for a cell to be initialized is also in VRPicker; but we need to keep
    # this check since VRPicker's state goes wrong with new demo code; because W vars
    # used in dizzy assigs are commited to state, however they don't have real values in vls
    return self.__is_integer_var(loc) and self.__varstor.vls[loc[0]][loc[1]].is_elem_init(loc[2])

  def __fn_isgood_w(self, loc:Tuple[int, int, int]) -> bool:
    return self.__is_integer_var(loc)

  def __is_integer_var(self, loc:Tuple[int, int, int]):
    vt = self.__varstor.vls[loc[0]][loc[1]].typ
    return vt in integer_var_types


  def __generate_cond(self, truthness, condgen_log_strings:List[str]=None):
    if condgen_log_strings != None:
      def list_appender(_lst, title, msg):
        _lst += [title + ': '+ msg]
      self.__condgen.set_logfn(partial(list_appender, condgen_log_strings, 'cg'))
      # special temporary textualizer for condgen logging
      texer = Textualizer(fn_getvarname=lambda v: str(v))
      self.__condgen.evaler.set_logging(texer, partial(list_appender, condgen_log_strings, 'cg_evaler'))

    # fn_isgood_r, fn_isgood_w may be executed
    self.__condgen.set_thruthness(truthness)
    pick_history = []
    ret_cond = self.__condgen.gen_cond(pick_history)
    for use_purpose, range_loc in pick_history:
      self.__vrpicker.commit_picked_value_range(use_purpose, range_loc)

    return ret_cond



