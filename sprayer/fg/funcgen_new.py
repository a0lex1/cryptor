from c2.sprayer.fg.funcgen import FuncGen, FuncAST
from c2.sprayer.fg.funcgen_debug_helpers import FuncGenAstDebugHelpers
from c2.sprayer.fg._skel import Skel, SkelFillerNew, RolesShape
from c2.sprayer.fg._pseudocode_generator import PseudocodeGenerator
from c2.sprayer.fg._dbgbreak_else_adder import DbgBreakElseAdder
from c2.sprayer.fg._new_finalizer import NewFinalizer
from c2.sprayer.gens.nid_dfs import NIDDfsOrderChecker
from c2.sprayer.gens.multishoulder_tree_gen import MultishoulderTreeGen
from c2.sprayer.ccode.node import node_stmtlist
from c2.common.sx import Sx


# FuncGenNew is added after development of FuncGenWAround is stopped (cuz current SkelFiller doesn't maintain role order)
class FuncGenNew(FuncGen, FuncGenAstDebugHelpers):
  def configure(self, *args, **kwargs) -> None:
    super().configure(*args, **kwargs)
    self._do_debug_checks = True
    self._proceed_to_next_stage(self.__st_gen_shoulder_tree, 'gen shoulder tree')

  def __st_gen_shoulder_tree(self):
    fgnew_opts = self._opts
    # Create roles shape
    self.__roles_shape = RolesShape(self._roles)
    # And generate multishoulder tree for it
    shouldergen = MultishoulderTreeGen(self._rng)
    # #ShouldersAreSwitchkeys
    shouldergen.set_number_of_shoulders(self.__roles_shape.total_switchkeys())
    avg_nodes4branch = Sx(fgnew_opts['avg_nodes_for_branch_sx'], self._rng).make_number()
    num_nodes2distribute = avg_nodes4branch * shouldergen.get_number_of_shoulders()
    shouldergen.set_number_of_nodes_to_distribute(num_nodes2distribute) # ... between shoulder nodes (e.g. not including shoulder nodes)
    shouldergen.set_scatter_percent(50)
    shouldergen.do_gen()
    self.__G = shouldergen.G
    if self._do_debug_checks:
      checker = NIDDfsOrderChecker(self.__G)
      checker.do_check()
      if not checker.result:
        raise RuntimeError(f'MultishoulderTreeGen returned a graph that is not nid-dfs ordered {checker.result=} {checker.stop_nid=}')
    self._proceed_to_next_stage(self.__st_fill_shoulder_tree, 'fill shoulder tree')
    
  def __st_fill_shoulder_tree(self):
    self._skeldata = {}
    self._skel = Skel(self.__G, 0, None)
    self._skel.locate_next_nid()
    roles_shape = RolesShape(self._roles)
    skelfiller = SkelFillerNew(self._skeldata, self._skel, roles_shape, self._rng)
    skelfiller.init_skeldata()
    skelfiller.place_roles_method_a()  #TODO: method B
    #skelfiller.remove_unused_branches() ######## TODO: develop it
    skelfiller.swap_unordered_roleacts()
    skelfiller.merge_elses()
    #skelfiller.place_loops() ########## TODO: develop it##########################################
    skelfiller.fill_unused_nodes()
    ###
    self._proceed_to_next_stage(self.__st_create_ast, 'create ast')

  def __st_create_ast(self):
    self._func_ast.stmtlist = node_stmtlist()
    self.__pcgen = PseudocodeGenerator(self._func_ast.stmtlist, self._skel, self._skeldata)
    self.__pcgen.skelgraph2ast()
    #self._proceed(self.__st_act_expand, 'pseudo - act expand')
    self._proceed_to_next_stage(self.__st_manipulate_ast, 'manipulate ast')

  def __st_manipulate_ast(self):
    if self._opts['dbgbreak_elses']:
      # Two different mechanisms (can be combined):
      #   dbgbreak_notreached (ONLY at Flow.NOT, doesn't add monitoring for NOT entering @true@ if(s))
      #   dbgbreak_elses (to BOTH @true@'s else(s) and @false@ bodie(s))
      eadder = DbgBreakElseAdder()
      eadder.visit(self._func_ast.stmtlist)
    self._proceed_to_next_stage(self.__st_finalize_ast, 'finalize ast')

  def __st_finalize_ast(self):
    self.__wafinalizer = NewFinalizer(self._opts, self._varstor, self._roles, self._rng)
    # self.__wafinalizer.enable_add_eval_comment(True) #if RoleGen returns node_lines, comment this line (their evaluation will lead to exception)
    self.__wafinalizer.create_objects(self.__pcgen.num_if_trues, self.__pcgen.num_if_falses)
    self.__wafinalizer.visit(self._func_ast.stmtlist)
    self.__wafinalizer.check_done()
    self._proceed_to_next_stage(None, None)  # we're done

  #def __reassign_nids(self): # not needed yet, a stub for future
  #  reassigner = NIDReassignerDfs(self.__skel.G, self.__skel.root_nid)
  #  # currently we store the same G in two fields, update them
  #  self.__skel.G = reassigner.output_G_tree
  #  self.__G = reassigner.output_G_tree
  #  # update self._skeldata
  #  self.__apply_nid_remap(reassigner.output_remap_table)

  ### FuncGenAstDebugHelpers impl
  def _get_func_ast(self) -> FuncAST:
    return self._func_ast










