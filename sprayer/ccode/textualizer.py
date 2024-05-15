from c2.sprayer.ccode.node import *
from c2.sprayer.ccode.name_bind_string import NameBindString, eval_name_bind_string


class Textualizer(NodeVisitor):
  def __init__(self, fn_getvarname=None, tabs=0, comments=True, tabchar='  ', no_root_braces=True):
    super().__init__()
    self.tabs = tabs # feel free to change
    self.comments = comments # feel free to change
    self.tabchar = tabchar # feel free to change
    self.no_braces = no_root_braces

    self.__fn_getvarname = fn_getvarname
    self._notabs = False

    F = False
    self.fn_nop = lambda node: f'{self._t()}__noop'
    self.fn_var = lambda node: self._t()+self.__fn_getvarname(node.props['v']) # var name
    self.fn_arrofs = lambda node: f'{self._t(F)}AT({self.visit(node.children[0])}, {self.visit(node.children[1])})' # var_node, byteofs_node
    #self.fn_const = lambda node: f'{self._t()}0x{node.props["integer"]:x}'
    self.fn_op_plus = lambda node: f'{self._t(F)}({self.visit(node.children[0])} + {self.visit(node.children[1])})'
    self.fn_op_minus = lambda node: f'{self._t(F)}({self.visit(node.children[0])} - {self.visit(node.children[1])})'
    self.fn_op_mul = lambda node: f'{self._t(F)}({self.visit(node.children[0])} * {self.visit(node.children[1])})'
    #self.fn_line = lambda node: f'{self._t()}{node.props["line"]}' # now complex management
    self.fn_relop_greater = lambda node: f'{self._t(F)}{self.visit(node.children[0])} > {self.visit(node.children[1])}'
    self.fn_relop_less = lambda node: f'{self._t(F)}{self.visit(node.children[0])} < {self.visit(node.children[1])}'
    self.fn_relop_greater_eq = lambda node: f'{self._t(F)}{self.visit(node.children[0])} >= {self.visit(node.children[1])}'
    self.fn_relop_less_eq = lambda node: f'{self._t(F)}{self.visit(node.children[0])} <= {self.visit(node.children[1])}'
    self.fn_relop_eq = lambda node: f'{self._t(F)}{self.visit(node.children[0])} == {self.visit(node.children[1])}'
    self.fn_relop_neq = lambda node: f'{self._t(F)}{self.visit(node.children[0])} != {self.visit(node.children[1])}'
    self.fn_assig_eq = lambda node: f'{self._t(F)}{self.visit(node.children[0])} = {self.visit(node.children[1])}' # L, R
    self.fn_assig_incr = lambda node: f'{self._t(F)}{self.visit(node.children[0])}++'
    self.fn_assig_decr = lambda node: f'{self._t(F)}{self.visit(node.children[0]())}++'
    self.fn_call = lambda node: f'{self._t(F)}{node.props["callid"]}({  ",".join([self.visit(arg) for arg in node.children])   })' # callargs

    self.fn_arridx = lambda node: f'{self._t(F)}{self.visit(node.children[0])}[{self.visit(node.children[1])}]' # var_node, idx_node
    self.fn_reference = lambda node: f'{self._t(F)}&{self.visit(node.children[0])}'

    self._slist_once_notab = False
    self._slist_once_cmnt = ''

  def fn_const(self, node):
    if node.props['is64bit']:
      return f'{self._t()}0x{node.props["integer"]:x}ull' # 0xAAAull format
    else:
      return f'{self._t()}0x{node.props["integer"]:x}'

  def fn_line(self, node):
    if type(node.props['line']) == NameBindString:
      evaled = eval_name_bind_string(node.props["line"].eval(self.__fn_getvarname))
      return f'{self._t()}{evaled}'
    elif type(node.props['line']) == str:
      return f'{self._t()}{node.props["line"]}'
    else:
      raise RuntimeError()

  def fn_stmt_list(self, stmtlist_node:node_stmtlist):
    o = ''
    oldflag = self._notabs

    first_comment = stmtlist_node.comment

    _tb = self._t() if not self._slist_once_notab else ''
    if not self.no_braces or self.cur_block_level > 0:
      o += f'{_tb}{{{self._slist_once_cmnt}\n'

    self._slist_once_cmnt = ''
    self._slist_once_notab = False

    for stmt in stmtlist_node.children:
      if stmt.typ == NT.If or stmt.typ == NT.For or stmt.typ == NT.While or not stmt.comment:
        # this node type(s) handle(s) their comments themselves
        cmnt = ''
      else:
        # ---
        cmnt = f' {stmt.comment}'

      self.cur_block_level += 1 # we hooked Visitor.fn_stmt_list so we should do this

      # Start stmtlist from the comment, tabulate to children
      if first_comment:
        o += self._t() + first_comment + '\n'
        first_comment = None

      o += f'{self.visit(stmt)};{cmnt}\n'
      self.cur_block_level -= 1

      self._t(True) # ENABLE tabs again

      pass

    self._notabs = oldflag

    if not self.no_braces or self.cur_block_level > 0:
      o += f'{self._t()}}}'

    return o

  def fn_if(self, if_node):
    t = self._t(False)
    cmnt = ' '+if_node.comment if self.comments and if_node.comment != None else ''
    condtext = self.visit(if_node.children[0]) # cond
    self._t(True)
    #o = f'{t}if ({condtext}) {{{cmnt}\n'
    o = f'{t}if ({condtext}) '

    self._slist_once_notab = True
    self._slist_once_cmnt = cmnt

    if if_node.children[1] != None: # true_stmtlist
      o += self.visit(if_node.children[1]) # true_stmtlist

    # add else block if present
    if if_node.children[2] != None: # else_stmtlist
      o += f'\n{t}else '

      self._slist_once_notab = True
      #self._slist_once_cmnt = cmnt # else have no comment, use stmtlist's first stmt comment

      if if_node.children[2] != []: # else_stmtlist
        o += self.visit(if_node.children[2]) # else_stmtlist

    return o

  def fn_for(self, for_node):
    t = self._t(False)
    cmnt = ' '+for_node.comment if self.comments and for_node.comment != None else ''
    #self._notabs = True
    t_loopvar = self.visit(for_node.children[0]) # loopvar
    t_startval = self.visit(for_node.children[1]) # startval
    t_cond = self.visit(for_node.children[2]) # cond
    t_assig = self.visit(for_node.children[3]) # assig
    #self._notabs = False
    self._t(True)
    o = f'{t}for ({t_loopvar}={t_startval}; {t_cond}; {t_assig}) '

    self._slist_once_notab = True
    self._slist_once_cmnt = cmnt

    if for_node.children[4] != []: # stmtlist
      o += self.visit(for_node.children[4])

    return o

  def fn_while(self, while_node):
    cmnt = ' '+while_node.comment if self.comments and while_node.comment != None else ''
    t = self._t(False)
    #self._notabs = True
    t_cond = self.visit(while_node.children[0]) # cond
    self._t(True)
    o = f'{t}while ({t_cond}) '

    self._slist_once_notab = True
    self._slist_once_cmnt = cmnt

    if while_node.children[1]: # stmtlist
      o += self.visit(while_node.children[1]) # stmtlist

    return o

  def _t(self, change_to=None):
    if self._notabs:
      r = ''
    else:
      r = self.tabchar*(self.tabs + self.cur_block_level)
    if change_to != None:
      self._notabs = not change_to
    return r
