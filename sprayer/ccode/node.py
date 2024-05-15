from enum import Enum, auto

from c2.sprayer.ccode.node import *
from c2.sprayer.ccode.var import type_classes


# NodeType
class NT(Enum):
  Nop = auto()
  StmtList = auto()
  Op = auto()
  RelOp = auto()
  Var = auto()
  ArrOfs = auto()
  Const = auto()
  If = auto()
  Line = auto()
  Assig = auto()
  For = auto()
  While = auto()
  Call = auto()
  ArrIdx = auto()
  Reference = auto()


class Node:
  def __init__(self, typ=None, props=None, children=None, comment=None):
    #if typ == NT.Const and not 'is64bit' in props:
    #  breakpoint()
    assert(typ == None or type(typ) == NT)
    self.typ = typ
    if props == None:
      props = {}
    self.props = props
    if children:
      for i in range(len(children)):
        if children[i] != None and not type(children[i]) == Node:
          raise RuntimeError(f'children[{i}] is not instance of Node - {type(children[i])}')
    self.children = children
    self.comment = comment

  def __repr__(self): #broken + too lazy to fix = commented out
    n = len(self.children) if self.children != None else 0
    if self.typ == None:
      typname = ''
    else:
      typname = str(self.typ)
    return f'NODE {typname} ({n} children), props={self.props}'

op_codes = ['+', '-', '*']
relop_codes = ['>', '<', '>=', '<=', '==', '!=']
assig_codes = ['=', '+=', '-=']

# Object creation helpers

def node_nop(comment=None):
  return Node(NT.Nop, {}, [], comment)

def node_stmtlist(statements=None, comment=None):
  if statements == None:
    statements = []
  return Node(NT.StmtList, {}, statements, comment)

def node_op(op_code, A, B, comment=None):
  return Node(NT.Op, {'op_code': op_code}, [A, B], comment)

def node_relop(op_code, A, B, comment=None):
  return Node(NT.RelOp, {'op_code': op_code}, [A, B], comment)

def node_var(v, comment=None):
  return Node(NT.Var, {'v': v}, comment)

def node_arrofs(var_node, byteofs_node):
  return Node(NT.ArrOfs, {}, [var_node, byteofs_node])

def node_const(integer:int, is64bit=False):
  return Node(NT.Const, {'integer': integer, 'is64bit': is64bit}, children=None)

def node_if(cond, true_stmtlist=None, else_stmtlist=None, comment=None):
  if true_stmtlist == None:
    true_stmtlist = node_stmtlist()
  # else_stmtlist can be None if there is no `else` block
  return Node(NT.If, {}, [cond, true_stmtlist, else_stmtlist], comment)

def node_line(line, comment=None):
  return Node(NT.Line, {'line': line}, [], comment)

def node_assig(assigcode, L:Node, R:Node, comment=None):
  return Node(NT.Assig, {'assigcode': assigcode}, [L, R], comment)

def node_for(loopvar, startval, cond, assig, stmtlist, comment=None):
  return Node(NT.For, {}, [loopvar, startval, cond, assig, stmtlist], comment)

def node_while(cond, stmtlist, comment=None):
  return Node(NT.While, {}, [cond, stmtlist], comment)

def node_call(callid, callargs, comment=None):
  return Node(NT.Call, {'callid': callid}, callargs, comment)

def node_arridx(var_node, idx_node):
  return Node(NT.ArrIdx, {}, [var_node, idx_node])

# node_ref( node_var
# node_ref( node_arrofs( node_var(
# node_ref( node_arridx( node_var(
def node_ref(lvalue_node):
  return Node(NT.Reference, {}, [lvalue_node])

### Validation ###

def validate_node(node):
  if node.typ == NT.StmtList:
    # deprecated: stmtlist can't contain other stmtlists
    #for n in node.children:
    #  assert(n.typ != NT.StmtList)
    pass

  elif node.typ == NT.Assig:

    assert(node.props['assigcode'] in assig_codes)
    assert(node.children[0] != None) # A
    if node.props['assigcode'] == '+=' or node.props['assigcode'] == '-=':
      # can't have right side
      assert(node.children[1] == None) # B
    else:
      # must have right side
      assert(node.props['assigcode'] == '=')
      assert(node.children[1] != None) # B

  else:
      # validate for this node type is not implemented
      pass

### Aux ###
def node_var_or_arrofs(v, arridx):
  tbytesize = type_classes[v.typ].byte_size
  if v.is_array():
    return node_arrofs(node_var(v), node_const(arridx * tbytesize))  # arithmetics
  else:
    assert (arridx == 0)
    return node_var(v)

# sometimes we prefer arridx to arrofs (for example, right now it may help debugging)
def node_var_or_arridx(v, arridx):
  tbytesize = type_classes[v.typ].byte_size
  if v.is_array():
    return node_arridx(node_var(v), node_const(arridx))
  else:
    assert (arridx == 0)
    return node_var(v)


### Visitor ###

class NodeVisitor:
  def __init__(self):
    self.cur_block_level = 0 # stmtlist-related thing. probably rename
    self._parent_node_stack = [] # get its len() to find out current
    self._debug_checks = False

  def cur_recursion_level(self):
    return len(self._parent_node_stack)

  def check_done(self):
    assert(self.cur_block_level == 0)

  # the default visit() impl (below) returns what fn_xxx return, but the default
  # impls of fn_xxx(s) returns None. You can write our own fn_xxx(s) that will return something
  # (logical values, etc.). So the default impl of visit() will return those values.
  def visit(self, node):
    validate_node(node)
    t = node.typ
    if self._debug_checks:
      if len(self._parent_node_stack):
        # verify we're are a child of parent if parent exists
        assert(node in self._parent_node_stack[-1].children)
    if t == NT.Nop:
      return self.fn_nop(node)
    elif t == NT.Var:
      return self.fn_var(node)
    elif t == NT.ArrOfs:
      return self.fn_arrofs(node)
    elif t == NT.Const:
      return self.fn_const(node)
    elif t == NT.Op:
      optable = { '+': self.fn_op_plus, '-': self.fn_op_minus, '*': self.fn_op_mul }
      return optable[node.props['op_code']](node)
    elif t == NT.StmtList:
      return self.fn_stmt_list(node)
    elif t == NT.If:
      return self.fn_if(node)
    elif t == NT.For:
      return self.fn_for(node)
    elif t == NT.While:
      return self.fn_while(node)
    elif t == NT.Line:
      return self.fn_line(node)
    elif t == NT.RelOp:
      reloptable = { '>': self.fn_relop_greater, '<': self.fn_relop_less,
                     '>=': self.fn_relop_greater_eq, '<=': self.fn_relop_less_eq,
                     '==': self.fn_relop_eq, '!=': self.fn_relop_neq }
      return reloptable[node.props['op_code']](node)
    elif t == NT.Assig:
      assigtable = { '=': self.fn_assig_eq, '+=': self.fn_assig_incr,
                     '-=': self.fn_assig_decr }
      return assigtable[node.props['assigcode']](node)
    elif t == NT.Call:
      return self.fn_call(node)
    elif t == NT.ArrIdx:
      return  self.fn_arridx(node)
    elif t == NT.Reference:
      return self.fn_reference(node)
    else:
      raise RuntimeError(f'visit: bad node type - {t}')

  def fn_nop(self, node):
    return
  def fn_var(self, node):
    return
  def fn_arrofs(self, node):
    self._parent_node_stack.append(node)
    self.visit(node.children[0]) # v
    self.visit(node.children[1]) # byteofs_node
    self._parent_node_stack.pop()
  def fn_const(self, node):
    return
  def fn_op_plus(self, node):
    self._parent_node_stack.append(node)
    self.visit(node.children[0]) # A
    self.visit(node.children[1]) # B
    self._parent_node_stack.pop()
  def fn_op_minus(self, node):
    self._parent_node_stack.append(node)
    self.visit(node.children[0])
    self.visit(node.children[1])
    self._parent_node_stack.pop()
  def fn_op_mul(self, node):
    self._parent_node_stack.append(node)
    self.visit(node.children[0])
    self.visit(node.children[1])
    self._parent_node_stack.pop()

  def fn_stmt_list(self, node):
    self.cur_block_level += 1
    for nchild in range(len(node.children)):
      self._parent_node_stack.append(node)
      self.visit(node.children[nchild]) # recursion
      self._parent_node_stack.pop()
    self.cur_block_level -= 1

  def fn_if(self, node):
    self._parent_node_stack.append(node)
    self.visit(node.children[0]) # cond
    self.visit(node.children[1]) # true_stmtlist
    if node.children[2]: # else_stmtlist
      self.visit(node.children[2])
    self._parent_node_stack.pop()

  def fn_for(self, node):
    self._parent_node_stack.append(node)
    self.visit(node.children[0]) # loopvar
    self.visit(node.children[1]) # startval
    self.visit(node.children[2]) # code
    self.visit(node.children[3]) # assig
    self.visit(node.children[4]) # stmtlist
    self._parent_node_stack.pop()
  def fn_while(self, node):
    self._parent_node_stack.append(node)
    self.visit(node.children[0]) # cond
    self.visit(node.children[1]) # stmtlist
    self._parent_node_stack.pop()

  def fn_line(self, node):
    return

  def fn_call(self, node):
    return

  def fn_arridx(self, node):
    return

  def fn_reference(self, node):
    return

  def fn_relop_greater(self, node):
    self._parent_node_stack.append(node)
    self.visit(node.children[0])
    self.visit(node.children[1])
    self._parent_node_stack.pop()
  def fn_relop_less(self, node):
    self._parent_node_stack.append(node)
    self.visit(node.children[0])
    self.visit(node.children[1])
    self._parent_node_stack.pop()
  def fn_relop_greater_eq(self, node):
    self._parent_node_stack.append(node)
    self.visit(node.children[0])
    self.visit(node.children[1])
    self._parent_node_stack.pop()
  def fn_relop_less_eq(self, node):
    self._parent_node_stack.append(node)
    self.visit(node.children[0])
    self.visit(node.children[1])
    self._parent_node_stack.pop()
  def fn_relop_eq(self, node):
    self._parent_node_stack.append(node)
    self.visit(node.children[0])
    self.visit(node.children[1])
    self._parent_node_stack.pop()
  def fn_relop_neq(self, node):
    self._parent_node_stack.append(node)
    self.visit(node.children[0])
    self.visit(node.children[1])
    self._parent_node_stack.pop()

  def fn_assig_eq(self, node):
    self._parent_node_stack.append(node)
    self.visit(node.children[0]) # L
    self.visit(node.children[1]) # R
    self._parent_node_stack.pop()
  def fn_assig_incr(self, node):
    raise RuntimeError('todo')
  def fn_assig_decr(self, node):
    raise RuntimeError('todo')

  def fn_unexp(self, node):
    raise RuntimeError()


if __name__ == '__main__':
  n = Node()
  print(str(n))
