import sys

from .node import *
from .machine_int import *
from .var import *

#TODO: ensure_all_set


class Evaluator(NodeVisitor):
  def __init__(self, callmgr=None):
    super().__init__()
    self.callmgr = callmgr
    self.fn_stmt_list = self._fn_not_supported
    self.fn_if = self._fn_not_supported
    self.fn_for = self._fn_not_supported
    self.fn_while = self._fn_not_supported
    self.fn_line = self._fn_not_supported
    # we could evaluate assigs as 'old' value (before =, +=, =-), but we just forbid them for simplicity
    self.fn_assig_eq = self._fn_not_supported
    self.fn_assig_incr = self._fn_not_supported
    self.fn_assig_decr = self._fn_not_supported

    self._logtexer = None
    self._logfn = None

  def set_logging(self, logtexer, logfn):
    self._logtexer = logtexer
    self._logfn = logfn

  # hook super's visit behavior to add logging
  def visit(self, node):
    result = super().visit(node)
    if self._logfn:
      assert(self._logtexer)
      text = self._logtexer.visit(node)
      self._logfn(f'// ({type(result).__name__}) {text} == 0x{result.value:x}')
    return result

  def fn_op_plus(self, node):
    return self._do_op('+', node)
  def fn_op_minus(self, node):
    return self._do_op('-', node)
  def fn_op_mul(self, node):
     return self._do_op('*', node)
  def fn_relop_greater(self, node):
    return self._do_relop('>', node)
  def fn_relop_less(self, node):
    return self._do_relop('<', node)
  def fn_relop_greater_eq(self, node):
    return self._do_relop('>=', node)
  def fn_relop_less_eq(self, node):
    return self._do_relop('<=', node)
  def fn_relop_eq(self, node):
    return self._do_relop('==', node)
  def fn_relop_neq(self, node):
   return self._do_relop('!=', node)

  def _do_op(self, op, node):
    assert(op in op_codes)
    evalA = self.visit(node.children[0]) # A
    evalB = self.visit(node.children[1]) # B
    rettyp = self._select_type(type(evalA), type(evalB))
    if op == '+':
      ret = rettyp(0).assign(evalA).add(evalB)
    elif op == '-':
      ret = rettyp(0).assign(evalA).sub(evalB)
    elif op == '*':
      ret = rettyp(0).assign(evalA).mul(evalB)
    else:
      raise RuntimeError('bad op')
    assert(issubclass(type(ret), MachineInteger))
    return ret

  def fn_var(self, node):
    # just var, not a child of arrofs, return value
    v = node.props['v']
    assert(v.valcount() == 1 and len(v.values) == 1)
    ret = v.values[0]
    assert(type(ret) == int)
    return type_classes[v.typ](ret) # return MachineInt

  def fn_arrofs(self, node):
    #assert(node.children[1].typ in integer_var_types) # byteofs_node #NT.Const, not integer_var_types! Comment it out!
    v = node.children[0].props['v'] # var_node; don't visit it, we don't want value
    byteofs  = self.visit(node.children[1]) # byteofs_node
    typsiz = type_classes[v.typ].byte_size
    assert(byteofs.value % typsiz == 0)
    idx = byteofs.value // typsiz
    if not v.is_elem_init(idx):
      raise RuntimeError(f'unevaluatable fn_arrofs: uninitialized element {idx} for var {v}')
    value = v.values[idx]
    assert(type(value) == int)
    return type_classes[v.typ](value) # wrap int value into INT32, UINT32, etc.

  def fn_arridx(self, node):
    v = node.children[0].props['v'] # var_node; don't visit it, we don't want value
    #
    # no need for bytesize calculations
    #
    idxnode  = self.visit(node.children[1])
    idx = idxnode.value
    if not v.is_elem_init(idx):
      raise RuntimeError(f'unevaluatable fn_arridx: uninitialized element {idx} for var {v}')
    value = v.values[idx]
    assert(type(value) == int)
    return type_classes[v.typ](value) # wrap int value into INT32, UINT32, etc.

  def fn_const(self, node):
    # apply C rules for consts
    return self._wrap_const(node.props['integer'])

  def fn_call(self, node):
    # TODO
    evaled_args = [self.visit(arg) for arg in node.callargs]
    return node_const(0x12345678)
    return self.callmgr.exec_call(node.callid, evaled_args)


  # returns 1 or 0 if logic condition is TRUE or FALSE
  def _do_relop(self, relop, node):
    # return int32: 1 or 0
    evalA = self.visit(node.children[0]) # A
    evalB = self.visit(node.children[1]) # B
    TRUE, FALSE = INT32(1), INT32(0)
    if relop == '>':
      return TRUE if evalA.value > evalB.value else FALSE
    elif relop == '<':
      return TRUE if evalA.value < evalB.value else FALSE
    elif relop == '>=':
      return TRUE if evalA.value >= evalB.value else FALSE
    elif relop == '<=':
      return TRUE if evalA.value <= evalB.value else FALSE
    elif relop == '==':
      return TRUE if evalA.value == evalB.value else FALSE
    elif relop == '!=':
      return TRUE if evalA.value != evalB.value else FALSE
    else:
      raise RuntimeError('unknown relop')

  def _wrap_const(self, val: int):
    if val < INT32.first_signed():
      return INT32(val)
    if val <= INT32.max():
      return UINT32(val)
    if val < INT64.first_signed():
      return INT64(val)
    assert (val <= UINT64.max())
    return UINT64(val)

  def _select_type(self, typeA, typeB):
    # (int)5 - (unsigned char)9
    # (unsigned int)0 - (short)5
    # returned type is a type of larger operand
    tA, tB = typeA, typeB
    if tA.byte_size > tB.byte_size:
      rettyp = tA
    elif tA.byte_size < tB.byte_size:
      rettyp = tB
    else:
      # if operands are same size, unsigned wins
      assert (tA.byte_size == tB.byte_size)
      if not tA.is_signed:
        rettyp = tA
      elif not tB.is_signed:
        rettyp = tB
      else:  # both types are signed
        rettyp = tA
    # force INT32 if smaller
    if rettyp.byte_size < INT32.byte_size:
      rettyp = INT32
    return rettyp

  def _fn_not_supported(self, node):
    raise RuntimeError()



def test_ccode_evaluator(argv):
  v1 = Var(VT.i32, [0xfc66ecfd])
  v2 = Var(VT.u64, [0x150cdca7ef417c78])
  n = node_op('-', node_var(v1), node_var(v2))
  print(f'{Evaluator().visit(n).value:x}')

  n = node_op('-', node_const(0xfc66ecfd), node_const(0x150cdca7ef417c78))
  print(f'{Evaluator().visit(n).value:x}')


if __name__ == '__main__':
  test_ccode_evaluator(sys.argv[1:])



