from c2.sprayer.ccode.evaluator import Evaluator
from c2.sprayer.ccode.node import Node


# You create this object and give it to StmtExecutor. StmtExecutor fills it.
class StmtExecutorUndo:
  def __init__(self):
    self._rollbackvar = None
    self._rollbackvaridx = None
    self._rollbackvalue = None
  def set_var_rollback(self, rollbackvar=None, rollbackidx=None, rollbackvalue=None):
    self._rollbackvar = rollbackvar
    self._rollbackvaridx = rollbackidx
    self._rollbackvalue = rollbackvalue
  def apply(self):
    if self._rollbackvar != None:
      ##############????
      self._rollbackvar.values[self._rollbackvaridx] = self._rollbackvalue


class StmtExecutor:
  def __init__(self, do_gen_check_expr=True):
    self.do_gen_check_expr = do_gen_check_expr
    self.check_expr = None
    self._undo = None


  def set_onetime_undo(self, undo:StmtExecutorUndo):
    self._undo = undo


  def exec_stmt(self, stmt:Node):
    if stmt.typ == NT.Assig:
      self._exec_assig(stmt)

    #elif stmt.typ == NT.Call:
    #  self._exec_call(stmt)  # could be

    elif stmt.typ == NT.Nop:
      pass

    else:
      raise RuntimeError()

    self._undo = None # it was set onetime


  def _exec_assig(self, stmt:Node):
    assert(stmt.props['assigcode'] == '=') # improv: incr, decr
    L, R = stmt.children[0], stmt.children[1]
    assert (type(L) == Node and (L.typ == NT.Var) or L.typ == NT.ArrOfs)

    evaler = Evaluator()

    # EXECUTE (EVALUATE) THE RIGHT SIDE
    evaledR = evaler.visit(R) # MachineInteger
    assert (issubclass(type(evaledR), MachineInteger))


    if L.typ == NT.Var:
      v = L.props['v']
      assert (type(v) == Var)
      assert (v.valcount() > 0)

      #v.values[0] = evaledR.value
      # assign R to L with type cast (pass R through MachineInteger or L byte)
      converted = v.make_class_obj(0).assign(evaledR)

      if self._undo != None:
        self._undo.set_var_rollback(v, 0, v.values[0])
      v.values[0] = converted.value

    elif L.typ == NT.ArrOfs:
      var_node, byteofs_node = L.children
      assert (type(var_node) == Node)
      # STORE NEW VALUE
      v = var_node.props['v']

      assert(v.typ in integer_var_types)

      # EXECUTE (EVALUATE) BYTEOFS NODE (it can be const or complex runtime expr)
      evaledBO = evaler.visit(byteofs_node) # MachineInt
      arrofs = evaledBO.value
      typsiz = type_classes[v.typ].byte_size
      assert(arrofs % typsiz == 0)
      idx = arrofs//typsiz
      # STORE NEW VALUE
      converted = v.make_class_obj(0).assign(evaledR)

      if self._undo != None:
        self._undo.set_var_rollback(v, idx, v.values[idx])
      v.values[idx] = converted.value

    elif L.typ == NT.Brackets:
      #
      #
      # TODO
      #
      #
      pass

    else:
      raise RuntimeError()

    if self.do_gen_check_expr:
      try:
        self.check_expr = node_relop('==', node_var(v), node_const(converted.value))
      except Exception as e:
        print('*** *** Exception during EXPR CHECK *** ***')
        raise
    return


