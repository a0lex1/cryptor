from typing import List

from c2.sprayer.fg.func_ast import FuncAST
from c2.sprayer.fg.var_storage import VarStorage
from c2.sprayer.misc.role import Role
from c2.base.stage_runner import StageRunner


# Important: |roles| may be edited after FuncGen work! don't reuse them!
# To simplify creation, we introduce configure() instead of __init__
#   the content of |opts| depends on type of derived FuncGen
# Can change the contents of |roles|, it will have no effect
# Role impl node_line(s) with 'line_behind_setter' and 'line_behind_getter' props, FuncGen should use it
class FuncGen(StageRunner):
  def configure(self, func_ast:FuncAST, roles:List[Role], varstor:VarStorage, opts:dict, rng) -> None:
    self._func_ast = func_ast
    self._roles = roles
    self._varstor = varstor
    self._opts = opts
    self._rng = rng
  #StageRunner::execute(), etc.

  