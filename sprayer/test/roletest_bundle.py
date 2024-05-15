import sys

from c2.sprayer.ccode.node import Node, node_nop, node_assig, node_line, node_const, node_while, node_stmtlist, node_var
from c2.sprayer.ccode.var import Var, VT
from c2.sprayer.ccode.textualizer import Textualizer
from c2.sprayer.misc.role import Role


class RoletestBundle:
  def __init__(self):
    pass
  def get_globvardef(self) -> list:
    raise
  def get_roles(self) -> list:
    raise
  def get_checkcode(self) -> Node:
    raise


### TODO: add _f,_fk,etc testing roles

class BasicRoletestBundle(RoletestBundle):
  def __init__(self, num_roles, wrap_stmtlist, swkeys_before, swkeys_after,
               num_acts, with_while):

    super().__init__()
    self.num_roles = num_roles
    self.wrap_stmtlist = wrap_stmtlist
    self.swkeys_before = swkeys_before
    self.swkeys_after = swkeys_after
    self.num_acts = num_acts
    self.with_while = with_while

    self._coolarg_node = None
    self._cool_value = 0

  def set_cool_arg(self, coolarg_node:Node):
    self._coolarg_node = coolarg_node

  def get_globvardef(self) -> list:
    lines = []
    for nrole in range(self.num_roles):
      for nact in range(self.num_acts):
        lines += [f'static int {self._vmagicname(nrole, nact)} = -1;']
    return lines

  def _vmagicname(self, nrole:int, nact:int):
    return f'g_role{nrole}_{nact}_magic'

  def get_roles(self) -> list:
    assert(self._coolarg_node != None)
    roles = []
    for nrole in range(self.num_roles):
      # TODO: insert NOTREACHED(), not just nops

      # Important that |swt| should be ordered cuz the order of roles goes with the order
      # of execution. In python > 3.x dicts are ordered so it's ok.
      swt = {}
      swt.update({100+_: [node_nop()] for _ in range(self.swkeys_before)})

      acts = []
      for nact in range(self.num_acts):
        acts.append(node_assig('=', node_line(self._vmagicname(nrole, nact)), node_const(nact)))
        #acts.append(node_assig('=', self._coolarg_node, node_const(self._cool_value)))

      #if self.with_while:
      #  acts.append(node_while()) # todo: remake after switchtups->switchdict

      if self.wrap_stmtlist:
        acts = [ node_stmtlist(acts) ]

      swt[ 1 ] = acts #switchval=1, coolarg must be 1
      roles += [Role(self._coolarg_node, swt)] # REAL SWITCHVAL

      # TODO: insert NOTREACHED(), not just nops
      swt.update({100000+_: [node_nop()] for _ in range(self.swkeys_after)})

    return roles

  def get_checkcode(self) -> Node:
    stmtlist = node_stmtlist()
    CMP = 1
    if self.with_while:
      CMP += 5
    for nrole in range(self.num_roles):
      for nact in range(self.num_acts):
        stmtlist.children += [node_line(f'ASSERT({self._vmagicname(nrole, nact)} == {nact})')]
    return stmtlist


def test_BasicRoleTestBundle(argv):
  #num_roles, wrap_stmtlist, swtups_before, swtups_after, with_while):
  bundle = BasicRoletestBundle(3, False, 1, 1, 3, False)
  print('\n'.join(bundle.get_globvardef()), '')
  v = node_var(Var(VT.u32, []))
  bundle.set_cool_arg(v)
  roles = bundle.get_roles()
  for role in roles:
    print(role)
  print(Textualizer().visit(bundle.get_checkcode()))
  pass


if __name__ == '__main__':
  test_BasicRoleTestBundle(sys.argv[1:])



