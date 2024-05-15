from c2.sprayer.fg._replacing_visitor import ReplacingVisitor
from c2.common.utils import parsemac


class RoleActExpander(ReplacingVisitor):
  def __init__(self, roles):
    super().__init__()
    self.roles = roles

  def fn_line(self, node):
    mac = parsemac(node.props['line'])
    if not mac or mac[0] != 'roleact':
      return
    _, nrole, swkey, nact = mac
    nrole, nact = int(nrole), int(nact)
    if swkey == '':
      swkey = None
    else:
      swkey = int(swkey)
    replacement = [self.roles[nrole].switchdict[swkey][nact]]
    return replacement

