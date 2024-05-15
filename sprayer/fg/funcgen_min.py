from typing import List
from c2.sprayer.fg.funcgen import FuncGen
from c2.sprayer.fg.func_ast import FuncAST
from c2.sprayer.fg.var_storage import VarStorage
from c2.sprayer.misc.role import Role
from c2.sprayer.ccode.node import Node, NT, node_stmtlist, node_if, node_relop, node_const


class FuncGenMin(FuncGen):
  def configure(self, func_ast:FuncAST, roles:List[Role], varstor:VarStorage, fgmin_opts, rng) -> None:
    super().configure(func_ast, roles, varstor, fgmin_opts, rng)
    # IGNORED: varstor, rng
    self._proceed_to_next_stage(self.__st_all, 'all in one')


  def __st_all(self):
    self._func_ast.stmtlist = node_stmtlist()
    roles = self._roles
    for nrole in range(len(roles)):
      role = roles[nrole]
      if role.expr != None:
        # conditional role
        #for switchval, acts in role.switchtups:
        for swkey in role.switchdict.keys():
          role_acts = role.switchdict[swkey]  # acts -> [node_line(), node_line(), ]

          assert(type(role_acts) == list)
          #assert(type(acts[0]) == str) # Why? no! it's Node! what the fuck is this assert

          self.__example_edit_spraytab_lines(role_acts)

          exprnode = node_relop('==', role.expr, node_const(swkey))
          ifnode = node_if(exprnode, node_stmtlist(role_acts))
          ifnode.comment = f'// role {nrole}'

          self._func_ast.stmtlist.children.append(ifnode)
        pass
      else:
        # unconditional role (role.expr == None)
        assert(len(role.switchdict) == 1) # len(role.switchdict)
        assert(len(role.switchdict) == 1)
        role_acts = list(role.switchdict.items())[0][1]

        self.__example_edit_spraytab_lines(role_acts)

        self._func_ast.stmtlist.children += role_acts
      pass

    self._proceed_to_next_stage(None, None) # we're done
    return


  def __example_edit_spraytab_lines(self, role_acts):
    for act in role_acts:
      assert (type(act) == Node)
      if act.typ == NT.Line:
        if 'line_behind_getter' in act.props:
          # handle  /*%commands*/ and  _zX()es
          assert('line_behind_setter' in act.props)

          def expand_line_todo(old_line):
            rs = old_line.replace('_zk()', '_ZK(TODO)')
            rs = rs.replace('/*%hi_dear_fg*/', '/*hi_from_fg_dear_user*/')
            return rs

          #new_line = expand_line_todo(act.props['line_behind'])
          getter = act.props['line_behind_getter']
          cur_line = getter()
          new_line = expand_line_todo(cur_line)

          act.props['line_behind_setter'](new_line)
    return

