from c2.sprayer.rg.rolegen_basic import RoleGenBasic
from c2.sprayer.rg._demonstrate_editing_line import demonstrate_editing_line
from c2.sprayer.misc.role import Role
from c2.sprayer.ccode.node import node_line, node_const


# class RoleGenDumb simply translates procs from spraytab to functions with roles where each line is a role
class RoleGenDumb(RoleGenBasic):
  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)

    spraytab = self.spraytab
    num_procs = len(spraytab['procs'])
    self.spraytab_procidxes = [_ for _ in range(num_procs)]
    self.lvararr = [[] for _ in range(num_procs)]
    # add _xarg to all procs

    # default defs
    self.defs = {'RoleGenDumb': {}}
    self.defs['RoleGenDumb']['_CALL(F)'] = self._make_call_def_for_args(['_xarg', 'RandDW_1'])

    # demonstrate editing line
    demonstrate_editing_line(spraytab)

    self._proceed_to_next_stage(self._st_all_things, 'all actions in one stage')


  # [ [F0_role0, F0_role1, ...], [F1_role0, ...]
  def _st_all_things(self):
    spraytab = self.spraytab
    num_procs = len(spraytab['procs'])

    # self._generate_arglistarr2(num_procs, 0, 3)
    self._generate_arglistarr2(num_procs)

    self.namearr = [f'P{n}' for n in range(num_procs)]

    self.rolearr = []
    self.orig_idxes = [i for i in range(num_procs)]
    # self.defs = {}
    for nproc in range(num_procs):
      procname = spraytab['procs'][nproc]
      proclines = spraytab['lines'][procname]
      numlines = len(proclines)
      roles = []  # roles for proc
      rolelines = []
      for nline in range(numlines):
        #orig_line = spraytab['lines'][procname][nline]
        line_node = self._fn_create_pxlx_line_node(nproc, nline)
        rolelines.append(line_node)

      roles.append(Role(None, {None: rolelines}))
      self.rolearr.append(roles)

    # gen dummy funcs
    for ndumb in range(self._opts['dumb_funcs']):
      swdict = {0: [node_line('__noop'), node_line('// dumb func a1')],
                1: [node_line('__noop'), node_line('// dumb func b1')]}
      self.rolearr.append([Role(node_const(1), swdict)])
      self.arglistarr.append([])
      self.lvararr.append([])
      self.namearr.append(f'DumbFuncByRoleGenDumb{ndumb}')

    self._proceed_to_next_stage(None, None)  # we're done


