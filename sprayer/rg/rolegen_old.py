import json, re, random, sys, os
import networkx as nx
from typing import Tuple

from c2.graph_factory import GraphFactory
from c2.sprayer.rg.rolegen import RoleGen
from c2.sprayer.rg._demonstrate_editing_line import demonstrate_editing_line
from c2.sprayer.misc.spraytab_utils import is_proc_from_decl, is_proc_from_decl_n
from c2.sprayer.misc.role import Role
from c2.sprayer.ccode.node import *
from c2.sprayer.ccode.var import *
from c2.common.graph import node_color, make_html_color, save_graph


# old role (TODO: move to _crole.py, cuz this is detail)
class _CRole():
  def __init__(self, cond='', callargs='', code='', comment='', spraytab_line_loc:Tuple[int, int]=None):
    self.cond = cond
    self.callargs = callargs
    self.code = code
    self.comment = comment
    self.spraytab_line_loc = spraytab_line_loc


# G will be modified
class RoleGenOld(RoleGen):
  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self._add_flag('graph_changed')

    self.root_nid = None
    self._argcnt1 = self._argcnt3 = 0
    self._roles = {} # old roles, new are in rolearr
    self.rolecnt_entr = {}  # {nid: 5} # TODO: make _private EVERYWHERE
    self.rolecnt_fwd = {}  # {nid: 5}
    self._proc_roots = {}  # {procnum: sg_root}

    # output (new) (class RoleGen)
    self.specific_lines = ['#include <math.h>']
    self.rolearr = []
    self.arglistarr = []
    self.namearr = []
    self.lvararr = []
    self.fixed_var_names = {}
    self.defs = {'RoleGenOld': {}}
    self.spraytab_procidxes = []

    self._entry_a1 = self._rng.randint(0, 0xffffffff)
    self._entry_a2 =  self._rng.randint(0, 0xffffffff)
    self._entry_a3 = self._rng.randint(0, 0xffffffff)
    self.defs['RoleGenOld']['_CALL(F)'] = \
      self._make_call_def_for_args(['_xarg', f'{self._entry_a1}', f'{self._entry_a2}', f'{self._entry_a3}'])
    self._nids_of_fromdecls = []
    self._G = None

    demonstrate_editing_line(self.spraytab)

    self._proceed_to_next_stage(self._st_new_graph, 'initialize graph')


  def _st_new_graph(self):
    self._G = GraphFactory(self._opts['graph'], self._rng).create_graph()
    self._proceed_to_next_stage(self._st_spray_root_proc, 'spray root proc')


  def _st_spray_root_proc(self):
    self._change_flag('graph_changed', True)
    spraytab = self.spraytab
    G = self._G
    G.remove_edges_from([edge for edge in nx.selfloop_edges(G)])
    G.remove_nodes_from([nid for nid in nx.isolates(G)])

    self.root_nid = self._find_root_nid()

    proc_roots = self._proc_roots
    ## spray root proc on root node (and remember it's sprayed)
    rootproc_idx = spraytab['procs'].index(spraytab['root_proc'])
    if not self._try_spray_some_proc(self.root_nid, [rootproc_idx]):  # allow P0 to spray
      raise RuntimeError('can\'t spray root_proc at root node')
    assert (list(self._proc_roots.keys()) == [rootproc_idx])
    #pcount = 1
    self._proceed_to_next_stage(self._st_spray_other_procs, 'spray other procs')

  def _st_spray_other_procs(self):
    self._change_flag('graph_changed', True)
    G = self._G
    spraytab = self.spraytab
    proc_roots = self._proc_roots

    all_nodes = [nid for nid in G.nodes if nid != self.root_nid]
    if self._opts['do_optimize']:
      # deterministic (optimizing) mode: try from the greatest parent (max. number of child nodes)
      all_nodes = sorted(all_nodes, key=lambda nid: len(list(G.successors(nid))), reverse=True)
    else:
      # random mode
      random.shuffle(all_nodes)
    num_need_procs = len(spraytab['lines'])
    for cur_node in all_nodes:
      if len(proc_roots) == num_need_procs:
        break
      if cur_node in proc_roots.values():
        # already used
        continue
      if self._try_spray_some_proc(cur_node, None):
        # lucky, proc was sprayed
        pass
    if len(proc_roots) != num_need_procs:
      raise RuntimeError(f'not enough nodes in call graph, only {len(proc_roots)}/{num_need_procs} roots sprayed')
    # all lines sprayed
    self._proceed_to_next_stage(self._st_name_functions, 'name functions')

  def _st_name_functions(self):
    self._change_flag('graph_changed', True)
    fid = 0
    G = self._G
    for nid in G.nodes:
      node = G.nodes[nid]
      if not 'funcname' in node:
        node['funcname'] = f'F{fid}'
        fid += 1
    self._fix_labels()
    self._proceed_to_next_stage(self._st_add_call_flow_calls, 'add call flow calls')

  def _st_add_call_flow_calls(self):
    # graph not changed
    G = self._G
    roles = self._roles
    for from_nid in G.nodes:
      for suc_nid in G.successors(from_nid):
        suc_node = G.nodes[suc_nid]
        if nx.has_path(G, suc_nid, from_nid):
          # recursion; place code that never executes ###fake role
          a1, a2, a3 = self._rng.randint(0xfffff, 0xffffffff),self._rng.randint(0xfffff, 0xffffffff), self._rng.randint(0xfffff, 0xffffffff)
          #cond = "isalpha('\xfc')"  ###false
          cond = '0' ###false
          comment = 'for call graph (recursion, never executed)'
        else:
          a1, a2, a3 = self._rng.randint(0xfffff, 0xffffffff),self._rng.randint(0xfffff, 0xffffffff), self._rng.randint(0xfffff, 0xffffffff)
          #cond = f'isdigit(\'3\')'  ###true
          #cond = f'ret_ae != 3912039'  ###true
          cond = f'1'  ###true
          comment = 'for call graph, dry'
        args = f'_xarg,{a1},{a2},{a3}'
        new_role = _CRole(cond, '', f'{suc_node["funcname"]}({args})', comment)
        # TODO: more random amount of calls duplication
        if not from_nid in roles:
          roles[from_nid] = [new_role]
        else:
          roles[from_nid].append(new_role)
    self._proceed_to_next_stage(self._st_add_roles_to_last_nodes, 'add roles to last nodes')

  # last nodes are nodes that don't have children (end of path(s))
  def _st_add_roles_to_last_nodes(self):
    # graph not changed
    G = self._G
    for nid in G.nodes:
      if not nid in self._roles:
        ### #Fire
        #self._roles[nid] = [_CRole('1', '', f'isalpha({self._rng.randint(0, 1000)});', 'keep last node alive')]
        self._roles[nid] = [_CRole('1', '', f'', 'keep last node alive')] # we disable this feature be empty string!
    self._proceed_to_next_stage(self._st_evaluate_macros, 'evaluate macros')

  def _st_evaluate_macros(self):
    # graph_changed ?
    roles = self._roles
    for func_nid in roles.keys():
      for func_role in roles[func_nid]:
        # print(func_role.code)
        func_role.code = self._evaluate_macros_in(func_role.code)
        # ... some other places to evaluate macros in
        func_role.comment = self._evaluate_macros_in(func_role.comment)
    self._proceed_to_next_stage(self._st_render, 'rendering things')

  def _st_render(self):
    self._change_flag('graph_changed', True)
    self._set_colors()
    self._render_extra() #new code
    self._proceed_to_next_stage(self._st_convert_old_roles_to_new, 'convert old roles to new')

  def _st_convert_old_roles_to_new(self):
    # graph not chagned
    assert(len(self._roles) == self._G.number_of_nodes())
    spraytab = self.spraytab
    roles = self._roles
    for nid in roles.keys():
      oldrole_list = roles[nid]
      proc_roles = []
      for old_role in oldrole_list:
        assert(type(old_role) == _CRole)
        if old_role.spraytab_line_loc != None:
          # create PX_LX line node (delegate to RoleGen)
          nproc, nline = old_role.spraytab_line_loc
          new_act = self._fn_create_pxlx_line_node(nproc, nline)
        else:
          # create just line node
          new_act = node_line(old_role.code, '// '+old_role.comment)

        if old_role.cond != None:
          # 1: means TRUE:
          role = Role(node_line(f'({old_role.cond})'), {1: [new_act]})
        else:
          # unconditional role
          role = Role(None, {None: [new_act]})

        proc_roles.append(role)
      self.rolearr.append(proc_roles)

      self.namearr.append(f'{self._G.nodes[nid]["funcname"]}')

      is_from_decl = self._nid_has_fromdecl_proc(nid)
      if is_from_decl:
        vl_a = []
      else:
        _xargvar = Var(VT.pvoid, [NullPtr() for _ in range(2)])
        self.fixed_var_names[_xargvar] = '_xarg'
        vl_a = [_xargvar, Var(VT.u32), Var(VT.u32), Var(VT.u32)] #TODO: shuffle
        self.fixed_var_names[vl_a[1]] = 'a1'
        self.fixed_var_names[vl_a[2]] = 'a2'
        self.fixed_var_names[vl_a[3]] = 'a3'
      self.arglistarr.append(vl_a)

      self.lvararr.append([])

    # spraytab_procidxes[0] is an index of spraytab's proc#0 in rolearr
    for nproc in range(len(self.spraytab['procs'])):
      nid = self._proc_roots[nproc]
      index_in_rolearr = list(roles.keys()).index(nid)
      self.spraytab_procidxes.append(index_in_rolearr)

    self._proceed_to_next_stage(None, None) #we're done


  # style=dashed for every node whose nid isn't in _roles
  def _render_extra(self):
    G = self._G
    for nid in G.nodes:
      if not nid in self._roles:
        G.nodes[nid]['style'] = 'dashed'

  def _fix_labels(self):
    for nid in self._G.nodes:
      node = self._G.nodes[nid]
      node['label'] = node['funcname']
      if 'used_for' in node:
        node['label'] += f' ({[",".join(node["used_for"])]})'

  def _nid_has_fromdecl_proc(self, nid):
    spraytab = self.spraytab
    procroot_keys = list(self._proc_roots.keys())
    procroot_values = list(self._proc_roots.values())
    if not nid in procroot_values:
      # not even sprayed
      return False
    stidx = procroot_keys[procroot_values.index(nid)]
    procname = spraytab['procs'][stidx]
    is_from_decl = is_proc_from_decl(spraytab, procname)
    #is_from_decl = procname in spraytab['proc_opts'] and 'is_from_decl' in spraytab['proc_opts'][procname]
    return is_from_decl

  def _try_spray_some_proc(self, sg_root_nid, allowed_procnums=None) -> bool:
    spraytab = self.spraytab
    G = self._G
    proc_roots = self._proc_roots
    sg_nids = list(nx.descendants(G, sg_root_nid))
    # new code
    sg_nids = [nid for nid in sg_nids if not nid in self._nids_of_fromdecls]
    if len(sg_nids) == 0:
      return False  # can't use |sg_root| for spraying
    # don't disallow using P* (proc entries) nodes as P*_L* containing nodes.

    self._rng.shuffle(sg_nids)
    proc_count = len(spraytab['procs'])
    getproclines = lambda nproc: spraytab['lines'][spraytab['procs'][nproc]]
    # Try from biggest proc to smallest. Sort proc nums in descending order by line counts.
    proc_idxes = [n for n in range(proc_count)]
    proc_idxes = sorted(proc_idxes, key=lambda n: len(getproclines(n)))
    for nproc in proc_idxes:
      if (allowed_procnums != None and not nproc in allowed_procnums) or nproc in proc_roots.keys():
        continue
      proc_linecount = len(getproclines(nproc))
      #print('[WoW] len(sg_nids) < proc_linecount:', len(sg_nids) < proc_linecount, f'{len(sg_nids)=}, {proc_linecount=}')

      #new code
      if self._opts['force_lines_scatter']:
        if len(sg_nids) < proc_linecount:
          continue  # if not enough nodes
      else:
        if len(sg_nids) == 0: # 1 is enough if it's not required to force_lines_scatter
          continue

      ### decided to use sg_root, remember we sprayed it
      #spraytab['proc'][spraytab[nproc]]
      if is_proc_from_decl_n(spraytab, nproc) and spraytab['root_proc'] != spraytab['procs'][nproc]:
        # add anoter root node for from_decl proc
        new_root_nid = type(sg_root_nid)(9000000 + int(sg_root_nid)) # support both int and str nids
        G.add_edge(new_root_nid, sg_root_nid)
        self._nids_of_fromdecls += [new_root_nid] # will be excluded from using for spraying
        sg_nids += [sg_root_nid] # add old root as usual nid to spray on
        sg_root_nid = new_root_nid # replace root with new root that has no parents
      self._do_spray_proc(nproc, sg_root_nid, sg_nids)
      return True

    # if we got here, then no procs can be placed in subgraph
    return False

  def _do_spray_proc(self, nproc, sg_root_nid, sg_nids):
    spraytab = self.spraytab
    G = self._G
    proc_roots = self._proc_roots
    roles = self._roles
    proc_name = spraytab['procs'][nproc]
    proc_lines = spraytab['lines'][proc_name]
    proc_linecount = len(proc_lines)
    proc_roots[nproc] = sg_root_nid
    G.nodes[sg_root_nid]['funcname'] = f'P{nproc}'  # naming
    G.nodes[sg_root_nid]['original_funcname'] = spraytab['procs'][nproc]
    # node_color(G.nodes[sg_root], '#aaaaaa')
    for nline in range(proc_linecount):
      # each proc's line

      # new code; allow ?
      if self._opts['force_lines_scatter']:
        # sg_nids guaranteed to have at least as much nids as number of lines
        sg_nid_index = nline
      else:
        # sg_nids can have less nids than nline, so loop the list
        sg_nid_index = nline % len(sg_nids)

      all_paths = nx.all_simple_paths(G, sg_root_nid, sg_nids[sg_nid_index])

      path_nids = self._rng.choice([p for p in all_paths])
      prev_nid, prev_node, prev_role = None, None, None
      rev_path_nids = list(reversed(path_nids))
      for nid in rev_path_nids:
        # each node of path (child->parent->...)
        node = G.nodes[nid]
        if prev_node != None:
          # F11<-P5<-F13
          humanread_path = f'(P{nproc}_L{nline})<-'
          humanread_path += ''.join(
            [(f'[@nodename({x})]<-' if x == nid else f'@nodename({x})<-') for x in rev_path_nids])
          comment = f'chain {humanread_path}'
          callargs = prev_role.callargs.replace('?', str(self._rng.randint(0, 0xffff)))
          code = f'@nodename({prev_nid})( _xarg, {callargs} )'
          spraytab_line_loc = None
        else:
          # final PX_LX line
          # code, comment will be set when converting old roles to new
          code = ''
          comment = ''
          node.setdefault('used_for', []).append(f'P{nproc}_L{nline}')
          spraytab_line_loc = (nproc, nline)
        assert(type(nid) == type(sg_root_nid))

        if nid == sg_root_nid:
          if nid != self.root_nid:  ###entry, but not root

            if is_proc_from_decl_n(spraytab, nproc):
              cond = None
            else:
              cond = f'a3 == {self._entry_a3} && a1 == {self._entry_a1} && a2 == {self._entry_a2}' ### _CALL() job
              self.rolecnt_entr[nid] = self.rolecnt_entr.setdefault(nid, 0) + 1

          else:  ###entry, root
            cond = None

        else:  # not entry
          cond = f'a3 == {self._argcnt3} && a1 == {self._argcnt1}'
          self.rolecnt_fwd[nid] = self.rolecnt_fwd.setdefault(nid, 0) + 1

        ### create role
        new_role = _CRole(cond, f'{self._argcnt1}, ?, {self._argcnt3}', code, comment, spraytab_line_loc)
        roles.setdefault(nid, []).append(new_role)

        self._argcnt1 += 2 #Weakness
        self._argcnt3 += 3 #Weakness
        prev_node = node
        prev_nid = nid
        prev_role = new_role
        pass
      pass
    return

  def _find_root_nid(self):
    G = self._G
    found_root_nid = None
    for nid in G.nodes:
      if 0 == len([x for x in G.predecessors(nid)]) and 0 != len([x for x in G.successors(nid)]):
        assert (not self.root_nid)
        found_root_nid = nid
    return found_root_nid

  def _invoke_macro(self, macro, arg):
    #assert(type(arg) == str)
    if macro == 'nodename':
      argt = type(self.root_nid)(arg)  # support for different nid types
      return self._G.nodes[argt]['funcname']#+'/**/'
    else:
      raise RuntimeError(f'bad {macro=}, {arg=}')

  def _evaluate_macros_in(self, s):
    return re.sub('\@([a-z0-9]+)\(([0-9]+)\)', lambda m: self._invoke_macro(m[1], m[2]), s)

  def _set_colors(self):
    # more blue = entry proc's every line -> call linecounts, more yellow = has more chains element calls in it
    # example: dark green means a lot of both counts
    G = self._G
    roles = self._roles
    max_entrycnt = sorted(self.rolecnt_entr.items(), key=lambda x: x[1], reverse=True)[0][1]  # first value of sorted
    max_fwdcnt = sorted(self.rolecnt_fwd.items(), key=lambda x: x[1], reverse=True)[0][1]  # first value of sorted
    for nid in G.nodes:
      node = G.nodes[nid]
      ne = self.rolecnt_entr[nid] if nid in self.rolecnt_entr else 0
      nf = self.rolecnt_fwd[nid] if nid in self.rolecnt_fwd else 0
      assert (ne <= max_entrycnt and nf <= max_fwdcnt)
      node_color(node, make_html_color((255 - ((255 // max_entrycnt) * ne), 255, 255 - ((255 // max_fwdcnt) * nf))))
      # print(f'node {nid} (name {node["funcname"]} ne={ne},nf={nf} (max e: {max_entrycnt}, max f: {max_fwdcnt})')
      if nid in self._proc_roots.values():  # proc_roots -> { procnum: sg_root }
        node['penwidth'] = 7.0  ### pen width for proc root nodes



