import copy
import networkx as nx

from c2.sprayer.rg.rolegen_basic import RoleGenBasic
from c2.sprayer.rg._pathgen import PathGen, RootOrder, ProcOrder
from c2.sprayer.misc.role import Role
from c2.sprayer.ccode.var import Var, VT
from c2.common.bit_writer import BitWriter

# TODO: demonstrate_editing_line not inserted here

#TODO: validate opts
# route_limit=8, # DWORD route[2]
class RoleGenSpray(RoleGenBasic):
  def __init__(self,
               spraytab: dict,  # can be changed during role gen
               rgpxlx_inline: bool, # TODO: need remake: we're now passing fn_create_pxlx_line_node
               rng,
               call_graph:nx.DiGraph,
               route_limit: int,
               route_bits_per_peer: int,
               # eliminate_unrouted: bool,
               root_order: RootOrder,
               proc_order: ProcOrder,
               max_args):

    super().__init__(spraytab, rgpxlx_inline, rng)
    self.G = call_graph
    # output:   rolearr   orig_idxes   arglistarr   defs
    # self.eliminate_unrouted = eliminate_unrouted
    assert (max_args >= 1)
    self.max_args = max_args
    self.route_bits_per_peer = route_bits_per_peer
    self.do_render = False  # set yourself

    # demonstrate editing line
    spraytab['lines'][p0name][0] = spraytab['lines'][p0name][0] + ' /*hi from RoleGenDumb; _zk() */'

    # only shape is now used by RoleGenSpray
    self._stshape = SpraytabShape(self.spraytab)
    self._stshape.from_spraytab(spraytab)

    self._pathgen = PathGen(self.G, route_limit, self._stshape,
                            self._rng, root_order, proc_order)
    self._procnids = None
    self._proc_lidstacks = None  # where we pop lids from
    # self._lids_used = {} # dict for hashing keys, all : values is None #! obsolete

    self._routarg_idxes = None

    # Create in constructor. Used for .num_route_dwords() and for spraying. _bit_writer is reset
    # in every _do_path
    self._bit_writer = BitWriter(self._pathgen.route_limit, self.route_bits_per_peer)

    self.defs = {'RoleGenSpray': {}}
    self.defs['RoleGenSpray']['CALL(F)'] = self._make_call_def_for_args(['_xarg', 'RandDW_1'])
    self._log0 = []

    self._proceed_to_next_stage(self.fix_graph, 'pathgen - fixing graph')

  def _st_fix_graph(self):
    self._pathgen.fix_graph()
    self._proceed_to_next_stage(self._st_find_rootnid, 'pathgen - finding root node')

  def _st_find_rootnid(self):
    self._pathgen.find_rootnid()
    self._proceed_to_next_stage(self._st_make_work_subgraph, 'pathgen - making work subgraph')

  def _st_make_work_subgraph(self):
    self._pathgen.make_work_subgraph()
    self._proceed_to_next_stage(self._st_spray_all_procs, 'pathgen - spraying all procs')

  def num_route_dwords(self):
    # create instance of BitWriter just for querying num_dwords()
    return self._bit_writer.num_dwords()

  def graph_updated(self):
    # use get_labeled_graph
    # return self._cur_stage >= 1 and self._cur_stage < 9
    if self._cur_stage == 2:
      return False  # finding root node doesn't modify graph
    return True

  def log0_updated(self):
    hide_pathlog_with_nids = True  # hide raw log
    _stages = [5, ]
    if not hide_pathlog_with_nids:
      _stages += [4]
    return self._cur_stage in _stages

  def get_labeled_graph(self):
    return self.G

  def get_log0(self):
    return self._log0

  def _st_spray_all_procs(self):
    self._pathgen.spray_all_procs()

    self._log0 = ['paths (nids):']
    self._log0 += self._textualize_paths()

    self._proceed_to_next_stage(self._st_everything_else, 'everything else (todo)')

  def _max_lid(self):
    return 2 ** self.route_bits_per_peer - 1

  def _make_proc_lidstacks(self):
    G = self.G
    self._proc_lidstacks = []
    for i in range(G.number_of_nodes()):
      lids = [x for x in range(self._max_lid())]
      # self._pathgen._rng.shuffle(lids) # using friend _rng here
      self._proc_lidstacks.append(lids)
    assert (len(self._proc_lidstacks) == G.number_of_nodes())

  def _consume_lids_assign_to_edges(self):
    G = self.G
    for nid in G.nodes:
      nproc = self._procnids.index(nid)
      chnids = G.successors(nid)
      for chnid in chnids:
        # use `label` so it's already rendered
        G.edges[nid, chnid]['label'] = self._proc_lidstacks[nproc].pop()
    # nx.set_edge_attributes(G, { (): {  } })
    return

  def _st_everything_else(self):
    G = self.G
    pathgen = self._pathgen
    self.spraytab_procidxes = pathgen.spraytab_procidxes
    spraytab_procidxes = self.spraytab_procidxes

    ### ALLOCATE ###
    self.rolearr = None  # output will be done later
    self._cond_rolearr = []
    self._uncond_rolearr = []
    self.namearr = []
    self._procnids = []
    # add proc entry nodes first
    # pidx = 0
    for npath in range(len(spraytab_procidxes)):
      spraytab_procidx = spraytab_procidxes[npath]
      # self.rolearr.append(None)
      self._cond_rolearr.append([])
      self._uncond_rolearr.append([])
      self.namearr.append(f'P{spraytab_procidx}')
      self._procnids.append(pathgen.prepared_nids[npath])  # TODO: RENAME: procnids
      spraytab_procidx += 1
    # add the rest of nids ( P99, F100, .. )
    _ = 0
    for nid in G.nodes:
      if not nid in self._procnids:
        # self.rolearr.append(None)
        self._cond_rolearr.append([])
        self._uncond_rolearr.append([])
        self.namearr.append(f'F{_}')
        self._procnids.append(nid)
        _ += 1
    assert (len(self._cond_rolearr) == G.number_of_nodes())
    assert (len(self._uncond_rolearr) == G.number_of_nodes())
    assert (len(self.namearr) == G.number_of_nodes())
    assert (len(self._procnids) == G.number_of_nodes())

    if self.do_render:
      self._render_procnames_on_nodes()

    # generate arguments and trash lvars for ALL procs
    self._generate_arglistarr(len(pathgen.paths), 0, self.max_args)  # RoleGenBasic
    self._insert_routeargs_to_arglistarr()
    self._generate_trashvars()
    self.arglistarr[0] = []  # root proc can't have args

    # 1. allocate lids for every proc and shuffle ; self._proclids;
    self._make_proc_lidstacks()
    # (max have enough for edges and P_L acts)
    # 2:
    self._consume_lids_assign_to_edges()  # pops lid and assigns it to edge; some lids left (used for P_L acts)
    # if self.do_render: # not required
    #  self._render_lids_on_edges()

    # Process EVERY proc : EVERY path
    for nprocpath in range(len(pathgen.paths)):
      # EVERY PROC
      procpaths = pathgen.paths[nprocpath]
      for npath in range(len(procpaths)):
        # EVERY PATH IN PROC
        path = procpaths[npath]
        nline = npath

        self._do_path(path, nline)
      pass

    # Merge/mix cond and uncond roles
    self._merge_mix_cond_uncond_roles()

    self._proceed_to_next_stage(None, None)  # we're done
    return

  def _merge_mix_cond_uncond_roles(self):
    assert (len(self._cond_rolearr) == len(self._uncond_rolearr) == len(self.arglistarr) == len(self._procnids) == len(
      self._proc_lidstacks))
    self.rolearr = []

    ##
    for nproc in range(len(self.arglistarr)):
      for role in self._cond_rolearr[nproc]:
        role.validate_instance()
    for nproc in range(len(self.arglistarr)):
      for role in self._uncond_rolearr[nproc]:
        role.validate_instance()
    ##

    for nproc in range(len(self.arglistarr)):
      mixed_roles = self._uncond_rolearr[nproc] + self._cond_rolearr[nproc]
      self.rolearr.append(mixed_roles)

  def _make_call_args(self, nprocdest, routearg_node):
    num_args = len(self.arglistarr[nprocdest])
    nroutearg = self._routarg_idxes[nprocdest]
    cnt = 0
    call_args = []
    for narg in range(num_args):
      if narg == nroutearg:
        call_args.append(routearg_node)
      else:
        call_args.append(node_const(777 + cnt))
        cnt += 1
    return call_args

  ### only one Role used for routine (it's like a switch for route arg) ###
  def _create_cond_role_if_not(self, nproc):
    if len(self._cond_rolearr[nproc]) > 0:
      return
    vroutearg = self.arglistarr[nproc][self._routarg_idxes[nproc]]
    ## BYTE* CAST
    vargnode = node_arrofs(node_var(vroutearg), node_const(0))
    self._cond_rolearr[nproc] = [Role(expr=vargnode)]
    assert (len(self._cond_rolearr[nproc]) == 1)

  def _do_path(self, path, nline):
    # EVERY PATH IN PROC
    assert (len(path) >= 2)

    spraytab_procidxes = self.spraytab_procidxes
    G = self.G

    # Shortcuts
    startnid = path[0]
    nprocidx = self._procnids.index(startnid)  # our proc index
    st_nproc = spraytab_procidxes[nprocidx]  # spraytab's index

    bit_writer = self._bit_writer
    bit_writer.reset()

    # First, process 1..end, calculating route integer (P_L also added at the end)
    # After this, we know route integer so we pass it in 0->1 call

    for npeer in range(1, len(path)):  # START FROM 1, NOT 0
      # cur peer in first hop destination
      peernid = path[npeer]
      nprocpeer = self._procnids.index(peernid)

      self._create_cond_role_if_not(nprocpeer)
      cond_role0 = self._cond_rolearr[nprocpeer][0]

      if npeer < len(path) - 1:
        ############ MID PEER (HAS NEXT) ##############
        # USING COND ROLE
        # lid is unique within a graph node, it uniquely identifies an edge
        nextnid = path[npeer + 1]
        nprocnext = self._procnids.index(nextnid)
        edge_lid = G.edges[peernid, nextnid][
          'label']  # already rendered #### TODO: INT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        assert (edge_lid <= self._max_lid())
        if not edge_lid in cond_role0.switchdict:
          ########### FIRST TIME SEEING EDGE #############
          v = self.arglistarr[self._routarg_idxes[nprocidx]]
          routearg_node = node_arrofs(node_var(v), node_const(1))  ###TODO: node_ref
          call_args = self._make_call_args(nprocnext, routearg_node)
          callnode = node_call(self.namearr[nprocnext], call_args)

          # if (routearg == <edge_lid>) { callnode
          cond_role0.switchdict[edge_lid] = [callnode]
          pass

        # Collect edge_lid bits to fucking route_integer
        bit_writer.write_bits(edge_lid)
      else:
        ############################################
        # LAST PEER
        ############################################
        P_L_node = node_line(f'P{st_nproc}_L{nline}')

        new_consumed_lid = self._proc_lidstacks[nprocpeer].pop()

        cond_role0.switchdict[new_consumed_lid] = [P_L_node]

        # Append the last LID that identify the concrete P_L in last node
        bit_writer.write_bits(new_consumed_lid)

      # continue to next peer
      pass

    # assert(bit_writer.all_written()) # no, not all the paths are max len
    assert (bit_writer.values_written() == len(path) - 1)

    ######## NOW WE CAN PLACE FIRST->SECOND CALL #######
    self._place_first_to_next_call(path)

    return

  def _place_first_to_next_call(self, path):
    # Construct fucking DWORDS bytearrs
    nproc = self._procnids.index(path[0])
    nprocnext = self._procnids.index(path[1])

    callid = self.namearr[nprocnext]
    callargs = self._make_call_args(nprocnext, 0000000000)

    ### USING UNCOND ROLES ###
    # Entry calls are created using new Role
    self._uncond_rolearr[nproc].append(Role(None, {None: [node_call(callid, [], '// call2next')]}))

  '''###############################################
      trashvar = self._pick_trash_var(peer_procnum) # role_lvars
      assert(len(trashvar.values) >= self.num_route_dwords())
      setroutevar_stmts = []
      byteofs = 0
      for ndword in range(self.num_route_dwords()):
        dwmask = 0
        setroutevar_stmts.append(node_assig('=',
                                   node_arrofs(node_var(trashvar),
                                               node_const(byteofs)),
                        node_const(dwmask),
                                   comment=f'// trashvar #{ndword}'))
        byteofs += 4 # DWORD
      pass
      callargs = [ ]
      call_stmt = node_call(callid, callargs, comment='// call to next\n')
      acts = [*setroutevar_stmts, call_stmt]
      roles.append(Role(None, [(None, acts)]))
      del callid
    # render func names on nodes
    return
  '''

  def _pick_trash_var(self, nproc) -> Var:
    vl = self.lvararr[nproc]
    r = self._rng.randint(0, len(vl) - 1)
    return vl[r]

  def _generate_trashvars(self):
    G = self.G
    self.lvararr = []
    for nproc in range(G.number_of_nodes()):
      self.lvararr.append([Var(VT.u32, [ValueUnknown() for _ in range(self.num_route_dwords())])])

  def _insert_routeargs_to_arglistarr(self):
    G = self.G
    self._routarg_idxes = []
    # randomly insert route arg into every proc's arglist
    for nproc in range(len(self.arglistarr)):
      vl_a = self.arglistarr[nproc]
      _randidx = self._rng.randint(0, len(vl_a))
      v = Var(VT.u8, [0 for _ in range(self.num_route_dwords() * 4)])
      vl_a.insert(_randidx, v)
      self._routarg_idxes.append(_randidx)
    assert (len(self._routarg_idxes) == len(self.arglistarr))

  ###### for log ######
  def _textualize_paths(self, fn_getnodlabel=lambda nid: str(nid)):
    pathgen = self._pathgen
    l = []
    for i in range(len(pathgen.paths)):
      procpaths = pathgen.paths[i]
      nline = 0
      for procpath in procpaths:
        l.append(' -> '.join([fn_getnodlabel(_) for _ in procpath]))
        l[-1] += f' -> {fn_getnodlabel(procpath[0])}_L{nline}'
        nline += 1
    return l

  # not needed
  # we're now using `label` attribute for lids to optimize
  # def _render_lids_on_edges(self):
  #  G = self.G
  #  for edge in G.edges:
  #    G.edges[edge]['label'] = G.edges[edge]['lid']

  def _render_procnames_on_nodes(self):
    G = self.G
    pathgen = self._pathgen
    gdata = copy.deepcopy(pathgen._gdata)
    for i in range(len(self._procnids)):
      nid = self._procnids[i]
      # z = self.spraytab['lines'][i]
      gdata.setdefault(nid, {})['+'] = self.namearr[i]
    labelnodes(G, gdata)

  def _update_log0(self):
    self._log0 = ['paths (proc names):']
    self._log0 += self._textualize_paths(lambda nid: self.namearr[self._procnids.index(nid)])

  pass  # end of class RoleGenSpray


