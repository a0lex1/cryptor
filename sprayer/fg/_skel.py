import math
import networkx as nx

from c2.sprayer.gens.nx_tree_graph import NXTreeGraphGen
from c2.sprayer.misc.role import Role
from c2.common.graph import node_color, make_html_color


class RolesShape:
  def __init__(self, roles:list=None):
    # just the structure of roles, no content
    self.role_list = []
    for role in roles:
      swdict = {}
      #for val, act in role.switchtups:
      for swkey in role.switchdict.keys():
        act = role.switchdict[swkey]
        if type(act) == list:
          actshape = [None for _ in range(len(act))]
        else:
          raise RuntimeError('only list acts now supported')
        swdict[swkey] = actshape
      self.role_list.append(Role(None, swdict))
    pass

  #def enumerate_switchkeys(self):
    #        Role1              Role2              Role3
    #         expr              expr               expr          << exprs of roles
    #     swkey1 swkey2     swkey1 swkey2   swkey1 swkey2 swkey3 << returns this, swkeys of all roles
    #     a1 a2  a1 a2 a3     a1     a1            a1     a1 a2  << acts
    #[]
    #pass

  def total_switchkeys(self):
    return sum([len(role.switchdict) for role in self.role_list])

  def total_number_of_acts(self):
    # StmtList s not counted
    total_acts = 0
    for nrole in range(len(self.role_list)):
      #for nsw in range(len(self.shape[nrole].switchtups)):
      for swkey in self.role_list[nrole].switchdict.keys():
        acts = self.role_list[nrole].switchdict[swkey]
        #val, acts = tup
        total_acts += len(acts) # really? what if acts is int, not list? strange code.
    return total_acts


# the concept of Skel in FG:
#   If you need to add rules, add it through |next_nid| increment, then you may need to recreate_dfscounting() to normalize nids
#   Can be saved/loaded to/from .dot file
class Skel:
  def __init__(self, G=None, root_nid:int=None, next_nid:int=None):
    self.G = G
    self.root_nid = root_nid
    self.next_nid = next_nid

  def from_file(self, fpath):
    Gtemp = nx.DiGraph(nx.drawing.nx_pydot.read_dot(fpath))
    # somehow nx writes .dot with str node ids, not int (as it was before writing)
    # need to convert manually
    self.G = nx.DiGraph()
    for e in Gtemp.edges:
      self.G.add_edge(int(e[0]), int(e[1]))
    self.root_nid = 0
    self.locate_next_nid()

  def locate_next_nid(self):
    previously_used_nid = sorted(self.G.nodes)[-1]
    self.next_nid = previously_used_nid + 1

  def to_file(self, fpath):
    dot = nx.drawing.nx_pydot.to_pydot(self.G)
    dot.write_dot(fpath)



# IMPROV
#  - another treegen that supports repeating/mirroring (human-like sequences)
#  - role_impl still can be used loops, but need if-(TRUE)-then-break after one iter
#  - add fake role impls and role ifs which are not really executed (duplicate roles) (now called `grinding`)
#
class SkelGen:
  def __init__(self, skel:Skel, roles_shape:RolesShape, initial_branch_nodes:int, rng):
    self.skel = skel
    self.roles_shape = roles_shape
    self.__treegen = NXTreeGraphGen(initial_branch_nodes, rng)

  def gentree(self):
    # initial tree creation
    self.__treegen.gen_seq()
    self.__treegen.make_tree()
    self.skel.G = self.__treegen.G
    self.skel.root_nid = self.__treegen.root_nid
    self.skel.next_nid = self.__treegen.next_nid


# Used by SkelFiller
class ActOrderer:
  def __init__(self, G, skeldata):
    self.G = G
    self.skeldata = skeldata
    self._prev_tup = None
    self._act_cnt = 0
    self._total_roleimpls_visited = 0

  def total_roleimpls_visited(self):
    return self._total_roleimpls_visited

  def visit(self, nid, lev=0):
    # visit deeper, maintaining flow, assign counter to 'role_impl' nids
    # reset counter to 0 if the role:nswtup has changed
    G = self.G
    skeldata = self.skeldata

    chnids = list(G.successors(nid))
    if len(chnids):
      # role_impls can't have children
      assert (skeldata[nid]['t'] != 'role_impl')

      for chnid in chnids:
        self.visit(chnid, lev+1)

    else:
      # |nid| node has no children, we are at bottom
      if skeldata[nid]['t'] == 'role_impl':
        cur_tup = skeldata[nid]['roletup']

        if self._prev_tup != None:
          # reset if tup has changed
          if cur_tup != self._prev_tup:
            self._act_cnt = 0

        nrole, swkey, _ = cur_tup
        skeldata[nid]['roletup'] = (nrole, swkey, self._act_cnt)
        self._act_cnt += 1
        self._prev_tup = cur_tup

        self._total_roleimpls_visited += 1
    return

class SkelFillerBase:
  def __init__(self, skeldata, skel, roles_shape, rng):
    assert(skeldata == {})
    self.skeldata = skeldata
    self.skel = skel
    self.roles_shape = roles_shape
    self._rng = rng

    self.loops_percent_min = 33
    self.loops_percent_max = 66
    self.else_percent_min = 33
    self.else_percent_max = 66

    #self._logfn = None

  #def set_logging_fn(self, logfn):
  #  self._logfn = logfn

  def init_skeldata(self):
    for nid in self.skel.G.nodes:
      self.skeldata[nid] = {'t': '', '': nid}

  def swap_unordered_roleacts(self):
    aorderer = ActOrderer(self.skel.G, self.skeldata)
    aorderer.visit(self.skel.root_nid)
    assert(aorderer.total_roleimpls_visited() == self.roles_shape.total_number_of_acts())

  def merge_elses(self):
    skel = self.skel
    rng = self._rng
    mergetups = []
    # collect tups to merge in dry tun mode
    self.__mergevisit(True, skel.root_nid, mergetups)
    if len(mergetups):
      # calculate how many of tups we actually want to merge
      # one tuple merging produces 1 else (by changing node's t to _else)
      # total_ifs = len(list([nid for nid in G.nodes if skeldata[nid]['t'] == ''])) # no, % of possible tups, not from total ifs
      else_percent = rng.randint(self.else_percent_min, self.else_percent_max)
      assert (else_percent <= 100)
      num_elses = math.floor(len(mergetups) / 100 * else_percent)
      assert (num_elses <= len(mergetups))
      #self._log(f'else_percent={else_percent}, num_elses chosen {num_elses}, and len(mergetups) is {len(mergetups)}')
      rng.shuffle(mergetups)  # leave only first num_elses_m elements of randomly shuffled list
      mergetups = mergetups[:num_elses]
      # actually merge
      for this_nid, prev_nid in mergetups:
        self.__merge(False, this_nid, prev_nid)
        # rendering
        self.skel.G.nodes[this_nid]['penwidth'] = 2

  def place_loops(self):
    G = self.skel.G
    rng = self._rng
    skeldata = self.skeldata
    cond = lambda nid: skeldata[nid]['t'] == ''
    skel = self.skel
    loopcand_nids = [nid for nid in G.nodes if nid != skel.root_nid and cond(nid)]
    if len(loopcand_nids):
      loops_percent = rng.randint(self.loops_percent_min, self.loops_percent_max)
      num_loops = math.floor((len(loopcand_nids) / 100) * loops_percent)
      #self._log(f'loops_percent={loops_percent}, num_loops chosen {num_loops}, and len(loopcand_nids) is {len(loopcand_nids)}')
      for i in range(num_loops):
        rnid = rng.choice(loopcand_nids) # pick random node
        if rng.choice([1, 2]) == 1:
          skeldata[rnid]['t'] = 'while'
          node_color(G.nodes[rnid], make_html_color((0xf0, 0xea, 0xf0)))
        else:
          skeldata[rnid]['t'] = 'for'
          node_color(G.nodes[rnid], make_html_color((0xf0, 0xf0, 0xea)))


  # with IFs
  def fill_unused_nodes(self):
    G = self.skel.G
    skeldata = self.skeldata
    cond = lambda nid: skeldata[nid]['t'] == ''
    nids = [nid for nid in G.nodes if nid != self.skel.root_nid and cond(nid)]
    if len(nids):
      for nid in nids:
        skeldata[nid]['t'] = self._rng.choice(['if_true', 'if_false'])
        # skeldata[nid]['last'] = 1
        node_color(G.nodes[nid], make_html_color((0xa0, 0xb0, 0xb0)))

  def ensure_empty_types(self, nids):
    for nid in nids:
      assert(self.skeldata[nid]['t'] == '')

  def __merge(self, is_dry_run, this_nid, prev_nid):
    rng = self._rng
    # if this_nid==77:
    #  breakpoint()
    skeld = self.skeldata
    if skeld[this_nid]['t'] == '':
      if skeld[prev_nid]['t'] == 'role_if':
        # connect role_if <- empty
        if not is_dry_run:
          skeld[this_nid]['t'] = '_else'
          skeld[this_nid]['flow'] = 'maybe'  # if (role1cond) {...} else {maybe_flow}
      elif skeld[prev_nid]['t'] == '':
        # connect '' <- ''
        if not is_dry_run:
          skeld[this_nid]['t'] = '_else'
          # pick random true/false for both empty nodes
          _ = [('if_true', 'not'),
               ('if_false', 'true')][rng.choice([0, 1])]
          skeld[prev_nid]['t'] = _[0]
          skeld[this_nid]['t'] = '_else'
          skeld[this_nid]['flow'] = _[1]
        pass
      elif skeld[prev_nid]['t'] == 'if_true':
        # connect if_true <- empty
        if not is_dry_run:
          skeld[this_nid]['t'] = '_else'
          skeld[this_nid]['flow'] = 'not'  # prev is true
      elif skeld[prev_nid]['t'] == '_else':
        # we visited it
        return False
      elif skeld[prev_nid]['t'] == 'if_false':
        # we visited it
        return False
      else:
        raise RuntimeError(f'bad prev_nid\'s t - {skeld[prev_nid]["t"]}')
      return True
    elif skeld[this_nid]['t'] == 'if_true':
      if skeld[prev_nid]['t'] == '':
        # connect empty <- if_true
        if not is_dry_run:
          skeld[prev_nid]['t'] = 'if_false'
          skeld[this_nid]['t'] = '_else'
          return True
      else:
        return False
    else:
      return False  # nodes can't be connected
    pass

  def __mergevisit(self, is_dry_run, nid, mergetups): # mergetups is output
    succ_nids = list(self.skel.G.successors(nid))
    prev_nid = None
    used_nids = []
    for succ_nid in succ_nids:
      if prev_nid != None:  # not first iter
        if not prev_nid in used_nids:  # prev not added
          if self.__merge(is_dry_run, succ_nid, prev_nid):  # dry run merge success, add to possible merges
            mergetups.append((succ_nid, prev_nid))
            used_nids.append(succ_nid)
            self.skel.G.nodes[succ_nid]['color'] = 'green'
      prev_nid = succ_nid
      self.__mergevisit(is_dry_run, succ_nid, mergetups)  # recursion

  # make entire path if_true (from nid to root)
  def set_t_if_true_visitor(self, nid):
    if self.skeldata[nid]['t'] == '':
      self.skeldata[nid]['t'] = 'if_true'

  # for tree, not for all graphs
  def _visitparents(self, G, nid, cbk):
    preds = list(G.predecessors(nid))
    assert (len(preds) == 1 or len(preds) == 0)
    for pred_nid in preds:
      cbk(pred_nid)
      self._visitparents(G, pred_nid, cbk)

  # for tree, not for all graphs
  def _visitchildren(self, G, nid, cbk):
    succs = list(G.successors(nid))
    for succ_nid in succs:
      cbk(succ_nid)
      self._visitchildren(G, succ_nid, cbk)
  '''
  def _log(self, msg):
    if self._logfn:
      self._logfn(msg)
  '''


'''class SkelFillerOld(SkelFillerBase):
  # Role acts placed in RANDOM order! Act indecies not assigned; swap_unordered_roleacts does this job
  def place_roles(self):
    G = self.skel.G
    skel = self.skel
    skeldata = self.skeldata
    for nrole in range(len(self.roles_shape.role_list)): # every role
      role_shape = self.roles_shape.role_list[nrole]
      for swkey in role_shape.switchdict.keys():
        assert(type(swkey) == int or swkey == None) #
        swacts = role_shape.switchdict[swkey]

        cond = lambda nid: skeldata[nid]['t'] == '' and not 'rchi' in skeldata[nid] and not 'rpar' in skeldata[nid]
        rnids = [nid for nid in G.nodes if nid != skel.root_nid and cond(nid)]
        roleif_nid = self._rng.choice(rnids)  # pick random NODE for role IF
        skeldata[roleif_nid]['t'] = 'role_if'
        # role for roleif, roletup for role act nodes
        skeldata[roleif_nid]['role'] = (nrole, swkey)

        def setchildflag(nid):
          skeldata[nid]['rpar'] = 1  # path from this node contains roles

        def setparentflag(nid):
          skeldata[nid]['rchi'] = 1  # path from root to this node contains roles

        # mark we used the path
        self._visitparents(G, roleif_nid, setparentflag)
        self._visitchildren(G, roleif_nid, setchildflag)

        num_acts = len(swacts)

        # select  next > prev_nid  to  match  control  flow
        # Important: in class Recombiner, since the edge is added to the right
        # side  (nx behavior), such  recombination  can't  break  the
        # 'next nid' > 'prev nid' rule
        prev_nid = None
        for nact in range(num_acts):
          # #BreakingNIDDfsOrdering
          # insert role impl node at RANDOM POSITION on subgraph (-> we're gonna need to fix wrongly ordered acts in the next stages)
          # ['t']=='' check eliminates the use of act nodes inserted here, in place_roles(); we won't eat our own shit
          cond = lambda nid: skeldata[nid]['t'] == '' and\
                     (prev_nid == None or nid > prev_nid)
          subnids = [nid for nid in list(nx.descendants(G, roleif_nid)) if cond(nid)]
          self.ensure_empty_types(subnids)
          if len(subnids):
            subnid = self._rng.choice(subnids)  # pick random SUBNODE for role IMPL INSERTION
          else:
            subnid = roleif_nid # if no children, insert directly to roleif node
          prev_nid = subnid # save here
          # insert role impl
          newnid = skel.next_nid
          skel.next_nid += 1
          G.add_edge(subnid, newnid)
          assert (not newnid in skeldata)
          skeldata[newnid] = {'t': 'role_impl',
                              'roletup': (nrole, swkey, '-'),
                              '': newnid}
          # rendering
          node_color(G.nodes[newnid], make_html_color((0xff, 0xdd, 0xdd)))

          self._visitparents(G, newnid, self.set_t_if_true_visitor)

          #print(f'*** act placed (role {nrole}, swkey {swkey}, nact `-`  at node {newnid}') # new

        # rendering
        node_color(G.nodes[roleif_nid], make_html_color((0xff, 0xbb, 0xff)))
      pass
    pass
'''


class SkelFillerNew(SkelFillerBase):
  # Skel's graph's number of shoulders should be = number of roles_shape.total_switchkeys() #ShouldersAreSwitchkeys
  def place_roles_method_a(self):
    return self.__place_roles_with_method(True)

  def place_roles_method_b(self):
    return self.__place_roles_with_method(False)

  # removes unused shoulders
  def remove_unused_branches(self):
    # TODO.
    # del root.children[L:] where L is number of first completely unused shoulder (compare nids)
    #
    pass

  ### internal funcs

  def __place_roles_with_method(self, method_a_not_b:bool):
    G = self.skel.G
    num_roles = len(self.roles_shape.role_list)
    nswkey_glob = 0
    # precalculations
    self.__shoulder_nids = list(G.successors(self.skel.root_nid))
    for nrole in range(num_roles):
      role_shape = self.roles_shape.role_list[nrole]
      for nswkey_loc in range(len(role_shape.switchdict)):
        self.__place_roleif(method_a_not_b, nrole, nswkey_loc, nswkey_glob)
        nswkey_glob += 1

  def __setchildflag(self, nid):
    self.skeldata[nid]['rpar'] = 1  # path from this node contains roles

  def __setparentflag(self, nid):
    self.skeldata[nid]['rchi'] = 1  # path from root to this node contains roles

  #  stage  1  fill shoulder tree...
  #  Process finished with exit code -1073741819 (0xC0000005)
  def __place_roleif(self, method_a_not_b:bool, nrole:int, nswkey_loc:int, nswkey_glob:int):
    G = self.skel.G
    skel = self.skel
    skeldata = self.skeldata
    roleif_nid = None # keep nid used for most recent role_if (None indicates it's not yet set)
    total_swkeys = self.roles_shape.total_switchkeys()
    role_shape = self.roles_shape.role_list[nrole]
    switchkeys = list(role_shape.switchdict)
    swkey = switchkeys[nswkey_loc]
    assert(type(swkey) == int or swkey == None) #
    swacts = role_shape.switchdict[swkey]
    assert(len(self.__shoulder_nids) == self.roles_shape.total_switchkeys())

    cond = lambda nid: skeldata[nid]['t'] == '' and not 'rchi' in skeldata[nid] and not 'rpar' in skeldata[nid]

    # determine the next shoulder's nid
    if nswkey_glob == total_swkeys-1:
      # the last global swkey, don't limit
      next_shoulder_root_nid = None
    else:
      # not last global swkey, use nid of next as limit
      next_shoulder_root_nid = self.__shoulder_nids[nswkey_glob+1]

    # choose max limit
    cond_before_next_shoulder = lambda nid: next_shoulder_root_nid == None or (nid < next_shoulder_root_nid)

    # choose min limit
    if method_a_not_b:
      # method A (strict one role=one shoulder), start from current shoulder
      cond_after_xxx = lambda nid: nid >= self.__shoulder_nids[nswkey_glob]
    else:
      # method B (shift left): start earlier, insert after previous role_if nid (paper#60, we're gonna need to remove unused branches if they left)
      cond_after_xxx = lambda nid: roleif_nid == None or (nid > roleif_nid) # prev not set yet OR > prev

    # choose using conds formed above
    rnids = [nid for nid in G.nodes
             if nid != skel.root_nid and cond(nid)
             and cond_after_xxx(nid)
             and cond_before_next_shoulder(nid)]

    if 0 == len(rnids):
      raise RuntimeError('the guarantee of at least 1 node (the shoulder itself) is broken')

    roleif_nid = self._rng.choice(rnids)  # pick random NODE for role IF
    skeldata[roleif_nid]['t'] = 'role_if'
    # role for roleif, roletup for role act nodes
    skeldata[roleif_nid]['role'] = (nrole, swkey)

    # mark we used the path
    self._visitparents(G, roleif_nid, self.__setparentflag)
    self._visitchildren(G, roleif_nid, self.__setchildflag)

    num_acts = len(swacts)
    self.__prev_nid = None
    # Place acts
    for nact in range(num_acts):
      self.__place_act(roleif_nid, nrole, swkey)

    # rendering
    node_color(G.nodes[roleif_nid], make_html_color((0xff, 0xbb, 0xff)))
    return # from __place_roleif()

  #PyCharmBugC0000005 disappeared after splitting __place_roleif to __place_act
  #PyCharmBugC0000005 is where program just crashed with C0000005 ONLY if breakpoint is set somewhere in __place_roleif, and NOT in pdb debugger, the bug is in PyCharm only
  def __place_act(self, roleif_nid:int, nrole, swkey):
    skeldata = self.skeldata
    skel = self.skel
    G = self.skel.G
    cond = lambda nid: skeldata[nid]['t'] == '' and \
                         (self.__prev_nid == None or nid > self.__prev_nid)
    subnids = [nid for nid in list(nx.descendants(G, roleif_nid)) if cond(nid)]
    self.ensure_empty_types(subnids)
    if len(subnids):
      subnid = self._rng.choice(subnids)  # pick random SUBNODE for role IMPL
    else:
      subnid = roleif_nid # if no children, insert directly to roleif node
    self.__prev_nid = subnid # save here
    # insert role impl
    newnid = skel.next_nid
    skel.next_nid += 1

    ###
    ### #BreakingNIDDfsOrdering  by insertion of new node(s) ###
    ###
    G.add_edge(subnid, newnid)

    assert (not newnid in skeldata)
    skeldata[newnid] = {'t': 'role_impl',
                        'roletup': (nrole, swkey, '-'),
                        '': newnid}
    # rendering
    node_color(G.nodes[newnid], make_html_color((0xff, 0xdd, 0xdd)))

    self._visitparents(G, newnid, self.set_t_if_true_visitor)
















