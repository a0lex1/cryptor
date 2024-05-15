import networkx as nx, json, fnmatch, os, sys
from enum import Enum

from c2.sprayer.misc.spraytab_utils import SpraytabShape

_sd = os.path.dirname(__file__)


class RootOrder(Enum):
  RANDOM = 0
  HUGEST_FIRST = 1


class ProcOrder(Enum):
  RANDOM = 0
  DEFAULT = 1
  HUGEST_FIRST = 2


#                                P0                 P1            P2
# stshape-> [                     3,                 2,           1 ], 0
# paths  -> [ [path1, path2, path3],    [path1, path2]      [path1] ]
#        [nid,nid,nid,..]                               [nid,nid,nid,..]
#
# Graph G can be MODIFIED by PathGen.
#
class PathGen:
  def __init__(self, G:nx.DiGraph, route_limit, stshape:SpraytabShape, rng,
               root_order=RootOrder.RANDOM, proc_order=ProcOrder.RANDOM):
    self.G = G # input/output (rendering) # G can be modified
    self.route_limit = route_limit
    self.stshape = stshape
    self._rng = rng
    self.root_order = root_order
    self.proc_order = proc_order
    self.do_render = False # set yourself
    self.init()

  def init(self):
    # output
    self.spraytab_procidxes = None
    self.paths = [None for _ in range(self.stshape.numprocs())]
    self.prepared_nids = None

    self._gdata = {}
    self._SG = None
    self._rootnid = None

  def fix_graph(self):
    G = self.G
    G.remove_edges_from([edge for edge in nx.selfloop_edges(G)])
    G.remove_nodes_from([nid for nid in nx.isolates(G)])

  # sgsize can be > actual number of nodes because some nodes can be a part
  # of multiple paths
  def make_work_subgraph(self):
    G = self.G
    gdata = self._gdata
    collected = []

    # visit all nodes
    totalsize = self._sgvisit(self._rootnid, collected)  # root's sgsize

    # create subgraph of visited nodes
    SG = nx.subgraph(G, collected)
    self._SG = SG

    if self.do_render:
      for nid in SG.nodes:
        k = gdata[nid]['sgsize'] / totalsize # div by zero? must .check_graph
        r = round(255-(k/2*255))
        g = r
        color = f'#{r:02x}{g:02x}ff'
        node_color(SG.nodes[nid], color)
      labelnodes(G, gdata)
      # set in .find_rootnid, overwriten by us
      G.nodes[self._rootnid]['style'] = 'dashed'

  def _fnpath_hugest_sg(self, nid):
    return -self._gdata[nid]['sgsize'] # step to hugest subgraph child

  def _sgvisit(self, nid, collected, lev=0):
    G = self.G
    gdata = self._gdata

    collected.append(nid)
    G.nodes[nid]['penwidth'] = 3

    chnids = list(G.successors(nid))
    sgsize = 0
    for chnid in chnids:
      if chnid in collected:
        continue
      if lev < self.route_limit:
        G.edges[(nid, chnid)]['penwidth'] = 3
        sgsize += 1 + self._sgvisit(chnid, collected, lev + 1)

    gdata[nid] = {'sgsize': sgsize, 'nid': nid} # on return from recursion, save sgsize of entire visited subtree
    return sgsize

  def find_rootnid(self):
    G = self.G
    self._rootnid = None
    for nid in G.nodes:
      if 0 == len([x for x in G.predecessors(nid)]) and 0 != len([x for x in G.successors(nid)]):
        assert (self._rootnid == None) # only one is allowed
        self._rootnid = nid
    G.nodes[self._rootnid]['style'] = 'dashed'

  def spray_all_procs(self):
    #G = self.G # SG because we sort all of its nodes
    SG = self._SG
    gdata = self._gdata
    stshape = self.stshape

    #=====================================================================
    # (graph's root always go first)
    # 0  7  99 13     <- pentry_nids    <RANDOM | HUGEST_FIRST>
    # P1 P8 P3 P2     <- procidxes      <RANDOM | HUGEST_FIRST | DEFAULT>
    # ^
    # rootproc_idx always go first to MATCH  graph's root
    #=====================================================================

    # 1. Prepare sorted nodes to spray on. rootnid always go first, its subgraph is always hugest
    #

    _allnids = [nid for nid in SG.nodes if gdata[nid]['sgsize'] > 0]
    _prepared_nids = None
    if self.root_order == RootOrder.HUGEST_FIRST:
      _prepared_nids = sorted(_allnids, key=self._fnpath_hugest_sg) # now [0] is the hugest sg nid
    elif self.root_order == RootOrder.RANDOM:
      _prepared_nids = _allnids
      self._rng.shuffle(_prepared_nids)
    assert(len(_prepared_nids) >= self.stshape.numprocs())
    # swap
    _newidx = _prepared_nids.index(self._rootnid)
    _prepared_nids[0], _prepared_nids[_newidx] = _prepared_nids[_newidx], _prepared_nids[0]

    self.prepared_nids = _prepared_nids # save as output

    # 2. Prepare sorted procs to spray. rootproc_idx element must go first
    # [0, 1, 2, 3, 4]
    #        ^rootproc_idx=2
    # [3, 1, 0, 4, 2]  < shuffled, need 2 to be [0] element
    #              ^[_newidx]
    #
    # [2, 1, 0, 4, 3]  < fixed, rootproc placed at 0

    procidxes = [i for i in range(stshape.numprocs())]
    if self.proc_order == ProcOrder.RANDOM:
      self._rng.shuffle(procidxes)
    elif self.proc_order == ProcOrder.DEFAULT:
      pass
    elif self.proc_order == ProcOrder.HUGEST_FIRST:
      procidxes = sorted(procidxes, key=lambda nproc: -stshape.linecount(nproc))
    # swap
    _newidx = procidxes.index(stshape.rootproc_idx) # find rootproc in shuffled|sorted |procidxes|
    procidxes[0], procidxes[_newidx] = procidxes[_newidx], procidxes[0]

    # Verify root proc matches graph's root
    assert(_prepared_nids[0] == self._rootnid)
    assert(procidxes[0] == stshape.rootproc_idx)

    self.spraytab_procidxes = procidxes

    # Spray each proc
    nsg = 0
    for nproc in procidxes:
      sgnid = _prepared_nids[nsg]

      procpaths = []
      nlines = stshape.linecount(nproc)
      # Spray each line
      for nline in range(nlines):

        # rule of making paths: all used goes to the end
        def fnwalk(nid):
          used = nid in gdata and 'used' in gdata[nid]
          # key of sorting is a tuple
          return (used, -self._gdata[nid]['sgsize'])

        path = self._walk_until_end(sgnid, fnwalk)
        assert(len(path) >= 2 and len(path) <= self.route_limit)
        path = self._cut_path(path)
        assert(len(path) >= 2 and len(path) <= self.route_limit)

        procpaths.append(path)
        # mark the end of path (the `L_` node)
        for pnid in path:
          gdata.setdefault(pnid, {})['used'] = 1
        lastnid = path[-1]
        gdata[lastnid][f'P{nproc}_L{nline}'] = ''
        # mark all nodes in path `used`

        #print(f'P{nproc}_L{nline} at nid {lastnid}')

      # all lines sprayed, continue work with current proc
      spraytabidx = self.spraytab_procidxes[nproc]
      self.paths[spraytabidx] = procpaths
      gdata.setdefault(sgnid, {})[f'P{nproc}'] = ''

      SG.nodes[sgnid]['color'] = 'red' # rendering
      nsg += 1 # next sg for next proc

    if self.do_render:
      labelnodes(self.G, gdata)
    pass

  # path will include the nid we started from
  # uses walk fn to chose children nodes while walking
  def _walk_until_end(self, nid, fnwalk):
    SG = self._SG # we want to limit us
    def vis(nid, path, fnwalk, lev=0):
      if lev == self.route_limit:
        return
      path += [nid]
      chnids = list(SG.successors(nid))
      # if recursed, simply kick off parents from children
      chnids = [c for c in chnids if not c in path]
      if 0 == len(chnids):
        return
      chnids = sorted(chnids, key=fnwalk) # may go random or hugest sgsize child
      cnid = chnids[0] # decided to walk this child node
      vis(cnid, path, fnwalk, lev+1)
      return
    path = []
    vis(nid, path, fnwalk)
    assert(len(path))
    return path

  def _cut_path(self, path):
    assert(len(path) >= 2) # at least: only P -> L node, no intermediates
    if len(path) == 2:
      cut_until = 2
    else:
      cut_until = self._rng.randint(2, len(path) - 1)
    return path[:cut_until]

  ''' 
  def num_procs_sprayed(self):
    return len([None for p in self.paths if p != None])

  def is_proc_sprayed(self, n):
    return self.paths[n] != None
  '''

