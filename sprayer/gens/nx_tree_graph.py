import random
import networkx as nx
from c2.common.graph import save_graph

class NXTreeGraphGen:
  def __init__(self, num_leafs, rng):
    self.num_leafs = num_leafs

    self._rng = rng

    self.seq = None
    self.G = None ##
    self.root_nid = None ##
    self.next_nid = None ##

  def gen_seq(self):
    self.seq = ['e' for i in range(self.num_leafs)] + ['l' for j in range(self.num_leafs)]
    self._rng.shuffle(self.seq)
    #print('TreeGraphGen.seq', self.seq)
    # seq = ['l', 'l', 'l', 'e', 'e', 'e', 'e', 'e', 'l', 'e', 'e', 'e', 'l', 'l', 'e', 'l', 'l', 'l', 'e', 'l']

  def make_tree(self):
    # e=enter, l=leave
    self.G = nx.DiGraph()
    G = self.G
    id = 1
    seq = self.seq
    self.root_nid = 0
    G.add_node(self.root_nid)
    stack = [0]
    for i in range(0, len(seq)):
      assert (len(stack) >= 1)
      if seq[i] == 'e':
        #print(f'adding node {id} (prev {stack[-1]})')
        G.add_node(id)
        #if len(stack):
        G.add_edge(stack[-1], id)  # add edge to prev node
        stack.append(id)
        id += 1
      elif seq[i] == 'l':
        if len(stack) > 1:
          stack.pop()
    self.next_nid = id
    # stack can still have elements, we don't care
    pass


# class Recombiner - limit the depth of graph G by moving too long nodes to root
class NXTreeGraphRecombiner:
  def __init__(self, G, root_nid):
    self.G = G
    self.root_nid = root_nid
    self.new_G = None
    self.new_root_nid = None

  def recomb(self, max_depth):
    self._max_depth = max_depth
    self._lev = 0
    self._prev_nid = None
    self.new_G = self.G.copy()
    while True:
      num_recomb = self._visit(self.root_nid)
      if num_recomb == 0:
        break
    self.new_root_nid = self.root_nid

  def _visit(self, nid):
    new_G = self.new_G
    if self._lev > self._max_depth:
      if self._prev_nid != None:
        # unlink from previous (parent) and link to root
        # since the edge is added to the right side (nx behavior),
        # such recombination can't break the 'next nid' > 'prev nid' rule
        new_G.remove_edge(self._prev_nid, nid)
        new_G.add_edge(self.root_nid, nid)
      return 1 # num recombined
    children = list(new_G.successors(nid))
    ret = 0
    for child_nid in children:
      self._lev += 1
      self._prev_nid = nid
      ret += self._visit(child_nid)
      self._lev -= 1
    return ret



def _sample_nx_tree_graph():
  gg = NXTreeGraphGen(5, random.Random())
  gg.gen_seq()
  gg.make_tree()
  save_graph(gg.G, file_title='NXTreeGraphGen', show=True)

if __name__ == '__main__':
  _sample_nx_tree_graph()

