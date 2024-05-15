import networkx as nx

from .textualizer import *

class Node2Graph:
  def __init__(self, stmtlist:node_stmtlist, save_G_nids=True):
    self.G = nx.DiGraph() # output
    self.nextnid = 0
    self.G.add_node(self.nextnid)
    self._prevnid = 0
    self.nextnid += 1
    self.save_G_nids = save_G_nids
    self._visit(stmtlist)

  def _visit(self, node):
    texer = Textualizer(None)
    #dasd
    recurs = self._visit
    if node.children == None:
      return
    for chnode in node.children:
      if chnode == None:
        continue
      self.G.add_node(self.nextnid)
      self.G.add_edge(self._prevnid, self.nextnid)
      if chnode.children != None and len(chnode.children):
        self.G.nodes[self.nextnid]['label'] = type(chnode).__name__
      else:
        self.G.nodes[self.nextnid]['label'] = texer.visit(chnode)
      self.G.nodes[self.nextnid]['label'] += f' ({self.nextnid})'
      if self.save_G_nids:
        chnode.G_nid = self.nextnid
      old_prevnid = self._prevnid
      self._prevnid = self.nextnid
      self.nextnid += 1
      recurs(chnode)
      self._prevnid = old_prevnid

