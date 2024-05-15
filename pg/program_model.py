import networkx as nx
from dataclasses import dataclass

from c2.common.graph import labelnodes

@dataclass
class ProgramModel:
  G : nx.DiGraph = None
  gdata : dict = None
  cached_number_of_userprocs : int = None

  def render_gdata_on_graph(self, width=70):
    labelnodes(self.G, self.gdata, width=width)
    for nid in self.G.nodes:
      if self.gdata[nid]['tt'] == 'R':
        pass
      elif self.gdata[nid]['tt'] == 'G':
        self.G.nodes[nid]['fillcolor'] = '#eeeeee'
        self.G.nodes[nid]['style'] = 'filled'
      else: raise RuntimeError()
    self.G.nodes[0]['penwidth'] = 3
    self.G.nodes[0]['color'] = '#0000aa'



