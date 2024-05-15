import urllib, re, random, os, sys, argparse
import networkx as nx

from c2.common.sx import Sx
from c2.common.graph import save_graph


class GraphFactory:
  def __init__(self, graph_init_string, rng=None):
    if rng == None:
      rng = random.Random()
    self._graph_init_string = graph_init_string
    self._rng = rng

  def create_graph(self) -> nx.Graph:
    pars_res = urllib.parse.urlparse(self._graph_init_string)
    if pars_res.scheme == 'barabasi':
      assert(pars_res.netloc == 'default')
      query_dict = urllib.parse.parse_qs(pars_res.query)
      # parse_qs returns key->[val] because there may be several values with same name: a=1&b=2&c=3&b=2&b=3&b=5
      m_sx = query_dict['m_sx'][0]
      n_sx = query_dict['n_sx'][0]
      m = Sx(m_sx, self._rng).make_number()
      n = Sx(n_sx, self._rng).make_number()
      print(f'[ ] Generating graph for opts ({n=} {m=}, sxes was: {n_sx=}, {m_sx=})')
      call_graph = self._barabasi_digraph(n, m)
    elif pars_res.scheme == 'testgstock':
      self._validate_filename(pars_res.netloc)
      dotpath = f'{_sd}/sprayer/test/td/graphs0/{pars_res.netloc}'
      call_graph = nx.drawing.nx_pydot.read_dot(dotpath)
    elif pars_res.scheme == 'testlegal':
      self._validate_filename(pars_res.netloc)
      dotpath = f'{_sd}/sprayer/test/td/otherapp_graphs0/{pars_res.netloc}'
      call_graph = nx.drawing.nx_pydot.read_dot(dotpath)
    else:
      raise RuntimeError(f'unknown scheme - {pars_res.scheme}')
    return call_graph

  def _validate_filename(self, name):
    re.match('^[\w\d\s\.]+$', name) #Security

  def _barabasi_digraph(self, n, m=2):
    G0 = nx.barabasi_albert_graph(n, m, seed=self._rng.randint(0, sys.maxsize))
    G = nx.DiGraph()
    for edge in G0.edges:
      u, v = edge
      G.add_edge(u, v)
    return G


_sd = os.path.dirname(__file__)

if __name__ == '__main__':
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('graph_init_str')
  parser.add_argument('--out_file', required=False)
  parser.add_argument('--show', action='store_true')
  args = parser.parse_args()
  gf = GraphFactory(args.graph_init_str)
  G = gf.create_graph()
  if args.out_file:
    dot = nx.drawing.nx_pydot.to_pydot(G)
    dot.write_dot(args.out_file)
    if args.show:
      # Security  inserting args.out_file into os.sytem() command!
      os.system('"'+args.out_file+'"'+' > NUL')
  else:
    if args.show:
      raise RuntimeError('cannot --show without --out_file')

