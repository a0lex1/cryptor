import networkx as nx, argparse, random, re, sys

from ..common.rangestr import *

def barabasi_digraph(n, m=2, rng=None):
  if rng == None:
    rng = random.Random()
  G0 = nx.barabasi_albert_graph(n, m, seed=rng.randint(0, sys.maxsize))
  G = nx.DiGraph()
  for edge in G0.edges:
    u, v = edge
    G.add_edge(u, v)
  return G


if __name__ == '__main__':
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('--seed', '--seed', required=False)
  parser.add_argument('-m', '--m', default='2', help='int or range')
  parser.add_argument('-n', '--n', default='50..100', help='int or range')
  parser.add_argument('-o', '--outfile', required=True)
  args = parser.parse_args()

  seed = args.seed
  if seed == None:
    seed = random.randint(0, sys.maxsize)
  rng = random.Random(seed)

  #m_range = parse_rangestr(args.m)
  #n_range = parse_rangestr(args.n)
  #print('m_range', m_range, 'n_range', n_range)
  #m = rng.randint(m_range[0], m_range[1])
  #n = rng.randint(n_range[1], n_range[0])

  m = rand_from_rangestr(args.m, rng)
  n = rand_from_rangestr(args.n, rng)

  print('m', m, 'n', n)
  

  G = barabasi_digraph(n, m, rng)
  dot = nx.drawing.nx_pydot.to_pydot(G)
  dot.write_dot(args.outfile)

