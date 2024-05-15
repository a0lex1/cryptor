import os, random, argparse, sys, shutil
import networkx as nx

#for --seed 919044933124393197

inters = [
  (35, 14),
  (16, 1),
  (40, 36),
  (48, 22),
  (29, 7),
  (12, 36),
  (12, 45),
  (27, 41),
  (42, 22),
  (38, 3),
  (148, 12),
  (148, 3),
  (148, 116),
  (54, 76),
  (54, 114),
  (133, 143),
  (133, 131),
  (133, 146),
  (115, 126),
  (47, 55),
  (47, 104),
  (47, 28),
  (47, 77),
  (47, 105),
  (117, 2),
  (68, 58),
  (63, 30),
  (33, 144),
  (144, 9),
  (144, 27),
  (27, 62),
  (145, 27),
  (12, 146),
  (117, 50),
  (114, 42),
  (131, 6),
  (124, 93),
  (124, 31),
]


recurses = [
  (1, 3),
  (30, 33),
  (20, 13),
  (29, 35),
  (38, 49)
]

selfloops = [
  0,
  14,
  1,
  30,
  35
]

def gen(ninters, nrecurses, nselfloops, seed):
  linter = inters[:ninters]
  lrecur = recurses[:nrecurses]
  lselfloop = selfloops[:nselfloops]

  G = nx.random_tree(150, seed, nx.DiGraph)
  for iu, iv in linter:
    G.add_edge(iu, iv)
  for ru, rv in lrecur:
    G.add_edge(ru, rv)
  for s in lselfloop:
    G.add_edge(s, s)
  return G


if __name__ == '__main__':
  _sd = os.path.dirname(__file__)
  j = os.path.join

  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('-i', '--inters', default=0, type=int)
  parser.add_argument('-r', '--recurses', default=0, type=int)
  parser.add_argument('-s', '--selfloops', default=0, type=int)
  parser.add_argument('--seed', type=int, required=False)
  args = parser.parse_args()
  if args.seed:
    seed = args.seed
    print('USING SEED FROM ARGS:', seed)
  else:
    seed = random.randint(0, sys.maxsize)
    print('USING NEW RANDOM SEED:', seed)

  if os.path.isdir(j(_sd, 'td', 'graphs0/')):
    shutil.rmtree(j(_sd, 'td', 'graphs0/'))
  os.makedirs(j(_sd, 'td', 'graphs0/'))

  if not args.inters and not args.recurses and not args.selfloops:
    total = 0
    for kinter in [0, 1, len(inters)]:
      for krec in [0, 1, len(recurses)]:
        for ksl in [0, 1, len(selfloops)]:
          G = gen(kinter, krec, ksl, args.seed)
          nx.drawing.nx_pydot.to_pydot(G).write_dot(
            j(_sd, 'td', 'graphs0', f'i{kinter}_r{krec}_sl{ksl}.dot'))
          total += 1
    print(f'{total} written')
  else:
    gen(args.inters, args.recurses, args.selfloops)





