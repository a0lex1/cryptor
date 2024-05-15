### resput.py -o --shuffle bitmap:0-5%,single icon:50-99%,multi
### TODO: use wd.ResourceRepository, don't directly os.listdir(get_resrepository_dir())
###       (this script will probably be placed to stub_tools/)
### TODO: size management

import os, sys, argparse, random, re, shutil

from c2._internal_config import get_resrepository_dir
from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE
from c2.infra.seed_get_or_generate import seed_get_or_generate

def parse_shuffle(s):
  m = re.match('^(.+?):([0-9]+)(-[0-9]+)?%,(.+?)$', s)
  t = m[1]
  per = int(m[2])
  if m[3] != None:
    assert(m[3][0] == '-')
    permax = int(m[3][1:])
  else:
    permax = None
  f = m[4]
  return (t, per, permax, f)

#_sd = os.path.dirname(__file__)

if __name__ == '__main__':
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('--dbs', nargs='*', action='append', help='whitelist')
  parser.add_argument('-c', '--clear', action='store_true')
  parser.add_argument('-o', '--outdir', default='rsrc')
  #parser.add_argument('-s', '--shuffle', nargs='+', action='append', required=False)
  cliseed = CLISeed(os.getcwd(), DEFAULT_SEED_SIZE)
  cliseed.add_to_argparser(parser)

  args = parser.parse_args()
  cliseed.set_parsed_args(args)

  seed = seed_get_or_generate(cliseed, DEFAULT_SEED_SIZE)
  rng = random.Random(seed)
  print(f'<resput.py rng probe: {rng.randint(0, sys.maxsize)}>')

  '''shuffle = []
  if args.shuffle:
    for a in args.shuffle:
      for b in a:
        shuffle.append(b)
  parshufs = [parse_shuffle(ps) for ps in shuffle]
  if parshufs:
    raise RuntimeError('todo')'''
  j = os.path.join

  whitelist_dbs = sum(args.dbs, []) if args.dbs else None
  if whitelist_dbs != None:
    print('whitelist dbs:', whitelist_dbs)

  all_paths = []
  ### TODO ###
  for dbname in os.listdir(get_resrepository_dir()):
    if whitelist_dbs != None:
      if not dbname in whitelist_dbs:
        print('resput: db EXCLUDED by whitelist:', dbname)
        continue
    fullp = j(get_resrepository_dir(), dbname)
    if not os.path.isdir(fullp):
      continue
    if dbname.startswith('_'):
      continue
    print('resput: db dir:', fullp)
    for x in os.listdir(fullp):
      xp = j(fullp, x)
      if os.path.isdir(xp):
        all_paths.append(xp)
  #dirs = [d for d in os.listdir(j(get_resdbs_dir(), args.db)) if not d.startswith('!')]
  #randres = rng.choice(dirs)
  randres = rng.choice(all_paths)

  if args.clear:
    shutil.rmtree(args.outdir, ignore_errors=True)
  
  print(f'random resource chosen from {len(all_paths)} resources: {randres}')

  j = os.path.join
  shutil.copytree(randres, args.outdir)

