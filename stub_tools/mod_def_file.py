import os, sys, argparse, random, string

from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE, textualize_seed
from c2.infra.seed_get_or_generate import seed_get_or_generate

def rand_string(len_min, len_max, rng):
  source = string.ascii_letters + string.digits
  len = rng.randint(len_min, len_max)
  result_str = ''.join((rng.choice(source) for i in range(len)))
  return result_str

parser = argparse.ArgumentParser(os.path.basename(__file__))
parser.add_argument('-l', '--libname', required=False)
parser.add_argument('-e', '--export', nargs='+', action='append', required=True)
parser.add_argument('-o', '--out_header', required=True)

cli_seed = CLISeed(None, DEFAULT_SEED_SIZE)
cli_seed.add_to_argparser(parser)

args = parser.parse_args()

cli_seed.set_parsed_args(args)


exps = []
for exp in args.export:
  exp = exp[0]
  exps.append(exp.split('='))

seed = seed_get_or_generate(cli_seed, DEFAULT_SEED_SIZE)
print(f'mod_def_file.py using seed {textualize_seed(seed)}')
rng = random.Random(seed)
print(f'<mod_def_file.py rng probe: {rng.randint(0, sys.maxsize)}>')

libname = args.libname
if libname == '$randstr$':
  libname = rand_string(5, 15, rng)

with open(args.out_header, 'w') as f:
  if args.libname:
    f.write(f'LIBRARY {libname}\n')
  f.write(f'EXPORTS\n')
  for f_alias, f_name in exps:
    if f_alias == '$randstr$':
      f_alias = rand_string(5, 15, rng)
    f.write(f'  {f_alias}={f_name}\n')
  f.write('\n')

