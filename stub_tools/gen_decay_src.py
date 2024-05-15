import os, sys, argparse, random

from c2.common.sx import Sx # first time stub tools referencing other c2 source #historical
from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE, textualize_seed
from c2.infra.seed_get_or_generate import seed_get_or_generate


parser = argparse.ArgumentParser(os.path.basename(__file__))
parser.add_argument('-o', '--outdir', default='src_decay')
parser.add_argument('--cpp_count_sx', type=str, required=True)
parser.add_argument('--c_count_sx', type=str, required=True)

cli_seed = CLISeed(None, DEFAULT_SEED_SIZE)
cli_seed.add_to_argparser(parser)

args = parser.parse_args()

cli_seed.set_parsed_args(args)

seed = seed_get_or_generate(cli_seed, DEFAULT_SEED_SIZE)
print(f'gen_decay_src.py using seed {textualize_seed(seed)}')
rng = random.Random(seed)
print(f'<gen_decay_src.py rng probe: {rng.randint(0, sys.maxsize)}>')

cpp_count = Sx(args.cpp_count_sx, rng).make_number()
c_count = Sx(args.c_count_sx, rng).make_number()

print('-= gen_decay_src <--!--> the Decay Generator =-')
print(f'{cpp_count=} {c_count=} ({args.cpp_count_sx=} {args.c_count_sx=})')

print(f'making dir {args.outdir}')
os.makedirs(args.outdir, exist_ok=True)

print(f'generating decay src to outdir {args.outdir}')

for i in range(cpp_count):
  fname = os.path.join(args.outdir, f'decay{i}.cpp')
  open(fname, 'w').close()
print(f'{cpp_count} CPP files generated')

for i in range(c_count):
  fname = os.path.join(args.outdir, f'decay{i}.c')
  open(fname, 'w').close()
print(f'{c_count} C files generated')

print('done generating decay src')

