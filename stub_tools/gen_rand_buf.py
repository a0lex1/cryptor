import argparse, random, hexdump, os, sys

from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE, textualize_seed
from c2.infra.seed_get_or_generate import seed_get_or_generate
from c2.common.sx import Sx


def gen_rand_buf_main(argv):
  parser = argparse.ArgumentParser()
  parser.add_argument('-o', '--out_file', required=True)
  parser.add_argument('-l', '--length_sx', required=True, help='SX string')
  parser.add_argument('--hex_dump', action='store_true')
  cli_seed = CLISeed(os.getcwd(), DEFAULT_SEED_SIZE)
  cli_seed.add_to_argparser(parser)
  args = parser.parse_args(argv)
  cli_seed.set_parsed_args(args)

  seed = seed_get_or_generate(cli_seed, DEFAULT_SEED_SIZE)
  print(f'gen_rand_buf.py using seed {textualize_seed(seed)}')
  rng = random.Random(seed)
  print(f'<gen_rand_buf rng probe: {rng.randint(0, sys.maxsize)}>')

  gen_rand_buf = lambda n: bytearray(map(rng.getrandbits,(8,)*n))

  byte_len = Sx(args.length_sx, rng).make_number()
  print(f'Chosen length: {byte_len}')
  rand_buf = gen_rand_buf(byte_len)

  print(f'Writing to {args.out_file}')
  open(args.out_file, 'wb').write(rand_buf)

  if args.hex_dump:
    print('hexdump:')
    hexdump.hexdump(rand_buf)

  print(f'get_rand_buf.py saved the file {args.out_file}')


if __name__ == '__main__':
  gen_rand_buf_main(sys.argv[1:])

