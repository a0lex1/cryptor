import os, sys, argparse, random, base64

from c2.infra.seed import DEFAULT_SEED_SIZE
from c2.infra.seed_db import SeedDB

#create_seed_file.py --if_not_exist -o %~dp0\seedfile  -s pg spg binhide


def create_seed_file_main(argv):
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('--if_not_exist', action='store_true')
  parser.add_argument('-o', '--output_file', required=True)
  parser.add_argument('-s', '--sections', nargs='*', action='append', required=True)
  parser.add_argument('--size', default=DEFAULT_SEED_SIZE)
  args = parser.parse_args(argv)

  sections = sum(args.sections, [])

  if args.if_not_exist:
    if os.path.isfile(args.output_file):
      print('NOTHING TO DO. --if_not_exist specified AND the file DOES exist. OK.')
      exit(0)

  seed_db = SeedDB(args.size)
  seed_db.generate(sections)
  seed_db.write_to_file(open(args.output_file, 'w'))



if __name__ == '__main__':
  create_seed_file_main(sys.argv[1:])


