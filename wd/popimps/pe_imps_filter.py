import argparse, os, sys

from c2.trasher.common.is_ms_dll import is_ms_dll


def pe_imps_filter_main(argv, out_stm=None):
  if out_stm == None:
    out_stm = sys.stdout
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('-i', '--input', required=True)
  parser.add_argument('--min_count', type=int, required=True)
  parser.add_argument('--allow_non_ms', action='store_true', help='don\'t eliminate imports from non-ms dlls (no guaranteed to be present on other systems)')
  parser.add_argument('--bla', required=False)
  parser.add_argument('--no_header', action='store_true')
  args = parser.parse_args(argv)
  skipped = 0
  first_line = True
  if not args.no_header:
    out_stm.write('dll,func,count\n')
  for line in open(args.input, 'r').readlines():
    if not args.no_header:
      if first_line:
        # skip header line
        first_line = False
        continue
    line = line.rstrip()
    dll, func, count = line.split(',')

    if not args.allow_non_ms:
      if not is_ms_dll(dll):
        print(f'NON-MS DLL SKIPPED - {dll} (use --allow_non_ms if you want it)')
        continue

    count = int(count)
    if count >= args.min_count:
      out_stm.write(f'{dll},{func},{count}\n')
    else:
      skipped += 1


if __name__ == '__main__':
  pe_imps_filter_main(sys.argv[1:])



