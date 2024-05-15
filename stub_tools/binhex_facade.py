import os, sys, argparse

_sd = os.path.dirname(__file__)
_binhex_exe = f'{_sd}/binhex.exe'


def binhex_facade_main(argv):
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('-i', '--input_file', required=True)
  parser.add_argument('-o', '--output_file', required=True)
  parser.add_argument('--name', required=True, help='made required in facade because facade needs to know it')
  parser.add_argument('--str', action='store_true')
  parser.add_argument('--no_cpp', action='store_true')
  args = parser.parse_args(argv)
  xtra_args = ''
  if args.name:
    xtra_args += '--name='+args.name+' '
  if args.str:
    xtra_args += '--str '
  cmd = f'{_binhex_exe} {args.input_file} {args.output_file} ' + xtra_args
  print('EXECUTING CMD:::', cmd)
  r = os.system(cmd)
  if r != 0:
    raise RuntimeError(f'binhide.exe exited with code {r}')

  output_dir = os.path.dirname(os.path.abspath(args.output_file))
  print(f'{args.output_file=} {output_dir=}')

  if not args.no_cpp:
    # place includer cpp/h
    output_basename = os.path.basename(args.output_file)
    header_text =\
f'''#pragma once

extern const size_t {args.name}_len;
extern unsigned char {args.name}_data[];
'''
    cpp_text = \
f'''
// extern
#include "./include_{output_basename}.h"

// definition
#include "./{output_basename}"
'''
    path_h = f'{output_dir}/include_{output_basename}.h'
    path_cpp = f'{output_dir}/include_{output_basename}.cpp'
    open(path_h, 'w').write(header_text)
    open(path_cpp, 'w').write(cpp_text)

    print('.cpp and .h files written (use --no_cpp to disable this), paths:', path_h, path_cpp)


if __name__ == '__main__':
  binhex_facade_main(sys.argv[1:])


