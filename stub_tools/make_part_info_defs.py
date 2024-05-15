#make_part_info_defs.py  -p ldr pay alloc_valloc  -o PART_INFO_DEFS.h
import argparse, json, re, os, sys

from c2.infra.tool_cli import ToolCLI

_sd = os.path.dirname(__file__)


class MakePartInfoDefsCLI(ToolCLI):
  def _initialize(self):
    self._progname = os.path.basename(__file__)

  def _setup_args(self):
    parser = self._parser
    gexcl = parser.add_mutually_exclusive_group(required=True)
    gexcl.add_argument('-p', '--parts', nargs='*', action='append')
    gexcl.add_argument('-l', '--lst_file', help='path to parts.lst')
    parser.add_argument('-o', '--out_file', required=True)


  def _do_work(self):
    args = self._args

    self.__part2defs = {}
    self.__part2weakdefs = {}

    if args.parts:
      parts = sum(args.parts, [])
    else:
      assert(args.lst_file)
      parts = [line.strip() for line in open(args.lst_file, 'r').readlines()]
      print(f'loaded {len(parts)} from file {args.lst_file}:')
      print(parts)
      print()

    for part in parts:
      if not re.match('^[\w\d_]+$', part):
        raise RuntimeError(f'malformed {part=} in parts')

      self.__collect_partinfo_if_present(part)

    print('parts have correct names')

    self.__dump_partinfo_header()
    print('part info header dumped')


  def __collect_partinfo_if_present(self, cpp_file_title):
    optional_json_file = f'{_sd}/../cpp_parts/{cpp_file_title}.json'
    if os.path.exists(optional_json_file):
      print(f'optional_json_file exists for {cpp_file_title}')
      part_info = json.load(open(optional_json_file, 'r'))
      if 'defs' in part_info:
        self.__part2defs[cpp_file_title] = part_info['defs']
      if 'weak_defs' in part_info:
        self.__part2weakdefs[cpp_file_title] = part_info['weak_defs']


  def __dump_partinfo_header(self):
    args = self._args
    with open(args.out_file, 'w') as f:
      w = f.write
      w('#pragma once\n\n')

      for partname in self.__part2defs.keys():
        w(f'// part \'{partname}\' defs\n')
        defdict = self.__part2defs[partname]
        for def_key in defdict.keys():
          def_value = defdict[def_key]
          if def_value == None:
            def_value = ''
          w(f'#define {def_key} {def_value}\n')
        w('\n\n')

      w('// Note: we could just remove non-unique keys from defs, but if we do, construct.py would have to be the single point of managing what key is already used and what isn\'t')
      for partname in self.__part2weakdefs:
        w(f'// part \'{partname}\' weak defs\n')
        defdict = self.__part2weakdefs[partname]
        for def_key in defdict.keys():
          def_value = defdict[def_key]
          if def_value == None:
            def_value = ''
          w(f'#ifndef {def_key}\n')
          w(f'#define {def_key} {def_value}\n')
          w(f'#endif\n')
        w('\n\n')



if __name__ == '__main__':
  MakePartInfoDefsCLI(sys.argv[1:]).execute()

