'''
 __   ___   ___    __    _    _____   __    ___
( (` | |_) | |_)  / /\  \ \_/  | |   / /\  | |_)
_)_) |_|   |_| \ /_/--\  |_|   |_|  /_/--\ |_|_)  your life for nothing
'''
import argparse, re, fnmatch, json, sys, os
from typing import List, Tuple
from dataclasses import dataclass, field

from c2.sprayer.ctools.preprocessor_cmd_system import PreprocessorCmdSystem, CmdInfo
from c2.sprayer.ctools.defines_collector import DefinesCollector
from c2.sprayer.ctools.macro_follower import MacroFollower
from c2.sprayer.ctools.parse_c_define import parse_c_define
from c2.infra.tool_cli import ToolCLI


@dataclass
class CollectorData:
  proctups:        List[Tuple[str, List[str]]]   = field(default_factory=list)
  zvars:           List[List[str]]               = field(default_factory=list)
  vstatic_vars:    List[List[str]]               = field(default_factory=list)
  headers:         List[List[str]]               = field(default_factory=list)
  privdefs:        List[Tuple[str, str]]         = field(default_factory=list)
  proc_opts:       dict                          = field(default_factory=dict)
  structs:         List[str]                     = field(default_factory=list)
  struct_fields:   dict                          = field(default_factory=dict)
  struct_opts:     dict                          = field(default_factory=dict)
  raw_lines:       List[str]                     = field(default_factory=list)
  libs:            List[str]                     = field(default_factory=list)
  root_proc:       str                           = None


class CollectorCmdSystem(PreprocessorCmdSystem):
  def set_data(self, data:CollectorData):
    self.__data = data # output

  def get_data(self) -> CollectorData:
    return self.__data

  def _setup(self):
    self.__procs = {}
    self.__cur_proc_lines = []
    self.__cur_zvar_lines = []
    self.__cur_staticvar_lines = []
    self.__cur_header_lines = []
    self.__cur_privdefs = []
    self.__cur_struct_name = None
    self.__cur_struct_is_mix = False
    self.__cur_struct_field_lines = []
    self.__cur_proc = None
    self.__cur_proc_is_from_decl = None
    self.__cur_proc_is_root = None
    self.__cur_raw_lines = []
    self.__cur_lib_lines = []

    # add all //@@@commands //@@@endcommands
    self._register_cmd_pair(CmdInfo('proc', min_args=1), CmdInfo('endproc', max_args=0)) # proc's max_args not set
    self._register_cmd_pair(CmdInfo('zvars', max_args=0), CmdInfo('endzvars', max_args=0))
    self._register_cmd_pair(CmdInfo('staticvars', max_args=0), CmdInfo('endstaticvars', max_args=0))
    self._register_cmd_pair(CmdInfo('headers', max_args=0), CmdInfo('endheaders', max_args=0))
    self._register_cmd_pair(CmdInfo('privdefs', max_args=0), CmdInfo('endprivdefs', max_args=0))
    self._register_cmd_pair(CmdInfo('structfields', min_args=1), CmdInfo('endstructfields', max_args=0))
    self._register_cmd_pair(CmdInfo('rawlines', max_args=0), CmdInfo('endrawlines', max_args=0))
    self._register_cmd_pair(CmdInfo('libs', max_args=0), CmdInfo('endlibs', max_args=0))


  def finalize(self):
    super().finalize()
    data = self.__data
    # add collected to proctups (ordered list)
    for k in self.__procs.keys():
      # (FuncName, ['line1', ...])
      if k in [p[0] for p in data.proctups]:
        raise RuntimeError(f'duplicated proc - {k}')
      data.proctups.append( (k, self.__procs[k]) )

  def _cmdsys_handle_outside_line(self, line):
    # we not interested in usual source code lines cuz we're only a collector of specific types of lines
    return


  def _cmdsys_handle_inside_line(self, line):
    cmd = self.cur_opencmd_stack[-1]
    data = self.__data
    if cmd == 'zvars':
      self.__cur_zvar_lines.append(line)
    elif cmd == 'staticvars':
      self.__cur_staticvar_lines.append(line)
    elif cmd == 'proc':
      if not re.match(r'\s*\/\/.*?', line):  # if not a comment line
        self.__cur_proc_lines.append(line)
    elif cmd == 'headers':
      include_filename = self.__parse_header_line(line)
      if include_filename:
        self.__cur_header_lines.append(include_filename)
    elif cmd == 'privdefs':
      tup = parse_c_define(line)
      if not tup:
        raise RuntimeError(f'the line is not a C #define line - {line}')
      k, v = tup
      self.__cur_privdefs.append((k, v))
    elif cmd == 'structfields':
      self.__cur_struct_field_lines.append(line)
    elif cmd == 'rawlines':
      self.__cur_raw_lines.append(line)
    elif cmd == 'libs':
      self.__cur_lib_lines.append(line)
    else:
      raise RuntimeError(f'unknown current {cmd=}')

  ### --- all open cmds ---
  def _cmdsys_opencmd_hook(self, macro_name, macro_opts):
    data = self.__data
    if macro_name == 'proc':
      if '/decl' in macro_opts:
        assert (not '/name' in macro_opts)
        self.__cur_proc = macro_opts['/decl']
        self.__cur_proc_is_from_decl = True
      elif '/name' in macro_opts:
        self.__cur_proc = macro_opts['/name']
        self.__cur_proc_is_from_decl = False
      else:
        raise RuntimeError(f'@@@proc needs either /decl or /name (mopts: {macro_opts})')
      is_root = '/root' in macro_opts
      if is_root:
        if data.root_proc != None:
          raise RuntimeError('only one root proc is allowed')
      self.__cur_proc_is_root = is_root
    elif macro_name == 'structfields':
      self.__cur_struct_name = macro_opts['/name']
      self.__cur_struct_is_mix = '/mix' in macro_opts
    else:
      # not interested in other open cmds
      pass

  ### --- all close cmds ---
  def _cmdsys_closecmd_hook(self, macro_name, macro_opts):
    data = self.__data
    if macro_name == 'endproc':
      # cur_proc_lines can be empty
      self.__procs[self.__cur_proc] = self.__cur_proc_lines
      if self.__cur_proc_is_from_decl:
        data.proc_opts.setdefault(self.__cur_proc, {})['is_from_decl'] = 1
      if self.__cur_proc_is_root:
        assert (data.root_proc == None)
        data.root_proc = self.__cur_proc
      self.__cur_proc_lines = []
      self.cur_proc = None
    elif macro_name == 'endzvars':
      data.zvars.append(self.__cur_zvar_lines)
      self.__cur_zvar_lines = []
    elif macro_name == 'endstaticvars':
      data.vstatic_vars.append(self.__cur_staticvar_lines)
      self.__cur_staticvar_lines = []
    elif macro_name == 'endheaders':
      data.headers.append(self.__cur_header_lines)
      self.__cur_header_lines = []
    elif macro_name == 'endprivdefs':
      data.privdefs += self.__cur_privdefs
      self.__cur_privdefs = []
    elif macro_name == 'endstructfields':
      data.structs.append(self.__cur_struct_name)
      data.struct_fields[self.__cur_struct_name] = self.__cur_struct_field_lines
      if self.__cur_struct_is_mix:
        data.struct_opts.setdefault(self.__cur_struct_name, {})['is_mix'] = 1
      self.__cur_struct_field_lines = []
    elif macro_name == 'endrawlines':
      data.raw_lines += self.__cur_raw_lines
      self.__cur_raw_lines = []
    elif macro_name == 'endlibs':
      data.libs += self.__cur_lib_lines
      self.__cur_lib_lines = []
    else:
      raise RuntimeError(f'unknown {macro_name=} (macro_opts={macro_opts}')


  def __parse_header_line(self, header_line):
    m = re.match('^#include [\<"](.+?)[\>"]$', header_line)
    return m[0] if m else None # return full line



class SpraytabCollector:
  def __init__(self, macro_follower:MacroFollower):
    self.data = CollectorData() # output
    self.__macro_follower = macro_follower

  def process_file(self, fname):
    # Create new CollectorCmdSystem for every file, but reuse |data|. This seems reasonable.
    self.__cmdsys = CollectorCmdSystem(self.__macro_follower, '@@@')
    self.__cmdsys.set_data(self.data)
    self.__cmdsys.initialize()
    for line in open(fname, 'r').readlines():
      self.__cmdsys.input_line(line)
    self.__cmdsys.finalize()



class SpraytabCLI(ToolCLI):
  def _initialize(self):
    self._progname = os.path.basename(__file__)

  def _setup_args(self):
    # cpp and cpp_dir are arrays and can be combined
    parser = self._parser
    parser.add_argument('-d', '--cpp_dir', nargs='+', action='append', required=False)
    parser.add_argument('-c', '--cpp', nargs='+', action='append', required=False)
    parser.add_argument('-o', '--out_dir', required=False, help='current dir by default')
    parser.add_argument('-D', '--define', nargs='+', action='append', required=False)
    parser.add_argument('-X', '--definition_header', nargs='+', action='append', required=False)
    parser.add_argument('-z', '--dump_headers', help='otherwise, add to spraytab', required=False)
    parser.add_argument('--sep_vars_h', help='(they are now staticvars) deprecated mode of strong gened_vars.h on disk',
                        action='store_true')
    parser.add_argument('--allow_nonexisting', action='store_true')
    
  def _do_work(self):
    args = self._args
    out_dir = os.path.realpath(args.out_dir if args.out_dir else '')

    if not args.cpp_dir and not args.cpp:
      raise RuntimeError('either -d (--cpp_dir) or -c (--cpp, single file) must be specified')
  
    defs = self.__collect_defs()

    self.__collector = SpraytabCollector(MacroFollower(defs))
    collector = self.__collector
    
    if args.cpp:
      self.__process_cpp_files()
  
    if args.cpp_dir:
      self.__process_cpp_dirs()
  
    # shortcut vars to simplify code
    collected_proc_tups = collector.data.proctups  # (procname, [lines...])
    collected_zvars = collector.data.zvars
    collected_vstatic_vars = collector.data.vstatic_vars
    collected_headers = collector.data.headers
    collected_privdefs = collector.data.privdefs
    collected_proc_opts = collector.data.proc_opts
    collected_root_proc = collector.data.root_proc
    collected_structs = collector.data.structs
    collected_struct_fields = collector.data.struct_fields
    collected_struct_opts = collector.data.struct_opts
    collected_raw_lines = collector.data.raw_lines
    collected_libs = collector.data.libs
    print(f'[ ] ROOT PROC ---> {collected_root_proc}')
  
    if not args.dump_headers and len(collected_headers) != 0:
      print('@@@headers will be added to spraytab because -z not specified')
  
    # TODO: remove this prints, just spit json
    print(f'[+] {len(collected_proc_tups)} procs collected:')
    for proctup in collected_proc_tups:
      print(f'  [>] {len(proctup[1])} lines\t--\t{proctup[0]}()')
  
    linecounts_sig = ",".join([str(len(p[1])) for p in collected_proc_tups])
    print(f'[ ] linecounts_sig -> {linecounts_sig}')
  
    print(f'[ ] writing spraytab.json')
  
    # make json spraytab and write it to file
    spraytab = {
      'root_proc': collected_root_proc,
      'procs': [tup[0] for tup in collected_proc_tups],
      'proc_opts': collected_proc_opts,
      'lines': {k[0]: k[1] for k in collected_proc_tups}
    }
    assert (len(spraytab['procs']) == len(spraytab['lines']))
  
    # Manager zvars
    spraytab['zvars'] = []
    for sublist in collected_zvars:
      for _ in sublist:
        spraytab['zvars'].append(_)
  
    # Manage static vars
    spraytab['staticvars'] = []
    for sublist in collected_vstatic_vars:
      for _ in sublist:
        spraytab['staticvars'].append(_)
  
    # Manage headers. Uniqualize them. WARNING: case sensitive
    # collected headers example: [['#include "ae_xxx.h"'], ['#include "decrypt_cryptbin.h"'],
    unique_header_lines = {}
    for hlines in collected_headers:
      for hline in hlines:
        unique_header_lines[hline] = None
    spraytab['headers'] = list(unique_header_lines.keys())
  
    # Manage privdefs
    spraytab['privdefs'] = dict(collected_privdefs)
  
    spraytab['structs'] = collected_structs
    spraytab['struct_fields'] = collected_struct_fields
    spraytab['struct_opts'] = collected_struct_opts
    spraytab['raw_lines'] = collected_raw_lines
    spraytab['libs'] = list(set(collected_libs))
  
    # write spraytab to file
    path = f'{out_dir}/spraytab.json'
    with open(path, 'w') as fj:
      fj.write(json.dumps(spraytab, indent=2))
  
    # ----------------------- spraytab.json has been written -------------------------------
  
    if args.sep_vars_h:  # deprecated mode, write vars to gened_vars.h
      print('[ ] writing gened_vars.h')
      path = f'{out_dir}/gened_vars.h'
      with open(path, 'w') as fvars:
        fvars.write(f'// Auto-generated with: {" ".join(sys.argv)} ;\n')
        fvars.write('// This file might not be used as a separate file\n\n')
        for vl in collected_vstatic_vars:
          fvars.write('//\n')
          for v in vl:
            fvars.write(v + '\n')
        fvars.write('\n')
    else:
      # new mode (storing vars inside spraytab); already added above
      pass
  
    if args.dump_headers:
      # deprecated thing, dump headers to file
      print(f'[ ] writing HEADERS (-z opt specified) to {args.dump_headers}')
      with open(args.dump_headers, 'w') as fhdrs:
        fhdrs.write(f'// Auto-generated with: {" ".join(sys.argv)} ;\n\n')
        fhdrs.write('// Headers\n\n')
        for unique_line in unique_header_lines:
          fhdrs.write(f'{unique_line}\n')
        fhdrs.write('\n')
  
    print()
    print('[+] spraytab.py done')


  def __collect_defs(self):
    args = self._args
    if args.definition_header:
      print('[ ] defs: collecting #ifdef/#ifndef/#else/#endif ...')
      defcollector = DefinesCollector()
      for header_path in sum(args.definition_header, []):
        print(f'[ ] defs: collecting from {header_path}')

        if not os.path.exists(header_path):
          if not args.allow_nonexisting:
            raise RuntimeError(
              f'Definition header {header_path} doesn\'t exist AND nonexisting files not allowed (no --allow_nonexisting opt)')
          else:
            print(f'[-] DEFINITION HEADER DOES\'T EXIST, IGNORING - {header_path}')
        else:
          defcollector.collect_definitions(open(header_path, 'r').read())

      defs = defcollector.get_collecteddefs()
      print(f'[+] defs: Total {len(defs)} defs collected:')
      for d in defs:
        print(f'[ ]   #define  {d}')
      print()
    else:
      defs = []
      print('[ ] defs: NO defs defined.')
    return defs


  def __process_cpp_files(self):
    collector = self.__collector
    args = self._args
    for cp in args.cpp:
      fname = cp[0]
      print('[ ] processing single (-c) file', fname)
      if not os.path.exists(fname):
        if not args.allow_nonexisting:
          raise RuntimeError(
            f'File {fname} doesn\'t exist AND nonexisting files not allowed (no --allow_nonexisting opt)')
        else:
          print(f'[-] FILE DOES\'T EXIST, IGNORING - {fname}')
      else:
        collector.process_file(fname)


  def __process_cpp_dirs(self):
    args = self._args
    collector = self.__collector
    for dirname in sum(args.cpp_dir, []):
      print('[+] processing DIRECTORY (-d)', dirname)
      if not os.path.exists(dirname):
        if not args.allow_nonexisting:
          raise RuntimeError(
            f'Directory {dirname} doesn\'t exist AND nonexisting files not allowed (no --allow_nonexisting opt)')
        else:
          print(f'[-] DIRECTORY DOES\'T EXIST, IGNORING - {dirname}')
      else:
        for root, dirs, files in os.walk(dirname):
          for file in files:
            fullp = os.path.join(root, file)
            print('[ ]   processing file in dir:', fullp)
            if fnmatch.fnmatch(fullp, '*.cpp') or fnmatch.fnmatch(fullp, '*.h'):
              collector.process_file(fullp)



if __name__ == '__main__':
  SpraytabCLI(sys.argv[1:]).execute()













