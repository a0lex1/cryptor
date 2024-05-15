import argparse, shutil, csv, re, fnmatch, glob, os, sys

from c2._internal_config import get_popularimports_dir, get_touchprj_dir, get_tmp_dir
from c2.sprayer.test.spraytest_project import SpraytestProject
from c2.infra.tool_cli import ToolCLI
from c2.common.line_reader import LineReader
from c2.common.fnmatch_one_of import fnmatch_one_of


_sd = os.path.dirname(__file__)

class PopularImportsCsvToTouchPrj(ToolCLI):
  def _initialize(self):
    self._progname = os.path.basename(__file__)
    self._st = None
    self._include_dlls_up = None # contains uppercase value
    self._exclude_dlls_up = None # contains uppercase value
    self._touchprj_dir = None
    self._mod2proclist = None
    self._retcode = 99919192

  def _setup_args(self):
    parser = self._parser
    gdll = parser.add_mutually_exclusive_group(required=False)
    gdll.add_argument('--dllinclude_file', help='text file, lines TODO: class LineReader')
    gdll.add_argument('--dllexclude_file', help='text file, lines TODO: class LineReader')
    gfn = parser.add_mutually_exclusive_group(required=False)
    gfn.add_argument('--fninclude_file', help='text file, lines TODO: class LineReader')
    gfn.add_argument('--fnexclude_file', help='text file, lines TODO: class LineReader')
    parser.add_argument('--do_link', action='store_true', help='otherwise, only compile')
    parser.add_argument('--do_exec', action='store_true', help='otherwise, only link or only compile (depending on --link)')
    parser.add_argument('--touchprj_dir', required=False, help='OVERRIDE value from config.py')
    parser.add_argument('--csv_path', required=False, help='OVERRIDE path of popularimports.csv file')
    # the following TWO args control the logic of how to act with an old data (old mod_xxx.cpp files)
    # Three modes possible:
    #   1) no cleanup 2) cleanup, but old files keep 3) cleanup, and old files overwrite
    parser.add_argument('--force_cleanup', action='store_true', help='DANGER! clear src/ dir before generating')
    parser.add_argument('--old_files', default='keep', choices=['keep', 'overwrite'])


  def _do_work(self):
    self.__load_include_exclude()

    self._touchprj_dir = self._args.touchprj_dir if self._args.touchprj_dir else get_touchprj_dir()

    self.__init_project()
    self.__generate_mod_xxx_cpp_files()
    self.__generate_main_cpp_file()
    shutil.copyfile(f'{_sd}/touchprj_files/touch.h.templ', f'{self._st.get_src_dir()}/touch.h')

    self._st.fast_compile(sprayed_build=False, dont_link=not self._args.do_link)

    if self._args.do_exec:
      self._st.run_fast_compiled_program(expect_code=self._retcode)
      print('program executed!')

    print('work done')


  def __load_include_exclude(self):
    ### DLLS ###
    if self._args.dllinclude_file:
      self._include_dlls_up = self._read_lines(self._args.dllinclude_file)
      self._include_dlls_up = [x.upper() for x in self._include_dlls_up]
    elif self._args.dllexclude_file:
      self._exclude_dlls_up = self._read_lines(self._args.dllexclude_file)
      self._exclude_dlls_up = [x.upper() for x in self._exclude_dlls_up]
    ### FNS ###
    if self._args.fninclude_file:
      self._include_fns_up = self._read_lines(self._args.fninclude_file)
      self._include_fns_up = [x.upper() for x in self._include_fns_up]
    elif self._args.fnexclude_file:
      self._exclude_fns_up = self._read_lines(self._args.fnexclude_file)
      self._exclude_fns_up = [x.upper() for x in self._exclude_fns_up]

  def _read_lines(self, path):
    rdr = LineReader(open(path, 'r'))
    return [line.upper() for line in rdr]

  # dllname_up should be upper
  def __check_filter(self, dllname_up) -> bool:
    if self._include_dlls_up:
      return fnmatch_one_of(dllname_up, self._include_dlls_up)
    elif self._exclude_dlls_up:
      return not fnmatch_one_of(dllname_up, self._exclude_dlls_up)
    else:
      # by default, pass all
      return True

  def __init_project(self):
    self._st = SpraytestProject(self._touchprj_dir, 'touchprj')
    self._st.put(allow_exist=True)
    if self._args.force_cleanup:
      # need to clear src dir cuz old cpp files can silently spoil everything
      # recreate_dir(self._st.get_src_dir()) # don't remove the dir, erase the files only (1 level)
      for file in glob.glob(f'{self._st.get_src_dir()}/*'):
        os.remove(file)

  # generate mod_xxx.cpp files from popularimports.csv made by special script
  def __generate_mod_xxx_cpp_files(self):
    csv_file = self._args.csv_path if self._args.csv_path else f'{get_popularimports_dir()}/popularimports.csv'
    reader = csv.reader(open(csv_file, 'r'), delimiter=',',)
    next(reader) # skip CSV header

    self._mod2proclist = {}  # { 'ADVAPI32.DLL': ['proc1', 'proc2', ] }

    #
    # Read CSV rows, build _mod2proclist
    #
    for dll, func, use_count in reader:

      dll2 = dll.upper()
      if not self.__check_filter(dll2): # include/exclude dlls
        continue

      self._mod2proclist.setdefault(dll2, []).append(func)

    for dll in self._mod2proclist.keys():
      cpp_path = f'{self._touchprj_dir}/src/mod_{dll}.cpp'
      if os.path.isfile(cpp_path):
        if self._args.old_files == 'keep':
          print(f'Keeping aready existing cpp file {cpp_path}')
          continue
        assert (self._args.old_files == 'overwrite')
        print(f'Exists cpp file, but will be overwritten - {cpp_path}')

      funcs = [func_name for func_name in self._mod2proclist[dll] if not self.__func_name_has_bad_chars(func_name)]
      if 0 == len(funcs):
        print(f'SKIPPING EMPTY MODULE (after filtering) - {dll}')
        continue

      dll_title = dll.split('.')[0]
      dll_title_fixed = self.__fix_dll_title(dll_title)
      funcs2 = [f'  TRASHER_TOUCH({x});' for x in funcs]
      trasher_touch_lines = '\n'.join(funcs2)
      mod_cpp = self.__instantiate_text_template(
        open(f'{_sd}/touchprj_files/mod_xxx.cpp.templ').read(),
        {
          '%%%modname%%%': 'mod_' + dll_title_fixed,
          '%%%trasher_touch_lines%%%': '  //#!touchlist_begin\n'
                                       + trasher_touch_lines
                                       + '\n  //#!touchlist_end\n',
        })

      open(cpp_path, 'w').write(mod_cpp)

  def __func_name_has_bad_chars(self, func_name) -> bool:
    # example of what we're fight with:
    #   TRASHER_TOUCH(??0exception@@QEAA@AEBV0@@Z);
    return '?' in func_name or '@' in func_name

  def __generate_main_cpp_file(self):
    decl_list, call_list = [], []
    for dll in self._mod2proclist.keys():
      dll_title = dll.split('.')[0]

      dll_title_fixed = self.__fix_dll_title(dll_title)

      decl_list += ['void mod_' + dll_title_fixed + '();']
      call_list += ['  mod_' + dll_title_fixed + '();']

    main_cpp = self.__instantiate_text_template(
      open(f'{_sd}/touchprj_files/main.cpp.templ').read(),
      {'%%%title_comment%%%': f'// autogenerated by {" ".join(sys.argv)} ;\n',
       '%%%fn_decls%%%': '\n'.join(decl_list),
       '%%%fn_calls%%%': '\n'.join(call_list),
       '%%%retcode%%%': str(self._retcode)})

    open(self._st.get_main_cpp_path(), 'w').write(main_cpp)

  def __instantiate_text_template(self, text_template, repl_dict) -> str:
    for repl_key in repl_dict:
      repl_value = repl_dict[repl_key]
      text_template = text_template.replace(repl_key, repl_value)
    return text_template

  def __fix_dll_title(self, dll_title):
    return dll_title.replace('-', '_')  # and probably more...



if __name__ == '__main__':
  PopularImportsCsvToTouchPrj(sys.argv[1:]).execute()
