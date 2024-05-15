import os, sys, shutil, fnmatch, json
from typing import List
from glob import glob
from dataclasses import dataclass

from c2._internal_config import get_tmp_dir
from c2.sprayer.spraygen import SpraygenCLI
from c2.sprayer.spraytab import SpraytabCLI
from c2.common.mirror_directory import mirror_directory
from c2.common.execcmd import execcmd
from c2.common.make_cmdline import make_cmdline


_sd = os.path.dirname(__file__)

class SpraytestCompileError(Exception):
  pass

@dataclass
class ExtraSrcDir:
  dir_name_in_project: str = None
  dir_orig_path: str = None
  file_masks: List[str] = None

# Doesn't support subdirs in src/
class SpraytestProject:
  def __init__(self, prj_dir, prog_name=None, extra_src_dirs:List[ExtraSrcDir]=None):
    if extra_src_dirs != None:
      raise RuntimeError('this mechanism is obsolete; introduced for proggen, but then decided it cannot be used')
    self.prj_dir = prj_dir
    if prog_name == None:
      prog_name = os.path.basename(prj_dir)
    self.prog_name = prog_name
    self.extra_src_dirs = extra_src_dirs

  def exists(self):
    return os.path.isdir(self.prj_dir)

  def _recreate_dir_link(self, target_rel_path, src_path):
    link = f'{self.prj_dir}/{target_rel_path}'.replace('/', '\\') # mklink will choke if / (it treats them flags)
    link_target = src_path.replace('/', '\\')
    if os.path.exists(link):
      os.unlink(link)
    execcmd(fr'mklink /j {link} {link_target}')

  def put(self, allow_exist=False):
    os.makedirs(fr'{self.prj_dir}/src', exist_ok=allow_exist)

    self._recreate_dir_link('include_spraygen', f'{_sd}/../include')

    if self.extra_src_dirs:
      os.makedirs(f'{self.prj_dir}/extra', exist_ok=allow_exist)
      for esd in self.extra_src_dirs:
        assert(type(esd) == ExtraSrcDir)
        dest_fullp = f'{self.prj_dir}/extra/{esd.dir_name_in_project}'
        if os.path.exists(dest_fullp):
          shutil.rmtree(dest_fullp)
        mirror_directory(dest_fullp, esd.dir_orig_path, esd.file_masks)

    # xcopy won't take /slashes, like mklink, they think those are opts, not path seps
    srcdir = fr'{_sd}/spraytest_project_files'.replace("/", "\\")
    dstdir = self.prj_dir.replace("/", "\\")
    cmd = fr'xcopy {srcdir}\* {dstdir} /s /y'
    r = os.system(cmd)
    if r != 0:
      raise RuntimeError('xcopy failed')
    # after copying, fix something in CMakeLists.txt in the destination dir
    data = open(f'{dstdir}\CMakeLists.txt', 'r').read()
    data = data.replace('_spraytest_', self.prog_name)
    open(f'{dstdir}\CMakeLists.txt', 'w').write(data)

  # write your program to this file after put()
  def get_src_dir(self): return f'{self.prj_dir}/src'
  def get_extra_dir(self): return f'{self.prj_dir}/extra'
  def get_main_cpp_path(self): return f'{self.get_src_dir()}/main.cpp'

  def init_from_spraytab(self, spraytab:dict):
    open(self.get_main_cpp_path(), 'w').write('#error The project is created from spraytab, -> we have no source code')
    json.dump(spraytab, open(f'{self.prj_dir}/spraytab.json', 'w'), indent=2)

  def init_from_filelist_or_directory(self):
    raise RuntimeError('possible future')

  def _spraytab_def_argv(self, prjdir_to_use):
    return ['-z', prjdir_to_use + '/gened_headers.h',
            '-d', prjdir_to_use + '/src', prjdir_to_use + '/extra',
            '-o', prjdir_to_use + '/',  # trailing / prevents \" ending
            '--allow_nonexisting'
            ]

  def _spraygen_def_argv(self, prjdir_to_use):
    return ['-j', prjdir_to_use + '/spraytab.json',
            '-o', prjdir_to_use + '/']  # trailing / prevents \" ending

  def write_spraypreparebat_file(self,
                                 do_spraytab:bool, do_spraygen:bool,
                                 spraytab_tool_extra_opts=None, spraygen_tool_extra_opts=None):
    assert(do_spraytab or do_spraygen)
    if do_spraytab:
      stargv = self._spraytab_def_argv('%~dp0')
      if spraytab_tool_extra_opts:
        stargv += spraytab_tool_extra_opts
      stargvstr = '"' + '" "'.join(stargv) + '"'
    if do_spraygen:
      sgargv = self._spraygen_def_argv('%~dp0')
      if spraygen_tool_extra_opts:
        sgargv += spraygen_tool_extra_opts
      sgargvstr = '"' + '" "'.join(sgargv) + '"'
    with open(f'{self.prj_dir}/$SprayPrepare.bat', 'w') as f:
      if do_spraytab:
        f.write(f'py -m c2.sprayer.spraytab {stargvstr} && (echo Success) || (echo ***Err in $spray_prepare.bat*** && goto exit)\n')
      if do_spraygen:
        f.write(f'py -m c2.sprayer.spraygen {sgargvstr} && (echo Success) || (echo ***Err in $spray_prepare.bat*** && goto exit)\n\n')
      f.write(':exit\n')

  # after init
  def run_tools(self,
                do_spraytab: bool, do_spraygen: bool,
                spraytab_tool_extra_opts=None, spraygen_tool_extra_opts=None):
    assert(do_spraytab or do_spraygen)
    if do_spraytab:
      stargv = self._spraytab_def_argv(self.prj_dir)
      if spraytab_tool_extra_opts:
        stargv += spraytab_tool_extra_opts

      stcli = SpraytabCLI(stargv)
      stcli.execute()

    if do_spraygen:
      sgargv = self._spraygen_def_argv(self.prj_dir)
      if spraygen_tool_extra_opts:
        sgargv += spraygen_tool_extra_opts

      sgcli = SpraygenCLI(sgargv)
      sgcli.execute()

    return # from run_tools

  # fast compile means with cl.exe, not devenv.exe /build
  # to disable adding default extra include dirs, set it to []
  def fast_compile(self, sprayed_build:bool, extra_include_dirs=None, source_file_masks=None,
                   dont_link=False,
                   extra_cl_args:List[str]=None):
    if source_file_masks == None:
      source_file_masks = ['*.cpp', '*.c']
    if extra_include_dirs == None:
      extra_include_dirs = [f'{self.prj_dir}/include_spraygen']
    old_dir = os.getcwd()
    os.chdir(self.prj_dir)
    if sprayed_build:
      extra_args = '-DSPRAYED_BUILD'
      cpp = f'{self.prj_dir}/gened_code.cpp'
    else:
      extra_args = ''
      cpp_paths = []
      # Visit recursively. Allow to have cpp subdirs.
      for root, dirs, files in os.walk(self.get_src_dir()):
        for file in files:
          if self._matches_any_mask(file, source_file_masks):
            fullp = f'{root}/{file}'
            relp = os.path.relpath(fullp, self.prj_dir)
            cpp_paths += [relp]

      cpp = ' '.join(cpp_paths)
    pass

    _extrahdrs = ''
    if extra_include_dirs:
      _extrahdrs = ' '.join([f'-I {incdir}' for incdir in extra_include_dirs])

    cmd = f'cl.exe {cpp} {extra_args} -I ./src/ -I ./extra/  {_extrahdrs}'
    if dont_link:
      cmd += ' /c'
    else:
      cmd += f' -Fe{self.prog_name}'# -Fo{self.prog_name}'
    if extra_cl_args:
      cmd += f' {" ".join(extra_cl_args)}'
    print(f'[=== Executing in dir, cmd: {cmd}')
    r = os.system(cmd)
    os.chdir(old_dir)
    if r != 0:
      raise SpraytestCompileError(f'*** cl.exe returned non-null - {r} ***')

  def _matches_any_mask(self, fname, source_file_masks):
    for mask in source_file_masks:
      if fnmatch.fnmatch(fname, mask):
        return True
    return False

  def exec_file_in_prj_dir(self, cmd):
    r = os.system(fr'{self.prj_dir}/{cmd}')
    assert(r == 0)


  def run_fast_compiled_program(self, expect_code:int=None, childargv=None) -> int:
    if childargv == None:
      childargv = []
    progname = self.prog_name
    cmdline = make_cmdline(f'{self.prj_dir}/{progname}', childargv)
    ret_code = execcmd(cmdline, expect_ret=expect_code)
    return ret_code

  def cmake_regen(self, bitness):
    if bitness == 32:
      self.exec_file_in_prj_dir('regen86.bat')
    elif bitness == 64:
      self.exec_file_in_prj_dir('regen64.bat')
    else: raise RuntimeError(f'bad bitness - {bitness}')

  def cmake_build(self, bitness, configurations=None):
    if configurations == None:
      configurations = ['Debug', 'ReleaseSprayed']
    'cmake --build %~dp0\build86 --config Debug'
    _bb = {32: '86', 64: '64'}[bitness]
    for configuration in configurations:
      execcmd(f'cmake --build {self.prj_dir}/build{_bb} --config {configuration}')

# SPRAYTEST PROJECT SELF TEST

_testproject_dir = fr'{get_tmp_dir()}/test_spraytest_project'

def _ensure_testproject_dir_exists():
  sp = SpraytestProject( _testproject_dir)
  if not sp.exists():
    sp.put()
  assert(sp.exists())

def _test():
  expect_code = 8991231
  spraytest_project = SpraytestProject(_testproject_dir)
  open(spraytest_project.get_main_cpp_path(), 'w').write(
    '#include <cstdio>\nint main() {\n'
    '  printf("I am thinking, therefore I exist. If I would be a program, how could I say this?\\n");\n'
    '  return '+str(expect_code)+';\n'
    '}\n')
  spraytest_project.fast_compile(sprayed_build=False)
  spraytest_project.run_fast_compiled_program(expect_code)
  pass

# this is slow test because cmake regen is slow
def _test_with_cmake():
  print('testing SpraytestProject with cmake regen')
  sp = SpraytestProject(_testproject_dir)
  open(sp.get_main_cpp_path(), 'w').write(
    fr'#include <cstdio>\nint main() {{printf("I am thinking\\\n")}}'
  )
  sp.fast_compile(sprayed_build=False) # leave it, it's not bad for us here
  sp.run_fast_compiled_program(expect_code=883)
  sp.cmake_regen(64)


def test_spraytest_project(argv):
  _ensure_testproject_dir_exists()
  _test()
  if 'slowtest!' in argv:
    _test_with_cmake()


if __name__ == '__main__':
  test_spraytest_project(sys.argv[1:])

