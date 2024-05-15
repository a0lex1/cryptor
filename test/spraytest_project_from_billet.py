import os, shutil
from typing import List
from dataclasses import dataclass

from c2.sprayer.test.spraytest_project import SpraytestProject, ExtraSrcDir
from c2.common.execcmd import execcmd
from c2.common.update_hardlinks import update_hardlinks


# High level class for a common way of testing projects from billets.
# Does not impose itself to anybody.
@dataclass
class ProjectFromBillet:
  prj_dir: str
  prj_name: str
  billet_dir: str = None
  billet_cpp_file: str = None
  do_test_nonsprayed: bool = True
  do_test_sprayed: bool = True
  expect_code: int = 0
  source_file_masks: List[str] = None
  spraytab_tool_extra_opts: List[str] = None
  spraygen_tool_extra_opts: List[str] = None
  __st: SpraytestProject = None

  def get_src_dir(self): return self.__st.get_src_dir()

  def prepare(self):
    assert ((self.billet_cpp_file == None) ^ (self.billet_dir == None))
    if self.source_file_masks != None:
      assert (self.billet_dir != None and self.billet_cpp_file == None)

    self.__st = SpraytestProject(self.prj_dir, self.prj_name)
    self.__st.put(allow_exist=True)
    srcdir = self.prj_dir + '/src'
    shutil.rmtree(srcdir)
    os.makedirs(srcdir)

    help_mklink = lambda s: s.replace('/', '\\')

    if self.billet_dir != None:
      update_hardlinks(srcdir, self.billet_dir)
    else:
      link_path = f'{self.prj_dir}/src/main.cpp'
      execcmd(f'mklink /h {help_mklink(link_path)} {help_mklink(self.billet_cpp_file)}')

    if self.do_test_sprayed:
      self.__st.write_spraypreparebat_file(True, True)

  def fast_compile_and_test(self):
    if self.do_test_nonsprayed:
      self.__st.fast_compile(sprayed_build=False)
      self.__st.run_fast_compiled_program(expect_code=self.expect_code)

    if self.do_test_sprayed:
      self.__st.run_tools(do_spraytab=True, do_spraygen=True,
                          spraytab_tool_extra_opts=self.spraytab_tool_extra_opts,
                          spraygen_tool_extra_opts=self.spraygen_tool_extra_opts)
      self.__st.fast_compile(sprayed_build=True)
      self.__st.run_fast_compiled_program(expect_code=self.expect_code)


