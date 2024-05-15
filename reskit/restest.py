import argparse, fnmatch, os, sys
from typing import List

from c2._internal_config import get_resrepository_dir, get_tmp_dir
from c2.reskit.res_repository import ResRepository
from c2.infra.tool_cli import ToolCLI
from c2.common.fnmatch_one_of import fnmatch_one_of


_sd = os.path.dirname(__file__)
_tmpdir = f'{get_tmp_dir()}/restest'

class ResTester:
  def __init__(self, resrep:ResRepository, dbname, resname): #rename rcname->resname
    self._resrep = resrep
    self._dbname = dbname
    self._resname = resname # resource name, e.g., 'charmap', 'msinfo', etc.

    # execute_test()
    self._rc_file = None
    self._res_file = None

    # _do()
    self._cpp_file = None
    self._obj_file = None
    self._exe_file = None


  # returns 0 if success
  def execute_test(self) -> int:
    res_dir = self._resrep.get_res_dir_path(self._dbname, self._resname)
    self._rc_file = f'{res_dir}/{self._resname}.rc'
    self._res_file = f'{res_dir}/{self._resname}.res'

    r = self._do()

    if r != 0:
      print('************** bad rc ****************')

    self._cleanup()
    return r

  def _do(self) -> int:
    compil_path = self._resrep.get_testcompile_files_path(self._dbname, self._resname)
    self._cpp_file = f'{_sd}/test.cpp'
    self._obj_file = f'{compil_path}/test.obj'
    self._exe_file = f'{compil_path}/test.exe'
    cmd = f'cl.exe /c {self._cpp_file} /Fo{self._obj_file} /Fe{self._exe_file}'
    print('test_rc(): cmd[ cl ]:', cmd)
    r = os.system(cmd)
    if r != 0:
      return r
    cmd = f'rc.exe {self._rc_file}'
    print('test_rc(): cmd[ rc ]:', cmd)
    r = os.system(cmd)
    if r != 0:
      return r
    cmd = f'link.exe {self._obj_file} {self._res_file} /out:{self._exe_file}'
    print('test_rc(): cmd[ link ]:', cmd)
    r = os.system(cmd)
    return r

  def _cleanup(self):
    if os.path.exists(self._obj_file):
      print(f'removing .obj file {self._obj_file}')
      os.remove(self._obj_file)
    if os.path.exists(self._res_file):
      print(f'removing .res file {self._res_file}')
      os.remove(self._res_file)
    if os.path.exists(self._exe_file):
      print(f'removing .exe file {self._exe_file}')
      os.remove(self._exe_file)


class ResTestCLI(ToolCLI):
  def _initialize(self): self._progname = os.path.basename(__file__)

  def _setup_args(self):
    self._parser.add_argument('-u', '--dbs', required=True, nargs='*', action='append', help='fnmatch mask(s) for name of dbs to use')
    self._parser.add_argument('-f', '--resname_mask', default='*', help='fnmatch mask for resnames in db') # not used?
    self._parser.add_argument('-i', '--ignore_errors', action='store_true')
    self._parser.add_argument('--repository_dir', required=False)

  def _do_work(self):
    repdir = self._args.repository_dir if self._args.repository_dir else get_resrepository_dir()
    dbmasks = sum(self._args.dbs, [])
    self._resrep = ResRepository(repdir)
    dbs = self._resrep.list_dbs()
    print(f'[:] dbs: {dbs}')
    for db in dbs:
      if not fnmatch_one_of(db, dbmasks):
        print(f'[-] db skipped by -u: {db}')
        continue
      self._test_db(db)
    print(f'[+] all dbs done')

  def _test_db(self, db):
    print(f'[ ] db: {db}')
    reses = self._resrep.list_res_dirs_in_db(db)
    for res in reses:
      print(f'[:]  processing: db: {db}  res: {res}')
      tester = ResTester(self._resrep, db, res)
      tester.execute_test()
    print(f'[+] db done: {db}')
    print()


if __name__ == '__main__':
  ResTestCLI(sys.argv[1:]).execute()









