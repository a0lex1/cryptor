import shutil, os, sys

from c2._internal_config import get_tmp_dir
from c2.test.spraytest_project_from_billet import ProjectFromBillet
from c2.common.update_hardlinks import update_hardlinks

_sd = os.path.dirname(__file__)
_my_tmpdir = f'{get_tmp_dir()}/billet'


def billet_main(argv):
  p = ProjectFromBillet(
    _my_tmpdir, 'billet', billet_dir=f'{_sd}/billet_files',
    expect_code=770
  )
  p.prepare()

  pg_src_dir = p.get_src_dir()+'/pg'
  if os.path.exists(pg_src_dir):
    shutil.rmtree(pg_src_dir)
  os.mkdir(pg_src_dir)
  update_hardlinks(pg_src_dir, f'{_sd}/pg_cpp')

  p.fast_compile_and_test()


if __name__ == '__main__':
  billet_main(sys.argv[1:])
