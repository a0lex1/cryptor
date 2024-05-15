import fnmatch, shutil, os, sys
from filecmp import dircmp
from typing import List

from c2._internal_config import get_tmp_dir
from c2.common.execcmd import execcmd

_help_mklink = lambda s: s.replace('/', '\\')

# allows existing target dirs, rmtree |mirror_dir_path| yourself before call this func!
def mirror_directory(mirror_dir_path, real_dir_path, file_mask_list:List[str]=None,
                     hardlink_instead_of_junction=True):
  mklink_cmd = '/h' if hardlink_instead_of_junction else '/j'
  for root, dirs, files in os.walk(real_dir_path):
    for file in files:
      fullp = f'{root}/{file}'
      relp = root[len(real_dir_path):] # \apples\green, for example
      destdir = f'{mirror_dir_path}/{relp}'
      destfile = f'{destdir}/{file}'
      os.makedirs(destdir, exist_ok=True)
      cmd = f'mklink {mklink_cmd} "{_help_mklink(destfile)}" "{_help_mklink(fullp)}"'
      execcmd(cmd)

# tools for working with dircmp
def same_folders_dcmp(dcmp) -> bool:
  if dcmp.diff_files or dcmp.left_only or dcmp.right_only:
    return False
  for sub_dcmp in dcmp.subdirs.values():
    if not same_folders_dcmp(sub_dcmp):
      return False
  return True

def ensure_same_folders(dir1, dir2):
  dcmp = dircmp(dir1, dir2)
  if not same_folders_dcmp(dcmp):
    raise RuntimeError('dirs not equal')

_sd = os.path.dirname(__file__)
_my_tempdir = get_tmp_dir()+'/test_mirror_directory'

def test_mirror_directory(argv):
  outdir = _my_tempdir
  shutil.rmtree(outdir, ignore_errors=True)

  realdir = f'{_sd}/../test/td/mirrorme'
  mirror_directory(outdir, realdir, ['*.xxx', '*.zzz',   ])
  ensure_same_folders(outdir, realdir)


if __name__ == '__main__':
  test_mirror_directory(sys.argv[1:])



