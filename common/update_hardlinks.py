import fnmatch, os

from c2._internal_config import get_tmp_dir
from c2.common.execcmd import execcmd

# creates hardlinks for files and junctions for subdirectories
def update_hardlinks(dst_dir, src_dir, src_masks=None):
  help_mklink = lambda s: s.replace('/', '\\')
  src_list = os.listdir(src_dir)
  for src in src_list:

    if src_masks != None: # filter by masks
      match = False
      for src_mask in src_masks:
        if fnmatch.fnmatch(src, src_mask):
          match = True
          break
      if not match:
        continue

    link_path = dst_dir + '/' + src
    if os.path.isdir(link_path):
      os.rmdir(link_path)
    elif os.path.isfile(link_path):
      os.unlink(link_path)

    link_target = os.path.join(src_dir, src)

    if os.path.isdir(link_target):
      _flag = '/j' # junction for directories
    elif os.path.isfile(link_target):
      _flag = '/h' # hardlink for files
    else:
      raise RuntimeError(f'not dir, not file, what else? - {link_target}')
    execcmd(f'mklink {_flag} {help_mklink(link_path)} {help_mklink(link_target)}')


import shutil, sys

_sd = os.path.dirname(__file__)
_my_tmpdir = get_tmp_dir() + '/test_update_symlinks'

def test_update_hardlinks(argv):
  shutil.rmtree(_my_tmpdir, ignore_errors=True)
  srcdir = _my_tmpdir+'/src'
  dstdir = _my_tmpdir+'/dst'
  os.makedirs(srcdir)
  os.makedirs(dstdir)
  open(srcdir+'/a', 'w').write('A')
  open(srcdir+'/b', 'w').write('B')
  open(srcdir+'/c', 'w').write('C')

  update_hardlinks(dstdir, srcdir)

  outlist = os.listdir(dstdir)
  print('out files in dir:', outlist)
  if outlist != ['a', 'b', 'c']:
    raise RuntimeError('unexpected files in dir')


if __name__ == '__main__':
  test_update_hardlinks(sys.argv[1:])
