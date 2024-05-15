import os


# We are planning to move wd logic onto level higher, where startup bat(s) live(s)
# So this current implementation is deprecated.
# Why this is bad now:
#  !) Can't tune single dir (popimps, resdbs, etc.) from cmdline. Only ability to set CRP_WORK_DIR.
def _workdir():
  return os.environ['CRP_WORK_DIR']

def get_tmp_dir():
  return _workdir() + '/' + f'tmp'

def get_loccrypts_dir():
  return _workdir() + '/' + 'loccrypts'

def get_resrepository_dir():
  return _workdir() + '/' + 'resdbs'

def get_touchprj_dir():
  return _workdir() + '/' + 'touchprj'

def get_popularimports_dir():
  return _workdir() + '/' + 'popular_imports'


_sd = os.path.dirname(__file__)

def get_cppbuild_dir():
  #return os.environ['CPPBUILD_DIR']
  return _sd + '/cppbuild'

