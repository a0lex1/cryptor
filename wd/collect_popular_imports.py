import os, sys

from c2._internal_config import get_popularimports_dir
from c2.wd.popimps.popimps_collect import PopImpsCollectCLI

_sd = os.path.dirname(__file__)


def collect_popular_imps_main(argv):
    if 'bla:lightcollection!' in argv:
      _min_popular_imps = 10
    else:
      _min_popular_imps = 100

    _file_masks = ['*.exe', '*.dll', ]
    _bin_dirs = []
    windir = os.environ['WINDIR']
    if 'bla:lightcollection!' in argv:
      # want more than one directory to test mechanisms
      _bin_dirs += [windir+'/system32/wbem']
      _bin_dirs += [windir+'/system32/spool']
    else:
      _bin_dirs += [os.environ['WINDIR']]
    popimps_dir = get_popularimports_dir()

    _blackfile = _sd + '/blacklist_paths_windows.lst'

    chargv = ['--out_dir', popimps_dir, '--dirs', *_bin_dirs, '--file_masks', *_file_masks,
              '--min_popular_imps', str(_min_popular_imps), '--blacklist_file', _blackfile]

    PopImpsCollectCLI(chargv).execute()



if __name__ == '__main__':
  collect_popular_imps_main(sys.argv[1:])

