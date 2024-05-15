import argparse, shutil, io, os, sys

from c2.wd.popimps.pe_imps_stat import PEImpsStatCLI
from c2.wd.popimps.pe_imps_filter import pe_imps_filter_main
from c2.infra.tool_cli import ToolCLI
from c2.common.execcmd import execcmd

_sd = os.path.dirname(__file__)


# This tool doesn't know about CRP_WORK_DIR. It places output CSVs to --out_dir
# However it still imports c2 which requires PYTHONPATH and implicitly bound to CRP_WORK_DIR
# due to a fact we're opening all c2 programs (pycharm, shell, tests) with single-point scripts that
# manage PYTHONPATH and CRP_WORK_DIR in pair. Kind of exceptional case.


class PopImpsCollectCLI(ToolCLI):
  def _initialize(self): self._progname = os.path.basename(__file__)
  def _setup_args(self):
    parser = self._parser

    parser.add_argument('--out_dir', required=True, help='Output dir')
    parser.add_argument('--dirs', required=True, nargs='+', action='append', help='Dirs to collect from')
    parser.add_argument('--file_masks', required=True, nargs='+', action='append', help='Masks for files in --dirs')
    parser.add_argument('--min_popular_imps', type=int, required=True, help='Skip if less') #TODO: rename to min_imps/etc.
    parser.add_argument('--blacklist_file', required=False, help='Line-by-line blacklist fnmatch patterns for DIR')

    parser.add_argument('--_no_collect', action='store_true')
    parser.add_argument('--_no_sort', action='store_true')
    parser.add_argument('--_no_filter', action='store_true')

  def _do_work(self):
    # csvsort program comes with pip install csvkit
    if shutil.which('csvsort') == None:
      raise RuntimeError('csvsort not found, install it')
    else:
      print('csvsort found')

    args = self._args
    self.__file_masks = sum(args.file_masks, [])
    self.__bin_dirs = sum(args.dirs, [])
    self.__min_popular_imps = args.min_popular_imps
    out_dir = args.out_dir

    self._imps_stat_csv_file = out_dir + '/imps-stat.csv'
    self._imps_stat_csv_sorted_file = out_dir + '/imps-stat-sorted.csv'
    self._popular_imps_csv_file = out_dir + '/popularimports.csv'

    if not args._no_collect:
      print('<Collecting...>')
      self.__collect()

    if not args._no_sort:
      print('<Sorting...>')
      self.__sort()

    if not args._no_filter:
      print('<Filtering...>')
      self.__filter()

    print('<Done.>')


  def __collect(self):
    # STEP 1  collect
    args = self._args
    peargv = ['-d', *self.__bin_dirs, '-f', *self.__file_masks, '-o', self._imps_stat_csv_file]
    if args.blacklist_file:
      peargv += ['--dir_blacklist_file', args.blacklist_file ]
    pecli = PEImpsStatCLI(peargv)
    pecli.execute()

  def __sort(self):
    execcmd(f'csvsort {self._imps_stat_csv_file} -c 1,3 -r > {self._imps_stat_csv_sorted_file}')

  def __filter(self):
    pfargv = ['-i', self._imps_stat_csv_sorted_file, '--min', str(self.__min_popular_imps)]
    buf = io.StringIO()
    pe_imps_filter_main(pfargv, buf)
    open(self._popular_imps_csv_file, 'w').write(buf.getvalue())




if __name__ == '__main__':
  PopImpsCollectCLI(sys.argv[1:]).execute()

