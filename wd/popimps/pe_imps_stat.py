# csvsort z_u_d.csv -c 1,3 -r > z_u_d_sorted.csv && z_u_d_sorted.csv
import pefile, os, sys
from fnmatch import fnmatch
from pprint import pprint
import time #DELETEME

from c2.infra.tool_cli import ToolCLI
from c2.common.fnmatch_one_of import fnmatch_one_of
from c2.common.line_reader import LineReader


class PEImpsStatCLI(ToolCLI):
  def _initialize(self): self._progname = os.path.basename(__file__)

  def _setup_args(self):
    parser = self._parser
    parser.add_argument('-d', '--directories', nargs='*', action='append', required=True)
    parser.add_argument('-f', '--masks', nargs='*', action='append', required=True, help='fnmatch mask(s) for FULL path of files to collect imports from')
    parser.add_argument('-o', '--out_csv', required=True)
    parser.add_argument('--dir_blacklist_file', required=False, help='text file, lines are fnmatch masks for FULL paths, not a basename mask')

  def _do_work(self):
    args = self._args
    directories = sum(args.directories, [])
    masks = sum(args.masks, [])
    if args.dir_blacklist_file:
      #blacklist_dirs = [line.rstrip() for line in open(args.dir_blacklist_file, 'r').readlines()]
      blacklist_dirs = [line for line in LineReader(open(args.dir_blacklist_file, 'r'))]
    else:
      blacklist_dirs = None
    print('blacklist dirs:', blacklist_dirs)

    self._refcounts = {  }

    for directory in directories:
      print(f'[ ] PROCESSING DIRECTORY {directory} ----------------')
      self._counter, self._prev_counter = 0, 0
      if not os.path.isdir(directory):
        raise RuntimeError(f'not exist or not a directory - {directory}')
      for root, dirs, files in os.walk(directory):
        for file in files:
          fullp = os.path.join(root, file)

          if blacklist_dirs != None:
            if fnmatch_one_of(fullp, blacklist_dirs):
              #print(f'SKIPPING BLACKLISTED DIR PATH - {fullp} (blacklist file {args.dir_blacklist_file})') # too much prints in console, comment it out
              continue

          if fnmatch_one_of(fullp, masks):
            self._process_file(fullp)


  def _process_file(self, fullp):
    refcounts = self._refcounts
    print(f'[ ] #{self._counter} processing {fullp}')
    try:
      pe = pefile.PE(fullp, fast_load=True)
      pe.parse_data_directories()
      if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return False
    except (pefile.PEFormatError, FileNotFoundError, OSError) as e:
      print('Ignoring load-pe exception:', e)
      return False
    # except (pefile.PEFormatError, FileNotFoundError, OSError) as e:
    for implib in pe.DIRECTORY_ENTRY_IMPORT:
      #try:
      if True:
        dll_name = implib.dll.decode()
        dll_name = dll_name.upper()
        for imp in implib.imports:
          # hex(imp.address)
          if not imp.name:
            continue
          imp_name = imp.name.decode()
          # print(f'{dll_name}!{imp_name}')
          if dll_name in refcounts:
            if imp_name in refcounts[dll_name]:
              refcounts[dll_name][imp_name] += 1
            else:
              refcounts[dll_name][imp_name] = 1
          else:
            refcounts[dll_name] = {imp_name: 1}
        pass
      self._counter += 1
      # write sorted refcounts every 500 bin files
      if self._counter > self._prev_counter + 100:
        self._prev_counter = self._counter
        self.__write_refcounts()
        print(f'[+] WRITTEN refcounts to {self._args.out_csv}')

  def __write_refcounts(self):
    refcounts = self._refcounts
    tups = []
    for dll_name in refcounts.keys():
      for imp_name in refcounts[dll_name]:
        tups.append( (f'{dll_name},{imp_name}', refcounts[dll_name][imp_name]) )
    tups = sorted(tups, key=lambda x: x[1], reverse=False)
    with open(self._args.out_csv, 'w') as fout:
      fout.write('dll,func,count\n') # CSV header
      for tup in tups:
        fout.write(f'{tup[0]},{tup[1]}\n') # CSV rows

if __name__ == '__main__':
  PEImpsStatCLI(sys.argv[1:]).execute()

