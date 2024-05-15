#need fix, doesnt work

import argparse, pefile, fnmatch, os, sys

from c2.stub_tools.strhash import strhash


class StrhashSelftest:
  def __init__(self, mul, hashlimit=0xffffffff):
    self.mul = mul
    self.hashlimit = hashlimit
    self.exts = ['*.dll', '*.sys', '*.ocx', '*.scr', '*.cpl', '*.msc'] # no '.exe', exes don't have exports
    self.all_hashes = {} # 'expname': 0xHASH
    self.all_exports = {} # 'expname': count
    self.filename_hashmap = {} # 'filename': 0xHASH
    self.upcased_filenames = {}

  def do_test(self, dirpath):
    for root, dirs, files in os.walk(dirpath):
      for file in files:
        fullp = os.path.join(root, file)
        fullp = os.path.realpath(fullp)
        executable = False
        for ext in self.exts:
          if fnmatch.fnmatch(file, ext):
            executable = True
            break
        if not executable:
          continue
        print('processing file', fullp)
        try:
          self._process_file(fullp)
          upcased_filename = os.path.basename(fullp).upper()
          if not upcased_filename in self.filename_hashmap:
            hsh = strhash(self.mul, upcased_filename, self.hashlimit)
            if not hsh in self.filename_hashmap.values():
              self.filename_hashmap[upcased_filename] = hsh
            else:
              raise RuntimeError(f'COLLISION in filenames: hash 0x{hsh:08X} for filename {upcased_filename} ' + \
                                 'already exists for {self.filename_hashmap[hsh]} (mul={self.mul})')
            self.upcased_filenames[upcased_filename] = hsh
        except (pefile.PEFormatError, ) as e:
          print('*** EXCEPTION ***', e)
          pass
    return 0

  def _process_file(self, fullp):
    pe = pefile.PE(fullp, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    exports = [(e.ordinal, e.name) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
    num_new, num_existing = 0, 0
    for e in sorted(exports):
      expord, expname = e
      if expname in self.all_exports:
        self.all_exports[expname] += 1
        num_existing += 1
      else:
        # first time seen
        num_new += 1
        self.all_exports[expname] = 1
        hsh = strhash(self.mul, expname, self.hashlimit)
        if not hsh in self.all_hashes:
          self.all_hashes[expname] = hsh
        else:
          raise RuntimeError(f'COLLISION in expnames: hash 0x{hsh:08X} for {expname} (ord {ord}) ' + \
                             'already exists for {self.all_hashes[hsh]} (mul={mul})')
    print(f'[+] {os.path.basename(fullp)} - {num_new} new, {num_existing} existing funcs')



def strhash_selftest_main(argv):
  parser = argparse.ArgumentParser()
  parser.add_argument('-d', '--directory', required=True)
  args = parser.parse_args(argv)

  selftest = StrhashSelftest(31)

  selftest.do_test(args.directory)


if __name__ == '__main__':
  strhash_selftest_main(sys.argv[1:])


