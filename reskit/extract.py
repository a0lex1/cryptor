import argparse, fnmatch, shutil, glob, re, os, sys
from pprint import pprint

from c2._internal_config import get_resrepository_dir, get_cppbuild_dir, RISOHEDITOR_EXE_PATH
from c2.infra.tool_cli import ToolCLI
from c2.reskit.restest import ResTester
from c2.reskit.res_repository import ResRepository
from c2.common.execcmd import execcmd
from c2.common.clear_dir import clear_dir


_encod = 'utf-8'
_sd = os.path.dirname(__file__)

class ResextractCLI(ToolCLI):
  def _initialize(self): self._progname = os.path.basename(__file__)

  def _setup_args(self):
    parser = self._parser
    parser.add_argument('-u', '--db', required=True)
    parser.add_argument('-d', '--dir', required=True, help='The dir with the input bins')
    parser.add_argument('-f', '--file_mask', required=True, nargs='+', action='append')
    parser.add_argument('-r', '--require_restype', nargs='*', action='append')
    parser.add_argument('-w', '--overwrite', action='store_true')
    parser.add_argument('-c', '--force_cleanup', action='store_true')
    parser.add_argument('-e', '--rename_if_testfail', action='store_true')
    parser.add_argument('-x', '--rename_if_noreqres', action='store_true')
    parser.add_argument('--blacklist', nargs='+', action='append')
    parser.add_argument('-t', '--timeout', default=3000, help='msec')
    parser.add_argument('--repository_dir', required=False)

  def _do_work(self):
    if shutil.which('cl') == None:
      print('cl.exe is not in %PATH%')
      exit(-1)

    args = self._args
    dbname = args.db
    self._blacklist = sum(args.blacklist, []) if args.blacklist else []
    self._repository_dir = args.repository_dir if args.repository_dir else get_resrepository_dir()
    self._require_restype = sum(args.require_restype, []) if args.require_restype else []

    print('Dir      :', args.dir)
    print('Masks    :', args.file_mask)
    print('Require  :', args.require_restype)
    print('Blacklist:', self._blacklist)
    #^[0-9]+ VERSIONINFO
    # ^[0-9]+ 24 "(.+?)"
    # ^[0-9]+ (.*?)("(.+?)")?

    self._resrep = ResRepository(self._repository_dir)
    resrep = self._resrep

    if args.force_cleanup:
      if resrep.db_exists(dbname):
        print(f'[ ] CLEARNING ENTIRE DB {dbname}')
        
        resrep.clear_db(dbname)
        
        print(f'[+] db cleaned up: {dbname}')
      else:
        print(f'[-] no cleanup performed, db not exist - {dbname}')
    else:
      if resrep.db_exists(dbname):
        print(f'[ ] CONTINUING (db {dbname} exists)')

    for root, dirs, files in os.walk(args.dir):
      for file in files:
        if not self._process_file(resrep, root, file):
          continue

    print('[+] extraction done')
    print('$$$'*10)
    print('Don\'t forget to restest before using those new resources!')
    print('$$$'*10)


  def _get_rsrc_tups_from_rc(self, rc_contents):
    m = re.findall('^([0-9]+) (.+?) (.+?)$', rc_contents, re.MULTILINE)
    return m

  def _fix_bad_chars(self, filepath):
    data = open(filepath, 'r', encoding=_encod, errors='backslashreplace').read()
    open(filepath, 'w', encoding=_encod).write(data)


  def _process_file(self, resrep:ResRepository, root:str, file:str) -> bool:
    j = os.path.join
    args = self._args
    dbname = args.db
    fullp = j(root, file)
    blacklisted = False
    for blackmask in self._blacklist:
      if fnmatch.fnmatch(fullp, blackmask):
        # print(f'FILE {fullp} IS BLACKLISTED BY MASK {blackmask}') #dont print, too much logging
        blacklisted = True
        break
    if blacklisted:
      return False

    match = False
    for mask in args.file_mask:
      if fnmatch.fnmatch(file, mask[0]):
        match = True
        break
    if not match:
      return False

    basname = os.path.basename(fullp)
    filebasen = os.path.splitext(basname)[0]  ###TODO: rename
    outdir = resrep.get_res_dir_path(dbname, filebasen, for_error=False)
    outdir_if_err = resrep.get_res_dir_path(dbname, filebasen, for_error=True)
    if args.overwrite:
      print(f'[ ] -w (--overwrite) specified, first removing dir {outdir}')
      shutil.rmtree(outdir, ignore_errors=True)
      shutil.rmtree(outdir_if_err, ignore_errors=True)
    else:
      if os.path.isdir(outdir):
        print(f'[-] already EXISTS, skipping - {fullp}')
        return False
      if os.path.isdir(outdir_if_err):
        print(f'[-] already EXISTS, skipping - {fullp}  (out dir for err is {outdir_if_err})')
        return False

    os.makedirs(outdir)
    rsrcpath = fr'{outdir}\{filebasen}.rc'
    rsrcpath = os.path.realpath(rsrcpath)

    exechlp_exec = f'{get_cppbuild_dir()}/exechlp/Release/x64/exechlp.exe'
    cmd = f'{exechlp_exec} /e /t {args.timeout} "{RISOHEDITOR_EXE_PATH}" --load "{fullp}" --save "{rsrcpath}" --save-options (sep-lang)(wrap-manifest)'
    risoh_ret = execcmd(cmd, expect_ret=None)

    print('RisohEditor ret', risoh_ret)
    # ^[0-9]+ (.*?)("(.+?)")?
    rename_to = None
    rsrcpath_en_us = fr'{outdir}\lang\en_US.rc'
    if not os.path.isfile(rsrcpath_en_us):
      print(f'[-] no such file - {rsrcpath_en_us}, deleting')
      shutil.rmtree(outdir)
      return False

    print('[ ] fixing bad chars')
    self._fix_bad_chars(rsrcpath)
    self._fix_bad_chars(rsrcpath_en_us)

    rsrcdata = open(rsrcpath_en_us, 'r', encoding=_encod).read()
    rctups = self._get_rsrc_tups_from_rc(rsrcdata)

    #
    #TODO: self._check_types() , ...
    #
    types_ok = True
    if self._require_restype:
      for reqtype in self._require_restype:
        if reqtype.upper() in map(lambda v: v[1].upper(), rctups):
          print(f'TYPE {reqtype.upper()} present')
        else:
          if args.rename_if_noreqres:
            os.rename(outdir, outdir_if_err)
          else:
            shutil.rmtree(outdir)

          # print('******* missing in', list(map(lambda v: v[1], rctups)))
          print(f'[-] required type MISSING - {reqtype}, %s' % ('renamed' if args.rename_if_noreqres else 'deleted'))
          types_ok = False
          break
      if types_ok:
        print(f'[ ] all required types present ({self._require_restype=})')
    if not types_ok:
      print()
      return False

    print(f'[ ] fixing {filebasen}: removing all langs except en_us')
    rsrclines = open(rsrcpath, 'r', encoding=_encod).readlines()
    with open(rsrcpath, 'w', encoding=_encod) as f:
      for line in rsrclines:
        if line.startswith('#include \"lang/'):
          if line != "#include \"lang/en_US.rc\"\n":
            # leave only english, not romainan
            print('[ ] fixup: skipping line: include language')
            continue
        f.write(line)  # ok, add line

    print(f'[ ] fixing {rsrcpath_en_us}')
    langlines = open(rsrcpath_en_us, 'r', encoding=_encod).readlines()
    with open(rsrcpath_en_us, 'w', encoding=_encod) as f:
      for line in langlines:
        if re.match(r"^\d+\s+\d+\s+\"res\/.*?\.manifest\"\n$", line):
          print('[ ] fixup: skipping line: .manifest line')
          continue
        if re.match(r".*? ?MUI ", line):
          print('[ ] fixup: skipping line: MUI')
          continue
        f.write(line)  # ok, add line

    print('[ ] testing rc')

    tester = ResTester(resrep, dbname, filebasen)
    # r = do_RC_test(args.db, filebasen)
    r = tester.execute_test()

    if r != 0:
      if args.rename_if_testfail:
        os.rename(outdir, outdir_if_err)
      else:
        shutil.rmtree(outdir)
      print(f'[-] test failed, %s' % ('renamed' if args.rename_if_testfail else 'deleted'))
      return False

    print(f'[+] OK ! - {filebasen}')
    print()
    
    return True

if __name__ == '__main__':
  ResextractCLI(sys.argv[1:]).execute()

