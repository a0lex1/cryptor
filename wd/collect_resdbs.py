import os, sys

from c2.reskit.extract import ResextractCLI

# argv = [  -f *.exe -r icon bitmap -w --blacklist *\assembly\* *\servicing\* *\WinSxS\* %*  ]
# extract.py argv + [ -u programfiles -d "%PROGRAMFILES%" ]
# extract.py argv + [ -u system32 -d "%WINDIR%\system32" ]
# ...

def _def_collect(dbname, bin_dir, extra_args=None):
  BLACKLIST = ['*\assembly\*', '*\servicing\*', '*\WinSxS\*', ]
  eargv = ['-u', dbname, '-d', bin_dir, '-f', '*.exe', '-w',
           '-r', 'icon', 'bitmap',
           '--blacklist', *BLACKLIST]
  if extra_args:
    eargv += extra_args
  extract_cli = ResextractCLI(eargv)
  extract_cli.execute()


def collect_resdbs_main(argv):
  if 'bla:lightcollection!' in argv: #--bla
    print('[[[ bla:lightcollection! mode enabled ]]]')
    print()
    _def_collect('wintoolspt', r'Z:/win-tools-pt') ###
  else:
    _def_collect('programfiles', os.environ['PROGRAMFILES'])
    _def_collect('programfiles', os.environ['PROGRAMFILES(X86)'])
    _def_collect('system32', os.environ['WINDIR']+'/system32')
    _def_collect('wintoolspt', r'Z:/win-tools-pt') ###
  print('\n[!Don\'t forget to test the db!]\n')


if __name__ == '__main__':
  collect_resdbs_main(sys.argv[1:])

