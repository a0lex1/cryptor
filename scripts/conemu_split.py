import os, sys
from typing import Tuple

_CONEMU_EXE = r'Z:\u\d\port_impnt\win-tools-pt\ConEmu\ConEmu64.exe'


def _usage():
  print('Usage: conemu_split.py /arg tst_worker /wrk 4 /cmd py -m mytest myarg1 myarg2')

def _printerr_exit1(errmsg):
  print(errmsg)
  _usage()
  exit(1)

def conemu_split_main(argv):
  argname, workers, cmd_items = None, None, None

  narg = 0
  while narg < len(argv):
    arg = argv[narg]
    if arg == '/arg':
      assert(narg < len(argv)-1)
      argname = argv[narg+1]
      narg += 1
    elif arg == '/workers':
      assert(narg < len(argv)-1)
      workers = int(argv[narg+1])
      narg += 1
    elif arg == '/cmd':
      assert(narg < len(argv)-1)
      cmd_items = argv[narg+1:]
      break
    else:
      raise RuntimeError(f'unknown {arg=}')
    narg += 1

  if argname == None:
    _printerr_exit1('/arg must be present')
  if workers == None:
    _printerr_exit1('/workers must be present')
  if cmd_items == None:
    _printerr_exit1('/cmd_items must be present')
    
  assert(argname != None)
  assert(workers != None)

  print(f'{argname=} {workers=} {cmd_items=}')

  shellcmd = f'start "" {_CONEMU_EXE} -runlist '
  #wrk_idx, wrk_cnt = _parse_worker(workers)
  cmd = ' '.join(['"'+item+'"' for item in cmd_items])
  for nworker in range(1, workers+1):
    shellcmd += f' {cmd} {argname} {nworker}/{workers}'
    is_last = nworker == workers
    if not is_last:
      shellcmd += ' ^|^|^| '

  print('shellcmd=>')
  print(shellcmd)

  exit_code = os.system(shellcmd)

  print('shell command returned, {exit_code=}')


if __name__ == '__main__':
  conemu_split_main(sys.argv[1:])
