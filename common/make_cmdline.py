from typing import List

def make_cmdline(program:str, argv:List[str]):
  # Rule. Because that if we wrap progname into "" than os.sytem doesn't recognize it,
  # we need a rule that progname SHOULD NOT CONTAIN WHITESPACES
  cmdline = program
  if argv:
    cmdline += ' '
    cmdline += ' '.join([f'"{a}"' for a in argv])
  return cmdline


