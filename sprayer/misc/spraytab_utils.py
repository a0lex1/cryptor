from typing import List, Dict, Tuple

def spraytab_from_sig(sig):
  # 1,2,3:0
  fs = sig.split(':')
  if len(fs) != 2:
    raise RuntimeError('bad signature, need one `:`')
  rpind = int(fs[1])
  es = fs[0]
  sigparts = [int(x) for x in es.split(',')]
  if rpind >= len(sigparts):
    raise RuntimeError(f'bad signature, root proc idx {rpind} out of range')
  spraytab = {
    'procs': [f'P{i}' for i in range(len(sigparts))],
    'lines': {f'P{i}': ['__nop;' for _ in range(sigparts[i])] for i in range(len(sigparts))},
    'root_proc': f'P{rpind}',
    'proc_opts': {},
    'staticvars': [],
    'headers': [],
    'privdefs': [],
    'raw_lines': [],
    'libs': []
  }
  return spraytab


class SpraytabShape:
  def __init__(self, sig=None, rootproc_idx=None):
    self.sig = sig
    self.rootproc_idx = rootproc_idx
  def linecount(self, nproc): # sugar
    return self.sig[nproc]
  def numprocs(self): # sugar
    return len(self.sig)
  def from_spraytab(self, spraytab):
    self.sig = []
    for p in spraytab['procs']:
      l = len(spraytab['lines'][p])
      self.sig.append(l)
    self.rootproc_idx = spraytab['procs'].index(spraytab['root_proc'])
    return self
  def from_sig(self, sigstr):
    temptab = spraytab_from_sig(sigstr)
    return self.from_spraytab(temptab)
  def __repr__(self):
    return type(self).__name__ + f'(sig={self.sig}, rootidx={self.rootproc_idx})'

def spraytab_from_shape(shape:SpraytabShape):
  st = {'lines':{}}
  for nproc in range(shape.numprocs()):
    pname = f'CoolProc{nproc}'
    st['procs'] = pname
    st['lines'][pname] = []
    for nline in range(shape.linecount(nproc)):
      st['lines'][pname].append(f'__noop({nproc},{nline});')
    st['root_proc'] = st['procs'][shape.rootproc_idx]
  return st

###

def make_spraytab(root_proc='',
  procs:List[str]=None,
  proc_opts:Dict[str, Dict]=None, lines:Dict[str, List[str]]=None, vars:List[str]=None,
  headers:List[str]=None,
  privdefs:Dict[str, str]=None) -> dict:

  if procs == None:
    procs = []
  if proc_opts == None:
    proc_opts = {}
  if lines == None:
    lines = {}
  if vars == None:
    vars = []
  if privdefs == None:
    privdefs = {}
  st = {
    "root_proc": root_proc,
    "procs": procs,
    "proc_opts": proc_opts,
    "lines": lines,
    "staticvars": vars,
    "headers": headers,
    "privdefs": privdefs
  }
  return st


def make_spraytab_for_console_prog():
  return make_spraytab("MAINPROC",
    [
      'MAINPROC',
      'func1'
    ],
    {
      "MAINPROC": {"is_from_decl": 1}
    },
    {
      "MAINPROC": [
        "  printf(\"hi\\n\");",
        "  flag2 = 1;"
      ]
    },
    [
      "static int flag1 = 0;",
      "static int flag2 = 0;"
    ],
    [
      "#include <cstdio>"
    ],
    {
      "MAINPROC_DECL()": "int main()",
      "MAINPROC_PRE()": "flag1 = 1",
      "MAINPROC_POST()": "{ ASSERT(flag1 == 1); return 770; }"
    })


def is_proc_from_decl(spraytab:dict, proc_name):
  is_from_decl = 'proc_opts' in spraytab and\
                 proc_name in spraytab['proc_opts'] and \
                 'is_from_decl' in spraytab['proc_opts'][proc_name]
  return is_from_decl

def is_proc_from_decl_n(spraytab:dict, nproc):
  proc_name = spraytab['procs'][nproc]
  return is_proc_from_decl(spraytab, proc_name)

def _test_make_spraytab1():
  st = make_spraytab_for_console_prog()
  print(st)

def test_spraytab_utils(argv):
  # spraytab_from_sig has NO TEST
  # SpraytabShape has NO TEST
  # spraytab_from_shape has NO TEST
  _test_make_spraytab1()

if __name__ == '__main__':
  test_spraytab_utils(sys.argv[1:])






