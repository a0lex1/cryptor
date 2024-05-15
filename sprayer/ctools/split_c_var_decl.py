import re, sys, os
from typing import Tuple

# Important: BYTE *a1  -> type BYTE and NAME *a1 ! Asterisk ! Not fixed because no need right now.
# string should terminate with ';'
# string is l/r stripped inside func
# See test(s) for more info
#
def split_c_var_decl(field_str) -> Tuple[str, str]: # `TYPE VARNAME;`
  f2 = field_str.lstrip().rstrip()
  m = re.match('^([\w\d_]+\*?) (\*?[\w\d_]+)(\[.+?\])?;', f2)
  if not m:
    raise RuntimeError('cannot split C type-var decl, bad string')
  return m[1], m[2], m[3]


def _test_splitexpect(line, expect_tup):
  tup = split_c_var_decl(line)
  if tup != expect_tup:
    print('Expected TUP:')
    print(expect_tup)
    print('Got TUP:')
    print(tup)
    raise RuntimeError('unexpected tup from StructReorderer._splitdecl')

def test_split_c_var_decl(argv):
  _test_splitexpect('BYTE a1;', ('BYTE', 'a1', None))
  _test_splitexpect('BYTE a1[4];', ('BYTE', 'a1', '[4]'))
  _test_splitexpect('BYTE* a1;', ('BYTE*', 'a1', None))
  _test_splitexpect('BYTE *a1;', ('BYTE', '*a1', None)) ####### Important: * is moved to var name! This is not fixed because we don't need this fix right now.


if __name__ == '__main__':
  test_split_c_var_decl(sys.argv[1:])




