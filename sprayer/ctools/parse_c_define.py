# Both CLI and library interface

import os, sys, re, fnmatch, argparse
from pprint import pprint
from typing import List, Tuple


# No multiline #define(s), e.g. no \ slashing is supported.
# Returns Tuple[str, str] or None if not valid C define line
def parse_c_define(line:str):
  # [ \t] is instead of \s because we don't want newlines to be whitespaces, only space and tab
  m = re.match('^[ \t]*#define[ \t]+([\w\d_,\(\)]+)[ \t]*(.*?)?$', line)
  if not m:
    return None
  return m[1].strip(), m[2].strip()

def _expect(text, expected_tup):
  tup = parse_c_define(text)
  if tup != expected_tup:
    print('*** *** UNEXPECTED TUP *** ***')
    print('Expected tup:')
    print(expected_tup)
    print('Got tup:')
    print(tup)
    raise RuntimeError('unexpected tup')

def test_parse_c_define(argv):
  # test incorrect variants
  _expect('', None)
  _expect('#define', None)
  _expect('#define\ntest apple', None)
  _expect('#define sex\nhi', None)
  # test 0-arg macro
  _expect('#define xxx', ('xxx', ''))
  _expect('#define  xxx', ('xxx', ''))
  _expect('#define  xxx ', ('xxx', ''))
  # test 0-arg macro with extra whitespaces
  _expect(' #define xxx', ('xxx', ''))
  _expect(' #define  xxx', ('xxx', ''))
  _expect(' #define  xxx ', ('xxx', ''))
  # test 1-arg macro
  _expect('#define XxX' ,('XxX', ''))
  _expect('#define XxX3' ,('XxX3', ''))
  _expect('#define xxx yyy' ,('xxx', 'yyy'))
  _expect('#define   xxx   yyy' ,('xxx', 'yyy'))
  _expect('#define   xxx   yyy ' ,('xxx', 'yyy'))
  _expect('#define xxx(a,b,c) yyy' ,('xxx(a,b,c)', 'yyy' ))
  _expect('#define xxx(a,b,c) yyy(a, b, c)' ,('xxx(a,b,c)', 'yyy(a, b, c)' ))
  _expect('#define xxx(a,b,c) yyy(a,  b,  c)' ,('xxx(a,b,c)', 'yyy(a,  b,  c)' ))
  _expect('#define xxx_(a_,b_,c_) eee' ,('xxx_(a_,b_,c_)', 'eee' ))
  _expect('#define xxx1X_(a_,b_,c_) eee' ,('xxx1X_(a_,b_,c_)', 'eee' ))

j = os.path.join

def grab_c_defines_main(argv):
  test_parse_c_define([]) # don't give him args

  print('*** This program will scan for .cpp and .c files in specified dir. ***')
  print()

  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('--root', required=True)
  args = parser.parse_args()
  all_defs = {}
  for root, dirs, files in os.walk(args.root):
    for file in files:
      fp = j(root, file)
      if fnmatch.fnmatch(file, '*.cpp') or fnmatch.fnmatch(file, '*.c'):
        try:
          lines = open(fp, 'r').readlines()
        except UnicodeDecodeError as e:
          print(f'exception UnicodeDecodeError ({e}) when processing', fp)
          continue
        for line in lines:
          tup = parse_c_define(line)
          if tup:
            all_defs[tup[0]] = tup[1]

  pprint(all_defs)


if __name__ == '__main__':
  grab_c_defines_main(sys.argv[1:])


