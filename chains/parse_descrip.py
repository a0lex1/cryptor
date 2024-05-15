import sys, re
from typing import List, Tuple

# direction category typeover paramdict
# parse single
def parse_descrip(s) -> Tuple[str, str, str, dict]:
  p = s.split(',')
  q = p[0].split(':')
  assert(len(q) == 2 or len(q) == 3)
  paramdict = {}
  if len(p) > 1:
    for i in range(1, len(p)):
      k, v = p[i].split('=')
      assert(not k in paramdict)
      paramdict[k] = v
  direction = q[0]
  category = q[1]
  if category == '':
    category = None
  typeover = None
  if len(q) == 3:
    typeover = q[2]
  return direction, category, typeover, paramdict

# parse entire line
def get_descrips(line,
                 descrips: List[Tuple[str, str, str, dict]],
                 positions: List[Tuple[int, int]]):
  for m in re.finditer('\<(.*?)\>', line):
    s = m.group(1)
    pos = m.span(1)
    pos = (pos[0]-1, pos[1]+1) # grab < and >
    descr_tup = parse_descrip(s)
    descrips.append(descr_tup)
    positions.append(pos)


def test_chains_parse_descrip(argv):
  line = '<out:String:char[512],m=10,n=15> GetStringFromPath(<in:FilePath>)'
  descrips = []
  positions = []
  get_descrips(line, descrips, positions)
  assert(len(descrips) == len(positions))
  for i in range(len(descrips)):
    print(descrips[i], 'pos', positions[i])

### TODO: MORE TESTS! ALL THE BASE CASES!!! I'M REALLY MAD!!! WITH/WITHOUT TypeOver, etc.


if __name__ == '__main__':
  test_chains_parse_descrip(sys.argv[1:])


