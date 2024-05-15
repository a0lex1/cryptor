# returns tup
def parse_rangestr(rangestr):
  if rangestr.isdigit():
    return int(rangestr), int(rangestr)
  else:
    p = rangestr.split('..')
    assert(len(p) == 2)
    assert(p[0].isdigit())
    assert(p[1].isdigit())
    return int(p[0]), int(p[1])

def rand_from_rangestr(rangestr, rng):
  start, end = parse_rangestr(rangestr)
  if start == end:
    return start
  else:
    return rng.randint(start, end)
