import re

#>>> convert('1,2,5-7,10') #WTF is this?
#[1, 2, 5, 6, 7, 10]
def convert(x):
    return sum((i if len(i) == 1 else list(range(i[0], i[1]+1))
               for i in ([int(j) for j in i if j] for i in
               re.findall('(\d+),?(?:-(\d+))?', x))), [])


# converts '@hello@1@5@' -> ('hello', '1', '5') # todo: -> common
def parsemac(str):
  if (str[0] == '@'):
    if  (str[-1] == '@'):
      p = str.split('@')
      assert (p[0] == '')
      return tuple(p[1:-1])
  return None

# helps to parse '/name Arg /someopt 1'
def strargs2map(st):
  p = st.split(' ')
  assert(len(p) % 2 == 0)
  o = {}
  for i in range(len(p)//2):
    pkey, pval = p[i*2], p[i*2+1]
    assert(pkey.startswith('/'))
    if pval.upper() == 'YES':
      pval = True
    elif pval.upper() == 'NO':
      pval = False
    o[pkey] = pval
  return o

# helps to parse 'x=1;y=2'
def stropts2map(st):
  o = {}
  pp = st.split(';')
  for p in pp:
    if not len(p):
      continue
    k, v = tuple(p.split(':'))
    assert(not k in o)
    o[k] = v
  return o

