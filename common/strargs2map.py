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

