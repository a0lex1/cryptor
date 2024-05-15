def dictapply(d, f, g=None):
  if g == None:
    g = lambda k: f[k] # default getter
  for k in d.keys():
    if k in f:
      d[k] = g(k)

