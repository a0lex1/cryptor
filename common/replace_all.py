def replace_all(s, w, t):
  ret = s
  while w in ret:
    ret = s.replace(w, t)
  return ret

