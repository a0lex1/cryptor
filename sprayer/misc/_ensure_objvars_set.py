def ensure_objvars_set(object, prefix):
  vs = vars(object)
  z = [v for v in vs.keys() if v.startswith(prefix) and vs[v] == None]
  if z != []:
    raise RuntimeError(f'not all vars set, None is: {z}')

