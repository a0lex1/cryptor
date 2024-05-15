from typing import List

from c2.sprayer.ccode.var import *
from c2.sprayer.misc._ensure_objvars_set import ensure_objvars_set


# Only integer vars supported now
class VarListGenerator:
  class Funcs:
    def __init__(self):
      self.fn_prob_types = None
      self.fn_count = None # must never return 0
      self.fn_prob_known = None
      self.fn_prob_unk = None
      self.fn_prob_uninit = None
    def ensure_all_set(self):
      ensure_objvars_set(self, 'fn_')

  def __init__(self, funcs:Funcs, rng):
    self.funcs = funcs
    self._rng = rng

  def gen_var_list(self, rmin, rmax, types=integer_var_types) -> List[Var]:
    self.funcs.ensure_all_set()
    vl = []
    funcs = self.funcs
    rng = self._rng
    for pos in range(rng.randint(rmin, rmax)):
      # remove all except |types|
      probtypes = {t: p for t, p in funcs.fn_prob_types(pos).items() if t in types}
      typelist = list(probtypes.keys())
      typeweights = tuple(probtypes.values())

      typ = rng.choices(typelist, weights=typeweights, k=1)[0]
      cnt = funcs.fn_count(pos)
      #print(cnt)
      assert(cnt != 0)

      vlist = [0, 1, 2]
      vweights=(funcs.fn_prob_known(pos), funcs.fn_prob_unk(pos), funcs.fn_prob_uninit(pos))
      values = []
      for c in range(cnt):
        cv = rng.choices(vlist, vweights, k=1)[0]
        if cv == 0: # known
          tcls = type_classes[typ]
          if tcls:
            value = rng.randint(0, tcls.max())
          else:
            raise RuntimeError('var type is None')
        elif cv == 1:
          value = ValueUnknown()
        elif cv == 2:
          value = ValueUninitialized()
        else:
          raise RuntimeError('can\'t be')
        values.append(value)
      vl.append(Var(typ, values))
      rng.shuffle(vl)
    return vl


class VLVarsGenFuncs(VarListGenerator.Funcs):
  def __init__(self,
               fn_prob_types=lambda pos: {t: 1 for t in integer_var_types},
               fn_count=lambda pos: pos//4 + 1,
               fn_prob_known=lambda pos: 1,
               fn_prob_unk=lambda pos: 1,
               fn_prob_uninit=lambda pos: 1
               ):
    super().__init__()
    self.fn_prob_types = fn_prob_types
    self.fn_count = fn_count
    self.fn_prob_known = fn_prob_known
    self.fn_prob_unk = fn_prob_unk
    self.fn_prob_uninit = fn_prob_uninit
    self.ensure_all_set()

  def only_knowns(self):
    self.fn_prob_unk = lambda pos: 0
    self.fn_prob_uninit = lambda pos: 0
    return self

  def only_unknowns(self):
    self.fn_prob_known = lambda pos: 0
    self.fn_prob_uninit = lambda pos: 0
    return self

  def only_uninit(self):
    self.fn_prob_unk = lambda pos: 0
    self.fn_prob_known = lambda pos: 0
    return self

  def fixed_count(self, cnt):
    self.fn_count = lambda pos: cnt
    return self

