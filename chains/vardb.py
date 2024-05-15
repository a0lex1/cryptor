from enum import Enum, auto, Flag
from collections import OrderedDict

class VF(Flag):
  VAR_DEFAULT = auto()
  VAR_TRASH = auto()   # for Direction.UNUSED
  VAR_KILLED = auto()

class VarDB:
  def __init__(self):
    self._varflags = []
    self._cats = []
    self._typeovers = []
    #self._paramdicts = []

  #def add_var(self, varflag:VarFlag, cat, typeover=None, paramdict:OrderedDict=None) -> int: # vid
  def add_var(self, varflag: VF, cat, typeover=None) -> int:  # vid
    #assert (not paramdict or type(paramdict) == OrderedDict)
    self._sanecheck()
    new_vid = len(self._cats)
    self._varflags.append(varflag)
    self._cats.append(cat)
    self._typeovers.append(typeover)
    #self._paramdicts.append(paramdict)
    self._sanecheck()
    return new_vid

  def number_of_vars(self):
    return len(self._cats)

  def get_var_tuple(self, vid):
    return (self.list_of_cats()[vid], self.list_of_typeovers()[vid])#, self.list_of_paramdicts()[vid])

  def list_of_varflags(self):
    return self._varflags
  def list_of_cats(self):
    return self._cats
  def list_of_typeovers(self):
    return self._typeovers
  #def list_of_paramdicts(self):
  #  return self._paramdicts

  def _sanecheck(self):
    #assert(len(self._cats) == len(self._typeovers) == len(self._paramdicts))
    assert (len(self._cats) == len(self._typeovers))

