from typing import List

from c2.sprayer.ccode.var import *


# Storage for the range location that encapsulates the size of the
# region, specified by strictly one of byte_count or value_count
#
class RangeLocation:
  def __init__(self, idx_vl:int, idx_var:int, idx_val:int, byte_count:int, value_count:int, vt:VT):
    self.idx_vl = idx_vl
    self.idx_var = idx_var
    self.idx_val = idx_val
    self.__byte_count = byte_count
    self.__value_count = value_count
    self.__vt = vt

  def value_type(self) -> VT:
    return self.__vt

  def byte_count(self):
    if self.__byte_count != None:
      return self.__byte_count
    else:
      assert(self.__value_count != None)
      return self.__value_count * type_classes[self.__vt].byte_size

  def value_count(self):
    if self.__value_count != None:
      return self.__value_count
    else:
      assert(self.__byte_count != None)
      value_bytesize = type_classes[self.__vt].byte_size
      return math.ceil(self.__byte_count / value_bytesize)

  def last_value_index(self):
    assert(self.byte_count() > 0)
    return self.idx_val + self.value_count() - 1



