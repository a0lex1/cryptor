import sys, math


class MachineInteger:
  # needs to be subclassed
  is_signed = None
  byte_size = None ### byte size is parameter, bit_size is func

  @classmethod
  def bit_size(cls):
    return cls.byte_size * 8

  @classmethod
  def max(cls):
    return 2 ** cls.bit_size() -1

  @classmethod
  def first_signed(cls):
    return cls.max() // 2 + 1

  @classmethod
  def opposite_signedness(cls):
    # returns class: int32 for uint32, uint8 for int8, etc.
    return NotImplemented()

  @classmethod
  def fits(cls, val:int):
    return val <= cls.max()

  def __init__(self, value:int):
    self.value = value
    self.check()
  def is_negative(self):
    return self.value >= type(self).first_signed()
  def to_signed(self):
    if self.value >= type(self).first_signed():
      return -(type(self).max() - self.value + 1)
    else:
      return self.value
  def from_signed(self, val:int):
    if val < 0:
      self.value = (type(self).max() + (val+1)) # 0xffffffff-(abs(val)+1)
    else:
      self.value = val
    self.value &= type(self).max()
    self.check()
    return self
  def assign(self, m_int):
    assert(issubclass(type(m_int), MachineInteger))
    m_int.check()
    self.value = m_int.value & type(self).max() # cut if m_int is bigger
    if m_int.is_signed and m_int.value >= type(m_int).first_signed() and m_int.byte_size < self.byte_size:
      # invert bits if m_int the source is negative and is smaller
      self.value = m_int.value | (type(self).max() ^ type(m_int).max())
    self.check()
    return self
  def _add_or_sub(self, add_not_sub:bool, m_int):
    m_int.check()
    if m_int.is_signed and m_int.is_negative():
      # swap + to - and value to value-(max_u+1)
      opp_op = self.sub if add_not_sub else self.add
      opp_val = -m_int.to_signed() # substract negative = add positive
      opp_obj = type(m_int).opposite_signedness()(opp_val)
      return opp_op(opp_obj)
    if add_not_sub:
      # don't need to handle overflow since the higher part is cut by &self.max()
      self.value = self.value + m_int.value
      self.value &= type(self).max() # cut
    else:
      # underflow
      self.value = self.value - m_int.value
      self.value &= type(self).max() # cut
      if self.value < 0:
        self.value = -self.to_signed()
    self.check()
    return self
  def add(self, m_int):
    return self._add_or_sub(True, m_int)
  def sub(self, m_int):
    return self._add_or_sub(False, m_int)
  def mul(self, m_int):
    m_int.check()
    if m_int.is_signed and m_int.is_negative():
      x = -m_int.to_signed()
      #x = m_int.value
      neg = True
    else:
      neg = False
      x = m_int.value
    self.value = (self.value * x)
    if neg:
      r = type(self)(0)
      r.from_signed(-self.value)
      self.value = r.value
    self.value &= type(self).max() # cut
    self.check()
    return self
  def div(self, m_int):
    self.value = (self.value // m_int) & type(self).max()
    self.check()
    return self
  # TODO: shl, shr, ror, rol, etc. (cr_common.ror)
  def check(self):
    assert(type(self.value) == int)
    assert(type(self).fits(self.value))
    assert(self.value >= 0)


class UINT8(MachineInteger):
  is_signed = False
  byte_size = 1
  def __init__(self, value):
    super().__init__(value)
  @classmethod
  def opposite_signedness(self):
    return INT8

class UINT16(MachineInteger):
  is_signed = False
  byte_size = 2
  def __init__(self, value):
    super().__init__(value)
  @classmethod
  def opposite_signedness(self):
    return INT16

class UINT32(MachineInteger):
  is_signed = False
  byte_size = 4
  def __init__(self, value):
    super().__init__(value)
  @classmethod
  def opposite_signedness(self):
    return INT32

class UINT64(MachineInteger):
  is_signed = False
  byte_size = 8
  def __init__(self, value):
    super().__init__(value)
  @classmethod
  def opposite_signedness(self):
    return INT64

#########

class INT8(MachineInteger):
  is_signed = True
  byte_size = 1
  def __init__(self, value):
    super().__init__(value)
  @classmethod
  def opposite_signedness(self):
    return UINT8

class INT16(MachineInteger):
  is_signed = True
  byte_size = 2
  def __init__(self, value):
    super().__init__(value)
  @classmethod
  def opposite_signedness(self):
    return UINT16

class INT32(MachineInteger):
  is_signed = True
  byte_size = 4
  def __init__(self, value):
    super().__init__(value)
  @classmethod
  def opposite_signedness(self):
    return UINT32

class INT64(MachineInteger):
  is_signed = True
  byte_size = 8
  def __init__(self, value):
    super().__init__(value)
  @classmethod
  def opposite_signedness(self):
    return UINT64


def test_ccode_machine_int(argv):
  v = INT64(0x05dc9dde85e3f9e9).sub(UINT32(0x80000000))
  print(f'0x{v.value:x}')

  v = INT16(0x3d71).mul(INT8(0xc6))
  print(f'0x{v.value:x}')

  v = UINT32(0x1000).mul(UINT32(0xfff80010))
  print(f'0x{v.value:x}')

  v = UINT32(0x1000).mul(INT32(0xfff80010))
  print(f'0x{v.value:x}')

  v = INT32(0).assign(INT8(0x32))
  print(f'0x{v.value:x}')

  v = UINT32(1).sub(UINT32(0x72010504))
  print(f'0x{v.value:x}')

  v = UINT32(5).sub(UINT32(7))
  print(f'0x{v.value:x}')
  #assert(v == 0)
  v = UINT32(5).sub(INT32(7))
  print(f'0x{v.value:x}')
  #assert(v == 0)
  v = INT32(5).sub(INT32(7))
  print(f'0x{v.value:x}')
  #assert(v == 0)
  v = INT32(5).sub(INT32(7))
  print(f'0x{v.value:x}')
  #assert(v == 0)
  v = UINT32(5).sub(INT32(0xfffffff0)) # -= 1
  print(f'0x{v.value:x}')
  #assert(v == 0)
  v = UINT32(5).add(INT32(0x80000001)) # -= 1
  print(f'0x{v.value:x}')
  #assert(v == 0)
  v = INT32(0x80000003).add(INT32(0x80000001)) # -= 1
  print(f'0x{v.value:x}')
  #assert(v == 0)
  v = INT32(0x80000003).sub(INT32(0x80000001)) # -= 1
  print(f'0x{v.value:x}')
  #assert(v == 0)

if __name__ == '__main__':
  test_ccode_machine_int(sys.argv[1:])

