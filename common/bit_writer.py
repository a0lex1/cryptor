import math

class BitWriter:
  # TODO add support for reversing the order?
  def __init__(self, num_values, bits_per_value):
    self.num_values = num_values
    self.bits_per_value = bits_per_value
    self.reset()

  def reset(self):
    self._bits_written = 0
    self._result = 0

  def all_written(self):
    assert(self._bits_written <= self.total_bits()) #
    return self._bits_written == self.total_bits()
  def total_bits(self):
    return self.num_values * self.bits_per_value
  def bits_written(self):
    return self._bits_written
  def values_written(self):
    assert(self._bits_written % self.bits_per_value == 0)
    return self._bits_written // self.bits_per_value
  def num_dwords(self):
    return math.ceil(self.total_bits() / 32)
  def max_value(self):
    return 2 ** self.total_bits() - 1

  def write_bits(self, value):
    assert(value <= self.max_value())
    assert(self._bits_written < self.total_bits())
    self._result |= value << self._bits_written
    assert(self._result <= self.max_value())
    self._bits_written += self.bits_per_value


  def value(self):
    assert(self._result <= self.max_value())
    return self._result


