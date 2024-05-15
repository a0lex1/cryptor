import sys, random
from typing import Tuple

# sx is a concept of giving either integer number or a range to randomly pick from
# Maximum included in range too! (like in random.randint)
# example of sx(es):  0  1  123123  0..33   0..0  44..9911
class Sx:
  # public:
  def __init__(self, interpretation:str, rng=None, limit:Tuple[int, int]=None):
    self.interpretation = interpretation
    if rng == None:
      rng = random.Random()
    self._rng = rng
    self._limit = limit
    assert (self._limit == None or type(self._limit) == tuple)
    self._splitter = '..'

    self.is_range_used = None
    self.minimum, self.maximum = None, None

    self.__parse()
    self.__validate()

  def make_number(self) -> int:
    return self._rng.randint(self.minimum, self.maximum)

#private:
  def __parse(self):
    if self.interpretation.isdigit():
      self.minimum = int(self.interpretation)
      self.maximum = self.minimum
      self.is_range_used = False
      return
    else:
      parts = self.__split()
      if parts:
        # successfully parsed
        self.minimum, self.maximum = parts
        return
    raise RuntimeError(f'{self.interpretation=} is NOT a correct sx string')

  def __split(self):
    p = self.interpretation.split(self._splitter)
    if len(p) == 2:
      frm, to = p
      if frm.isdigit() and to.isdigit():
        return int(frm), int(to)

  def __validate(self):
    if self._limit != None:
      assert(type(self._limit) == tuple)
      if self.minimum < self._limit[0]:
        raise RuntimeError(f'sx minimum value {self._limit[0]} is <breached by {self.minimum=}')
      if self.maximum > self._limit[1]:
        raise RuntimeError(f'sx maximum value {self._limit[1]} is >breached by {self.maximum=}')



def _test():
  sx = Sx('')
  assert(not sx.is_valid())
  assert(not sx.is_randrange())
  sx = Sx('a')
  assert(not sx.is_valid())
  assert(not sx.is_randrange())
  sx = Sx('0')
  assert(sx.is_valid())
  assert(not sx.is_randrange())
  assert(sx.get_num() == 0)
  sx = Sx('1')
  assert(sx.is_valid())
  assert(not sx.is_randrange())
  assert(sx.get_num() == 1)
  sx = Sx('123')
  assert(sx.is_valid())
  assert(not sx.is_randrange())
  assert(sx.get_num() == 123)
  ### now test with ranges
  # simple case
  sx = Sx('0..10')
  assert(sx.is_valid())
  assert(sx.is_randrange())
  n = sx.get_num()
  assert(n >= 0 and n <= 10)
  # more cases
  sx = Sx('0..0')
  assert(sx.is_valid())
  assert(sx.is_randrange())
  n = sx.get_num()
  assert(n == 0)
  # more cases
  sx = Sx('5..5')
  assert(sx.is_valid())
  assert(sx.is_randrange())
  n = sx.get_num()
  assert(n == 5)


def test_common_sxes(argv):
  _test()

if __name__ == '__main__':
  test_common_sxes(sys.argv[1:])


