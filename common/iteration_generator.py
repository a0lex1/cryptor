import sys
from typing import List, Dict

class EmptyRangeException(Exception):
  pass

class NoRangesException(Exception):
  pass

# |ranges| cannot be empty
# range cannot be 0 (empty)
class IterationGenerator:
  def __init__(self, ranges: list):
    if len(ranges) == 0:
      raise NoRangesException()
    self.validate_ranges(ranges)
    self.ranges = ranges

  def number_of_iterations(self) -> int:
    raise NotImplementedError()

  # returns positions for all ranges for N
  def iteration(self, N: int) -> List[int]:
    raise NotImplementedError()

  def validate_ranges(self, ranges):
    for range in ranges:
      assert(type(range) == int)
      if range == 0:
        raise EmptyRangeException('range cannot be empty')


class IterationGeneratorPositional(IterationGenerator):
  def number_of_iterations(self) -> int:
    # multiply all ranges
    g = self.ranges[0]
    assert(type(g) == int)
    for i in range(1, len(self.ranges)):
      r = self.ranges[i]
      g *= r
    return g

  def iteration(self, N:int) -> List[int]:
    cur = N
    poses = []
    #used_nodes = []
    for num_elems in self.ranges:
      ofs = cur % num_elems
      poses.append(ofs)
      cur //= num_elems
    return poses


class IterationGeneratorDiagonal(IterationGeneratorPositional):
  _reversed = False

  def set_reversed(self, reversed: bool):
    self._reversed = True
    return self

  def number_of_iterations(self) -> int:
    return max(self.ranges)

  # returns positions for all ranges for N
  def iteration(self, N: int) -> List[int]:
    poses = []
    for range in self.ranges:
      poses.append(N % range)
    return poses


def _test_itergen_expect(itergen, expect_instances: List[List]):
  instances = []
  for niter in range(itergen.number_of_iterations()):
    inst = itergen.iteration(niter)
    print(inst)
    instances.append(inst)
  if instances != expect_instances:
    print('expected instances:')
    print(expect_instances)
    print('got instances:')
    print(instances)
    raise RuntimeError('unexpected result of IterGen')


def _test_diagonal_simplecase():
  _test_itergen_expect(IterationGeneratorDiagonal([4, 2, 2, 1]),
                       [[0, 0, 0, 0],
                        [1, 1, 1, 0],
                        [2, 0, 0, 0],
                        [3, 1, 1, 0]
                       ])

def _test_edgecases(itergen_class):
  try:
    itergen = itergen_class([])
    raise RuntimeError('not reached')
  except NoRangesException:
    pass

  try:
    itergen = itergen_class([0])
    raise RuntimeError('not reached')
  except EmptyRangeException:
    pass

  _test_itergen_expect(itergen_class([1]), [[0]])
  _test_itergen_expect(itergen_class([1, 2]), [[0, 0], [0, 1]])


def _test_iteration_generator():
  ig = IterationGeneratorPositional([2, 3, 1, 4])
  for i in range(ig.number_of_iterations()):
    l = ig.iteration(i)
    print('list:', l)

def test_common_iteration_generator(argv):
  _test_iteration_generator()
  _test_diagonal_simplecase()
  _test_edgecases(IterationGeneratorPositional)
  _test_edgecases(IterationGeneratorDiagonal)

if __name__ == '__main__':
  test_common_iteration_generator(sys.argv[:1])






