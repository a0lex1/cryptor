import math, numpy as np, sys, copy, argparse, random, os
from typing import List

from pprint import pprint
from numpy.random import MT19937
from numpy.random import RandomState, SeedSequence


class SinWavesCoefficents:
  def __init__(self, S, a, b):
    self.S = S
    self.a = a
    self.b = b


class RandomSinWaveCoeff(SinWavesCoefficents):
  def __init__(self, num_sins=5, rng=None):
    if rng == None:
      rng = random.Random()
    self._rng = rng
    self._rs = RandomState(MT19937(SeedSequence(self._rng.randint(0, sys.maxsize))))

    pi = np.pi

    self.S = self._rand(0, pi * 2)

    self.a = [1]
    for i in range(1, num_sins):
      # add 1..3
      # self.a.append(self.a[i-1] + self.rs.randint(1, 4))
      self.a.append(self.a[i - 1] + self._rs.randint(1, 3))
      # self.a.append(1)
    assert (len(self.a) == num_sins)

    self.b = self._randlist(num_sins, 0.25, 1.0)
    # self.b = [1] + self._randlist(num_sins-1, 0.25, 1.0)
    # self.b = [1 for _ in range(num_sins)]
    assert (len(self.a) == len(self.b))

  def _rand(self, min, max):
    return self._randlist(1, min, max)[0]

  def _randlist(self, count, min, max):
    if count == 0:
      return []
    return [min + z * (max - min) for z in self._rs.rand(1, count)[0]]


class SinWaves:
  def __init__(self, params, W=1):
    self.params = params
    self.W = W

  def f(self, x):
    W = self.W
    S, a, b = self.params.S, self.params.a, self.params.b
    n = len(a)
    pi = np.pi
    c = []
    for i in range(n):
      c.append(math.sin((2 * pi * x * a[i] / W) + S) * b[i])  # nerd
    r = sum(c)
    r /= n
    return r


# Adjust by calling f twice
# extramul is useful for showing more than one period of function (see how it looks as repeated wave)
# round_to=28 is the default of python's round()
def adjust_sinwaves(params, W, H, positive=False, amplify_to_height=False, round_to=28) -> List[int]:
  if W == 0:
    return []  # empty list, as the most obvious result in this case
  w = SinWaves(params, W)
  # stage 1: calc y=f(x) to find ymin, ymax
  Y = [w.f(x) for x in range(W)]
  ymin = min(Y)
  ymax = max(Y)
  # print('ymin', ymin, 'ymax', ymax, 'amp', amp)
  if amplify_to_height:
    divby = ymax - ymin
    if divby == 0:
      # if W==1, this case; escape division by zero
      amp = 1
    else:
      amp = 1 / divby
  else:
    amp = 1
  if positive:
    sub = ymin
  else:
    sub = 0
  # stage 2: calc y=f(x) stretched to min..max
  Y2 = [(w.f(x) - sub) * amp for x in range(W)]  # stretch
  # if amplify_to_height:
  for x in range(W):
    Y2[x] *= H
  for x in range(W):
    Y2[x] = round(Y2[x], round_to)
  # print('min(Y2)', min(Y2), 'max(Y2)', max(Y2))
  assert (min(Y2) >= 0 or max(Y2) <= H)
  return Y2


def test_wave():
  '''
  (5.002191137850155,
 [1, 3, 4, 6, 7],
 [0.2505560727021031,
  0.619194965423739,
  0.931265179684234,
  0.5660234527097594,
  0.6874425757761075],
 1,
 2147483647,
 True,
 True,
 None)
  '''
  adjust_sinwaves(SinWavesCoefficents(5.002191137850155,
                                       [1, 3, 4, 6, 7],
                                       [0.2505560727021031,
                                        0.619194965423739,
                                        0.931265179684234,
                                        0.5660234527097594,
                                        0.6874425757761075]), 1, 2147483647, True, True, None)  # should crash
  raise RuntimeError('not reached! should crash above!')
  pass


#NotAddedToTests
if __name__ == '__main__':
  test_wave()
