# for now, this is the only use of sklearn; heavy package...
from numbers import Number
from typing import List

import sklearn.preprocessing

def normalize(list_of_numbers:List[Number]) -> List[Number]:
  # it's numpy.ndarray, convert it to list
  return list(sklearn.preprocessing.normalize([list_of_numbers], norm='max')[0])


def test_normalize():
  nums = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
  normed = normalize(nums)
  print(normed)


if __name__ == '__main__':
  test_normalize()




