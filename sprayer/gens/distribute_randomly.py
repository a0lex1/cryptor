import random
from typing import List


# Returns distributed numbers (paper#61)
# Warning, #SecurityOfRandomness not guaranteed (see comments)
def distribute_randomly(num_items:int, num_baskets:int, scatter_percent:int, rng) -> List[int]:
  assert (0 <= scatter_percent <= 100)
  if num_baskets == 0:
    if num_items != 0:
      raise RuntimeError('if num_baskets=0, num_items should be 0 too')
    return []
  if num_items == 0:
    return [0 for _ in range(num_baskets)]
  avg_items_per_basket = num_items // num_baskets
  if 0 == avg_items_per_basket:
    avg_items_per_basket = 1
  shift = round(avg_items_per_basket*scatter_percent/100)
  frm = avg_items_per_basket - shift
  to = avg_items_per_basket + shift
  baskets = [0 for _ in range(num_baskets)]
  itemsleft = num_items
  for nbasket in range(num_baskets):
    X = rng.randint(frm, to)
    if X > itemsleft:
      X = itemsleft
    baskets[nbasket] += X
    itemsleft -= X
    if 0 == itemsleft:
      break
  if itemsleft != 0:
    # What to do if some items left? A: Distribute the rest to random baskets.
    # The problem of this approach is:
    #   from the probability theory's perspective, the distribution details (math) are dark
    for nleftitem in range(itemsleft):
      basket_index = rng.randint(0, num_baskets-1)
      baskets[basket_index] += 1
  return baskets


############# TEST CODE ###################

class _Tester:
  def __init__(self, seed=None):
    self.__rng = random.Random(seed)

  def test(self, num_items, num_baskets, scatter_percent):
    l = distribute_randomly(num_items, num_baskets, scatter_percent, self.__rng)
    #print(l, sum(l))
    assert(sum(l) == num_items)
    return l

def test_distribute_randomly():
  for i in range(100):
    tester = _Tester()
    # common edge cases
    assert(tester.test(0, 0, 0) == [])
    assert(tester.test(0, 0, 50) == [])
    assert(tester.test(0, 0, 100) == [])

    # edge cases with scatter_percent=50
    assert(tester.test(0, 1, 50) == [0])
    assert(tester.test(1, 1, 50) == [1])
    assert(tester.test(9999, 1, 50) == [9999])

    # edge cases with scatter_percent=100
    assert(tester.test(0, 1, 100) == [0])
    assert(tester.test(1, 1, 100) == [1])
    assert(tester.test(9999, 1, 100) == [9999])

    # other cases
    tester.test(1, 10, 0)
    tester.test(1, 100, 0)
    tester.test(100, 1, 0)
    tester.test(100, 10, 0)
    tester.test(100, 100, 0)
    # with scatter_percent=55
    tester.test(1, 10, 55)
    tester.test(1, 100, 55)
    tester.test(100, 1, 55)
    tester.test(100, 10, 55)
    tester.test(100, 100, 55)
    # with scatter_percent=99
    tester.test(1, 10, 99)
    tester.test(1, 100, 99)
    tester.test(100, 1, 99)
    tester.test(100, 10, 99)
    tester.test(100, 100, 99)
    # with scatter_percent=100
    tester.test(1, 10, 100)
    tester.test(1, 100, 100)
    tester.test(100, 1, 100)
    tester.test(100, 10, 100)
    tester.test(100, 100, 100)


if __name__ == '__main__':
  test_distribute_randomly()







