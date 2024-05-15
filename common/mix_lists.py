import random, sys

def mix_lists(list1, list2, rng) -> list:
  if len(list1) == 0:
    return list2.copy()
  if len(list2) == 0:
    return list1.copy()
  # we only need duplicated lists
  list1 = list1.copy()
  list2 = list2.copy()
  total_len = len(list1)+len(list2)
  proportion = len(list1)/len(list2)
  ret_list = []
  while len(ret_list) < total_len:
    list_to_use = rng.choices([list1, list2], k=1, weights=(proportion, 1))[0]
    if len(list_to_use) > 0:
      val = list_to_use.pop(0) #pop front
      ret_list.append(val)
    proportion = len(list1)/(len(list2) if len(list2) else 1)
  assert(len(ret_list) == total_len)
  return ret_list


def _test_simple():
  rng = random.Random(random.randint(0, sys.maxsize))
  list1 = [i for i in range(20)]
  list2 = ['a', 'b', 'c', 'd']
  for i in range(30):
    #print(f'{list1=}')
    #print(f'{list2=}')
    list_new = mix_lists(list1, list2, rng)
    print(list_new)

def _test_with(list1, list2, rng, expect_ret_list=None):
  for i in range(1000):
    list_new = mix_lists(list1, list2, rng)
    if expect_ret_list != None:
      if list_new != expect_ret_list:
        raise RuntimeError('unexpected ret list')

def _test_edgecases():
  rng = random.Random(random.randint(0, sys.maxsize))
  _test_with([], [], rng, [])
  _test_with(['a'], [], rng, ['a'])
  _test_with([], ['b'], rng, ['b'])
  _test_with(['a'], ['a'], rng, ['a', 'a'])

  _test_with(['a', 'b', 'c'], [], rng, None)
  _test_with([], ['a', 'b', 'c'], rng, None)
  _test_with([i for i in range(20)], ['a', 'b', 'c', 'd'], rng, None)

def test_mix_lists(argv):
  _test_simple()
  _test_edgecases()


if __name__ == '__main__':
  test_mix_lists(sys.argv[1:])





