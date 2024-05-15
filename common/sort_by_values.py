from collections import OrderedDict


# Returns dict of same items, but sorted by values
def sort_by_values(dickt:dict, reverse=False):
  return OrderedDict(sorted(dickt.items(), key=lambda x: x[1], reverse=reverse))

def test_sort_by_values():
  assert(sort_by_values(OrderedDict({'a': 5, 'e': 3, 'z': 7, 'c': 4, 'h': 2, 'j': 6 }))
         == OrderedDict({'h': 2, 'e': 3, 'c': 4, 'a': 5, 'j': 6, 'z': 7}))


from functools import cmp_to_key, partial

# Test only with eyes
def sort_by_values_randomize_equal(dickt:dict, rng, reverse=False):
  our_rng = rng
  def cmpfunc(A, B):
    assert(type(A) == tuple)
    assert(type(B) == tuple)
    if A[1] == B[1]: # if values EQ
      return our_rng.choice([1, -1]) # random > or <
    else:
      assert(type(A[1]) == int)
      return A[1] - B[1]
  return OrderedDict(sorted(dickt.items(), key=cmp_to_key(cmpfunc), reverse=reverse))


def sample_sort_by_values_randomize_equal():
  import random
  dict_with_samekeys = {'x': 7, 'g': 7, 'e': 5, 'l': 5, 'j': 23, 'k': 23, 'w': 12, 'q': 7, 'm': 17, 'd': 17, 's': 10, 'u': 19, 'c': 14, 'p': 14}
  print('sample_sort_by_values_randomize_equal doing 50 times print')
  for i in range(50):
    sorted_randomized = sort_by_values_randomize_equal(dict_with_samekeys, random.Random())
    print('sorted, randomized where eq:', list(sorted_randomized.items()))
  print('sample_sort_by_values_randomize_equal done')


if __name__ == '__main__':
  test_sort_by_values()
  sample_sort_by_values_randomize_equal()


