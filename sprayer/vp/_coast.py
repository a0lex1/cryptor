from typing import List

# UPD: Not used now.

# A mechanism used by coasts. Both L and R coast points are separately passed to make_distance_lists
# to make distance lists for both L and R. `left` and `right` here are not those from coasts.
# Coasts' L will have left and right here, as well as coasts' R.
#                            dest_indices
#                            /           \
#                           |            |
#                 #0  1  2  3  4  5  6  7
#  your list:     [x, x, x, x, x, x, x, x]   # not passed to this func; only |list_size| is passed
#  dest_indices:  [         3,          7]
#
#  distance_list: [3, 2, 1, 0, -1, -2, 1, 0] # output, pre-allocated, items overwritten
#
# |eq_prefer_left| - prefer left when distances to left and right are equal in modulus, otherwise, prefer right
#
def make_distance_lists(list_size:int, dest_indices:List[int], distance_list:List[int],
                        eq_prefer_left=True,
                        sanity_checks=True):
  if sanity_checks:
    assert(len(dest_indices) > 0)
    assert(len(distance_list) == list_size)
    assert(sorted(dest_indices) == dest_indices)
    assert(all(di >= 0 for di in dest_indices))
    assert(max(dest_indices) < list_size)
  idx_before = None
  right_dest = dest_indices.pop(0)
  for cursor in range(list_size):
    if cursor == right_dest:
      idx_before = right_dest
      if len(dest_indices):
        right_dest = dest_indices.pop(0)
      else:
        right_dest = None
    dist_to_left = None
    dist_to_right = None
    if idx_before != None:
      dist_to_left = idx_before-cursor
    if right_dest != None:
      dist_to_right = right_dest-cursor
    if dist_to_left == None:
      # left is not yet set
      assert(dist_to_right != None)
      distance_list[cursor] = dist_to_right
    else:
      if dist_to_right == None:
        assert (dist_to_left != None)
        distance_list[cursor] = dist_to_left
      else:
        # both left and right are set, compare them; if eq, use |eq_prefer_left| to decide
        if abs(dist_to_left) < abs(dist_to_right):
          distance_list[cursor] = dist_to_left
        elif abs(dist_to_left) > abs(dist_to_right):
          distance_list[cursor] = dist_to_right
        else:
          assert(abs(dist_to_left) == abs(dist_to_right))
          if eq_prefer_left:
            distance_list[cursor] = dist_to_left
          else:
            distance_list[cursor] = dist_to_right

def _test_make_distance_list_with(list_size, dest_indices, expected_distance_list, **kwargs):
  actual_distance_list = [None for _ in range(list_size)]
  make_distance_lists(list_size, dest_indices, actual_distance_list, **kwargs)
  if actual_distance_list != expected_distance_list:
    print('Expected distance list:')
    print(expected_distance_list)
    print('Got distance list:')
    print(actual_distance_list)
    raise RuntimeError('actual distance list != expected distance list, see log')

def test_make_distance_list():
  # common case
  _test_make_distance_list_with(8, [3, 7], [3, 2, 1, 0, -1, -2, 1, 0])
  _test_make_distance_list_with(8, [3, 7], [3, 2, 1, 0, -1, 2, 1, 0], eq_prefer_left=False) # prefer right
  _test_make_distance_list_with(8, [3, 7], [3, 2, 1, 0, -1, -2, 1, 0])

  # with only one item in dest_indices
  _test_make_distance_list_with(8, [7], [7, 6, 5, 4, 3, 2, 1, 0])
  _test_make_distance_list_with(8, [1], [1, 0, -1, -2, -3, -4, -5, -6])
  _test_make_distance_list_with(8, [0], [0, -1, -2, -3, -4, -5, -6, -7])

  # with first 0
  _test_make_distance_list_with(8, [0, 7], [0, -1, -2, -3, 3, 2, 1, 0])

  # with neighbor dest_indices
  _test_make_distance_list_with(8, [0, 1], [0, 0, -1, -2, -3, -4, -5, -6])
  _test_make_distance_list_with(8, [5, 6], [5, 4, 3, 2, 1, 0, 0, -1])

  # with dest_indices first and last
  _test_make_distance_list_with(8, [0, 7], [0, -1, -2, -3, 3, 2, 1, 0])

  # with all indices in dest_indices
  _test_make_distance_list_with(8, [0, 1, 2, 3, 4, 5, 6, 7], [0, 0, 0, 0, 0, 0, 0, 0])

  # with >2 items in dest_indices
  _test_make_distance_list_with(8, [0, 4, 6], [0, -1, -2, 1, 0, -1, 0, -1])
  _test_make_distance_list_with(8, [0, 4, 6], [0, -1, 2, 1, 0, 1, 0, -1], eq_prefer_left=False) # prefer right


if __name__ == '__main__':
  test_make_distance_list()


####################

# input_list -> [0, 0, 1, 2, 3, 4, 5, 0, 0, 0, 0, 9, 10, 0, 0, ]

def make_coast_distance_lists(input_list:List[int], llist:List[int], rlist:List[int]):
  L_indices
  R_indices

  idx_prev_l
  idx_next_l
  idx_prev_r
  idx_next_r

  llist[x] = y
  rlist[x] = y

def test_make_coast_distance_lists():
  pass

if __name__ == '__main__':
  test_make_coast_distance_lists()


