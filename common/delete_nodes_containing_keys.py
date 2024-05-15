from pprint import pprint

from c2.common.jpath import *

def delete_nodes_containing_keys(d:dict, keys:list):
  paths = [] # [ ['a', 'b', 'subd'],  ['a'],  ]
  jpath_enum_l(d, paths) # both keys and values
  # collect interested paths
  paths2delete = []
  for path in paths:
    # path -> ['root', 'sub', 'field1']
    if path[-1] in keys:
      # remember to erase the entire node which contains $jif
      paths2delete.append(path[0:-1])
  # delete collected paths
  for path2delete in paths2delete:
    jpath_delete_l(d, path2delete, ignore_errors=True)

def _test_delete_nodes_containing_keys():
  _t = {
    'a': 1,
    'b': {
      'c': 2,
      'd': {
        'e': {
          'f': 3,
          'g': 4
        },
        'k': {
          'o': 11
        }
      },
      'p': {
        'm': 99
      },
      'q': {
        'u': {
          'v': 123,
          'r': 999
        }
      }
    }
  }
  pprint(_t)
  delete_nodes_containing_keys(_t, ['r', 'g'])
  pprint(_t)
  assert(_t == {'a': 1, 'b': {'c': 2, 'd': {'k': {'o': 11}}, 'p': {'m': 99}, 'q': {}}})


if __name__ == '__main__':
  _test_delete_nodes_containing_keys()
