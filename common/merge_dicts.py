import sys

# This help working with configs (null config, default config, extra config from json, apply it to each other, etc)

# possible options: allow_change_value_type:bool
import copy


def merge_dicts(dictA, dictB, allow_A_only, allow_B_only):
  dictA_copy = copy.deepcopy(dictA) # to track RuntimeError('item only in A
  overwritten, _visited = 0, 0
  for kB in dictB.keys():
    if not kB in dictA:
      if not allow_B_only:
        raise RuntimeError('item only in B (can\'t overwrite)')
      continue
    else:
      if type(dictB[kB]) == dict:
        # subdict, recursion
        if kB in dictA:
          assert(type(dictA[kB]) == dict) # in A, must be dict too
        merge_dicts(dictA[kB], dictB[kB], allow_A_only, allow_B_only)
      else:
        dictA[kB] = dictB[kB]
        overwritten += 1
      del dictA_copy[kB]
    pass
  if not allow_A_only:
    #if overwritten != len(dictA):
    if len( dictA_copy):
      raise RuntimeError('item only in A (not all overwritten)') # check dictA_copy



def _test_recurs():
  def make_null_conf():
    return \
    {
      'book': {
        'author': 'NextPeople',
        'year': 1967,
        'titles': {
          'a': None,
          'b': None,
          'c': {
            'eee': None,
          }
        }
      },
      'a': None,
      'b': None,
    }
  conf = make_null_conf()
  extraconf = {
    'book': {
      'year': 2390,
      'titles': {
        'c': {
          'eee': 'HI!'
        }
      }
    },
    'b': 2222,
  }
  merge_dicts(conf, extraconf, True, False)

  expected =\
    {
      'book': {
        'author': 'NextPeople',
        'year': 2390,
        'titles': {
          'a': None,
          'b': None,
          'c': {
            'eee': 'HI!',
          }
        }
      },
      'a': None,
      'b': 2222,
    }

  if conf != expected:
    print(conf)
    raise RuntimeError('test 1 - unexpected')



# non-recursive
def _test():
  def make_null_conf():
    return \
    {
      'a': None,
      'b': None,
      'c': None,
    }

  ######## EXPECT SUCCESS ########
  conf = make_null_conf()
  extraconf = {
    'b': 12,
  }
  merge_dicts(conf, extraconf, True, False)
  if conf != {'a': None, 'b': 12, 'c': None}:
    print(conf)
    raise RuntimeError('test 1 - unexpected')

  conf = make_null_conf()
  extraconf = {
    'x': 999,
    'a': 1,
    'b': 2,
    'c': 3,
  }
  merge_dicts(conf, extraconf, False, True)
  if conf != {'a': 1, 'b': 2, 'c': 3}:
    print(conf)
    raise RuntimeError('test 2 - unexpected')

  ######## EXPECT EXCEPTION ########
  try:
    print('**')
    conf = make_null_conf()
    extraconf = {
      'b': 12,
      'x': 404,  # << allow_B_only=False
    }
    merge_dicts(conf, extraconf, True, False)
    assert(not 'not reached')
  except RuntimeError as e:
    print(f'ok, expected exception 1 - {e}')
    pass

  try:
    conf = make_null_conf()
    # we don't put 'c' and allow_A_only=False so we expect exception
    extraconf = {
      'a': 42132,
      'b': 3128,
    }
    merge_dicts(conf, extraconf, False, True)
    assert(not 'not reached')
  except RuntimeError as e:
    print(f'ok, expected exception 2 - {e}')

def test_common_merge_dicts(argv):
  _test()
  _test_recurs()


if __name__ == '__main__':
  test_common_merge_dicts(sys.argv[1:])
