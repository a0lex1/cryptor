import sys


def get_all_keys(d: dict, lst):
  for k in d.keys():
    v = d[k]
    lst.append(k)
    if type(v) == dict:
      get_all_keys(v, lst)

def _test_get_all_keys():
  d = {
    'a': 1,
    'b': 2,
    'c': {
      'ho': 5,
      'z': 10,
      'm': {
        'p': 1
      }
    }
  }
  all_keys = []
  get_all_keys(d, all_keys)
  print(all_keys)


def test_common_get_all_keys(argv):
  _test_get_all_keys()


if __name__ == '__main__':
  test_common_get_all_keys(sys.argv[1:])
