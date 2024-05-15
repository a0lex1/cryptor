import json, sys

from c2.infra.jen import Jen


_test_dict = {
  "a": 123,
  "b": "big",
  "c": ["$jcs", "one", "two", "three"],
  "block": {
    "A": 1,
    "B": ["$jcn", '19', '33'],
    "sb": ['55', '66'] # no $jc
  },
  "nl0": [],
  "nl1": ["sup"],
  "nl2": ["hello", "nokia"],
  "lol": [ '$jcn', '100', '200' ],
  "bl": [ '$jcb', 'true', 'false' ]
}

def _test_jen():
  print("Default order--------------------")
  jen = Jen(_test_dict, []) # default order
  jen.build()
  for niter in range(jen.number_of_iterations()):
    e = jen.iteration(niter)
    print(e)

def _test_jen_custom_order():
  print("Custom order--------------------")
  jen = Jen(_test_dict, 'lol,block.B,c'.split(',')).build()
  for niter in range(jen.number_of_iterations()):
    e = jen.iteration(niter)
    print(e)

def _test_jen_nojen():
  jen = Jen({"a": 1, "b": 2, "c": {"x": "A", "y": "E"}}, []).build()
  assert(jen.number_of_iterations() == 1)
  assert(jen.iteration(0) == {"a": 1, "b": 2, "c": {"x": "A", "y": "E"}})

# a case when order list contains keys that are removed after filtering over {'A2'}
def  _test_exclude_by_key_easy_worder():
  d = {
    'Z': {
      'A': {
        'A1': ['$jcn', '6','7','8'],
        'A2': 2  # a signal to exclude the entire A block
      },
      'B': {
        'B1': ['$jcn', '55','66'],
        'B2': ['$jcs', 'eee', 'fff']
      }
    }
  }
  print('_test_exclude_by_key_easy_worder()')
  jen = Jen(d, ['Z.B.B2', 'Z.A.A1', 'Z.B.B1'], keys_to_exclude_node={'A2'},
            ignore_nonexisting_order_key=True)
  jen.build()
  ni = jen.number_of_iterations()
  jens = []
  for i in range(ni):
    inst = jen.iteration(i)
    print(inst)
    jens.append(inst)
  assert(jens == [{'Z': {'B': {'B1': 55, 'B2': 'eee'}}}, {'Z': {'B': {'B1': 55, 'B2': 'fff'}}}, {'Z': {'B': {'B1': 66, 'B2': 'eee'}}}, {'Z': {'B': {'B1': 66, 'B2': 'fff'}}}])


def  _test_exclude_by_key_easy():
  d = {
    'Z': {
      'A': {
        'A1': ['$jcn', '6','7','8'],
        'A2': 2
      },
      'B': {
        'B1': ['$jcn', '55','66'],
        'B2': ['$jcs', 'eee', 'fff']
      }
    }
  }
  print('_test_exclude_by_key_easy()')
  jen = Jen(d, [], keys_to_exclude_node={'A2'}).build()
  ni = jen.number_of_iterations()
  jens = []
  for i in range(ni):
    d = jen.iteration(i)
    jens.append(d)
  assert(jens == [{'Z': {'B': {'B1': 55, 'B2': 'eee'}}},
                   {'Z': {'B': {'B1': 66, 'B2': 'eee'}}},
                   {'Z': {'B': {'B1': 55, 'B2': 'fff'}}},
                   {'Z': {'B': {'B1': 66, 'B2': 'fff'}}}
                  ])

#3*2*2 *2
def  _test_exclude_by_key_complex():
  d = {
    'a': 1,
    'b': ['$jcs', 'hi', 'sup', 'bye'],
    'c': {
      'x': 22,
      'y': {
        'ee': ['$jcn', '37', '47'],
        'pp': 55
      },
      'mz': {
        'z': {
          'oo': {
            '_SKIPME_': 123,
            'mm': {
              'eeee': ['$jcb', 'true', 'false']
            }
          },
          'cc': {
            'psdp': {
              'iii': {
                'ioa': ['$jcs', 'aaa', 'bbb']
              }
            }
          }
        },
        'mz': {
          'jpp': 123,
          'eii': ['$jcb', 'true', 'false']
        }
      }
    }
  }
  jen = Jen(d, [], {'_SKIPME_'}).build()
  for niter in range(jen.number_of_iterations()):
    inst = jen.iteration(niter)
    print(inst)

    inst_text = json.dumps(inst)
    assert(not '_SKIPME_' in inst_text)

  assert(jen.number_of_iterations() == 3*2*2*2)
  return


def  _test_ignore_nonexisting_order_key():
  pass # TODO

def _test_reverse_values():
  jen = Jen(_test_dict, [], reverse_values=True)
  jen.build()
  ni = jen.number_of_iterations()
  jens = []
  for i in range(ni):
    inst = jen.iteration(i)
    print(inst)
    jens.append(inst)
  assert(jens == [{'a': 123, 'b': 'big', 'bl': False, 'block': {'A': 1, 'B': 33, 'sb': ['55', '66']}, 'c': 'three', 'lol': 200, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': False, 'block': {'A': 1, 'B': 33, 'sb': ['55', '66']}, 'c': 'two', 'lol': 200, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': False, 'block': {'A': 1, 'B': 33, 'sb': ['55', '66']}, 'c': 'one', 'lol': 200, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': False, 'block': {'A': 1, 'B': 19, 'sb': ['55', '66']}, 'c': 'three', 'lol': 200, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': False, 'block': {'A': 1, 'B': 19, 'sb': ['55', '66']}, 'c': 'two', 'lol': 200, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': False, 'block': {'A': 1, 'B': 19, 'sb': ['55', '66']}, 'c': 'one', 'lol': 200, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': False, 'block': {'A': 1, 'B': 33, 'sb': ['55', '66']}, 'c': 'three', 'lol': 100, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': False, 'block': {'A': 1, 'B': 33, 'sb': ['55', '66']}, 'c': 'two', 'lol': 100, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': False, 'block': {'A': 1, 'B': 33, 'sb': ['55', '66']}, 'c': 'one', 'lol': 100, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': False, 'block': {'A': 1, 'B': 19, 'sb': ['55', '66']}, 'c': 'three', 'lol': 100, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': False, 'block': {'A': 1, 'B': 19, 'sb': ['55', '66']}, 'c': 'two', 'lol': 100, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': False, 'block': {'A': 1, 'B': 19, 'sb': ['55', '66']}, 'c': 'one', 'lol': 100, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': True, 'block': {'A': 1, 'B': 33, 'sb': ['55', '66']}, 'c': 'three', 'lol': 200, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': True, 'block': {'A': 1, 'B': 33, 'sb': ['55', '66']}, 'c': 'two', 'lol': 200, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': True, 'block': {'A': 1, 'B': 33, 'sb': ['55', '66']}, 'c': 'one', 'lol': 200, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': True, 'block': {'A': 1, 'B': 19, 'sb': ['55', '66']}, 'c': 'three', 'lol': 200, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': True, 'block': {'A': 1, 'B': 19, 'sb': ['55', '66']}, 'c': 'two', 'lol': 200, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': True, 'block': {'A': 1, 'B': 19, 'sb': ['55', '66']}, 'c': 'one', 'lol': 200, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': True, 'block': {'A': 1, 'B': 33, 'sb': ['55', '66']}, 'c': 'three', 'lol': 100, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': True, 'block': {'A': 1, 'B': 33, 'sb': ['55', '66']}, 'c': 'two', 'lol': 100, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': True, 'block': {'A': 1, 'B': 33, 'sb': ['55', '66']}, 'c': 'one', 'lol': 100, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': True, 'block': {'A': 1, 'B': 19, 'sb': ['55', '66']}, 'c': 'three', 'lol': 100, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': True, 'block': {'A': 1, 'B': 19, 'sb': ['55', '66']}, 'c': 'two', 'lol': 100, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}, {'a': 123, 'b': 'big', 'bl': True, 'block': {'A': 1, 'B': 19, 'sb': ['55', '66']}, 'c': 'one', 'lol': 100, 'nl0': [], 'nl1': ['sup'], 'nl2': ['hello', 'nokia']}])


def test_jen(argv):
  _test_jen()
  _test_jen_custom_order()
  _test_jen_nojen()

  _test_exclude_by_key_easy()
  _test_exclude_by_key_complex()
  _test_exclude_by_key_easy_worder()
  _test_ignore_nonexisting_order_key()
  _test_reverse_values()


if __name__ == '__main__':
  test_jen(sys.argv[1:])
