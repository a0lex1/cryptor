import sys
from pprint import pprint
from typing import List
from dataclasses import dataclass

'''{
  "Buffer": {
    "StringA": {                # StringA, StringW
      "PathA": {                # PathA, PathW
        "FilePathA": { },       # FilePathA, FilePathW
        "DirectoryPathA": { }   #
      }
    },
    "StringW": {
      "PathW": {
        "FilePathW": { },
        "DirectoryPathW": { }
      }
    }
  },

}
'''

@dataclass
class DictKeycharExpander:
  clone_char : str = '@'
  clone_repls : List[str] = None

  def expand(self, node:dict, expanded_node:dict):
    assert(type(node) == dict)
    assert(type(expanded_node) == dict)
    _RECURSE = self.expand
    for key in node.keys():
      value = node[key]
      if self.clone_char in key:
        self._clone(node, expanded_node, key)
      else:
        if type(value) == dict:
          expanded_node[key] = {}
          _RECURSE(value, expanded_node[key])
        else:
          expanded_node[key] = value
      pass
    pass

  def _clone(self, d:dict, new_d:dict, key):
    for nreplchar in range(len(self.clone_repls)):
      cur_repl_char = self.clone_repls[nreplchar]
      new_key = key.replace(self.clone_char, cur_repl_char)
      val = d[key]
      if type(val) == dict:
        new_valnode = {}
        self._get_replaced(d[key], new_valnode, cur_repl_char)
        new_d[new_key] = new_valnode
      else:
        new_d[new_key] = val
    pass

  def _get_replaced(self, d:dict, new_d:dict, repl_char):
    _RECURSE = self._get_replaced
    for key in d.keys():
      new_key = key.replace(self.clone_char, repl_char)
      value = d[key]
      if type(value) == dict:
        new_d[new_key] = {}
        _RECURSE(value, new_d[new_key], repl_char)
      else:
        new_d[new_key] = value
     #TODO: replace in VALUES (strings, ) ?



def _test_dict_keychar_expander():
  test_dict = {
    'hello': {
      'String@': {
        '_test': True,
        'Path@': {
          'FilePath@': { 'x': 3, 'y': 4, 'z': { 'm': 0, 'e': 1 } },
          'DirectoryPath@': { 'a': False }
        }
      }
    },
    'WndProc@': {},
    'WndProc2@': { 'x': 1 },
    'WndProc3@': {
      'LPMSG@': 1,
      'LPCTX@': 'Struct'
    }
  }
  ed = {}
  DictKeycharExpander('@', ['A', 'W']).expand(test_dict, ed)

  #
 # TODO: replace in VALUES

  expected_ed = {
    'hello': {
      'StringA': {
        '_test': True,
        'PathA': {
          'FilePathA': { 'x': 3, 'y': 4, 'z': { 'm': 0, 'e': 1 } },
          'DirectoryPathA': { 'a': False },
        }
      },

      'StringW': {
        '_test': True,
        'PathW': {
          'FilePathW': { 'x': 3, 'y': 4, 'z': { 'm': 0, 'e': 1 } },
          'DirectoryPathW': { 'a': False }
        }
      }

    },
    'WndProcA': {},
    'WndProcW': {},
    'WndProc2A': { 'x': 1 },
    'WndProc2W': { 'x': 1 },
    'WndProc3A': {
      'LPMSGA': 1,
      'LPCTXA': 'Struct'
    },
    'WndProc3W': {
      'LPMSGW': 1,
      'LPCTXW': 'Struct'
    }
  }

  if ed != expected_ed:
    print('ORIGINAL:')
    pprint(test_dict)
    print()
    print('EXPECTED:')
    pprint(expected_ed)
    print('GOT:')
    pprint(ed)
    print()
    raise RuntimeError()

  return


def test_common_dict_keychar_expander(argv):
  _test_dict_keychar_expander()

if __name__ == '__main__':
  test_common_dict_keychar_expander(sys.argv[1:])



