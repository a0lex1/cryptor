import sys
from typing import List
from dataclasses import dataclass
from enum import Enum, auto
from pprint import pprint

from c2.common.jpath import *
from c2.infra.jen import Jen

# JIFResolver works with single instance, $jif(s) are in that instance
#
# #AvoidDynamicJifs e.g. don't let it be like xxx:{$jif:['rgdumb.someopt', 'someval'] (rgdumb's existence is itself under $jif)
# $jif should not resolve a node which existence is under another $jif (because order of resolving is not met:
# a node which is statically has proper value, but wouldn't exist due to its own $jifs... such condition
# would be considered True. See _test_jif_resolver_mutual_jifs1. But IMPORTANT, that implicit existence
# depending through parent node is OK.
#
class JIFResolver:
  def __init__(self):
    pass

  @dataclass
  class _ResolveCounters:
    nfoundeq: int = 0
    nfoundneq: int = 0
    nnotfound: int = 0

  class _LastIfTruthness(Enum):
    NOT_SET = auto()
    TRUE = auto()
    FALSE = auto()
    PATH_NOT_FOUND = auto()

  # all $jif(s) are checked over the initial |jen_from| dict
  # if you don't want counting, set resolve_counters to None
  def resolve_jifs(self,
                   jen_from,
                   jen_to,
                   resolve_counters:_ResolveCounters,  # output, but can be None
                   resolve_referee_inst = None         # if you want to resolve against another inst
                   ):
    self._resolve_jifs_worker(jen_from, jen_to, resolve_counters, resolve_referee_inst)


  def _resolve_jifs_worker(self,
                           jen_from,
                           jen_to,
                           resolve_counters,
                           resolve_referee_inst,
                           _lit = _LastIfTruthness.NOT_SET,
                           _cur_path=None,
                           _root=None):
    _RECURSE = self._resolve_jifs_worker
    assert(type(jen_from) == dict and type(jen_to) == dict)
    if _root == None:
      _root = jen_from
    _LastIfTruthness = JIFResolver._LastIfTruthness
    DEFER_JCLIST = True #Defer

    if _cur_path == None:
      _cur_path = []

    for k in jen_from.keys():
      v = jen_from[k]
      cur_path_k = _cur_path + [k]
      if type(v) == dict:
        # need to recursive enter
        # by default, use current lit
        _lit = _lit
        if '$jif' in v:
          # in this case, _lit will be changed to the result of _check_cond
          assert(type(v['$jif']) == list)
          assert(len(v['$jif']) == 2)

          _check_against_inst = resolve_referee_inst if resolve_referee_inst else _root
          _lit = JIFResolver._check_cond(_check_against_inst, v['$jif'], DEFER_JCLIST)

          if _lit == _LastIfTruthness.TRUE:
            # <found and eq>  ->  copy entire node except $jif itself
            if resolve_counters:
              resolve_counters.nfoundeq += 1

          elif _lit == _LastIfTruthness.FALSE:
            # <found and not eq>  ->  don't copy entire node
            if resolve_counters:
              resolve_counters.nfoundneq += 1
            continue

          elif _lit == _LastIfTruthness.PATH_NOT_FOUND:
            # <not found> ->  leave, don't touch
            if resolve_counters:
              resolve_counters.nnotfound += 1

          elif _lit == _LastIfTruthness.NOT_SET:
            raise RuntimeError('_check_cond must not return NOT_SET')
          else:
            raise RuntimeError('unexpected value')

        jen_to[k] = {}

        ######
        _RECURSE(v, jen_to[k], resolve_counters, resolve_referee_inst, _lit, cur_path_k, _root)

      else:
        # actually copy value
        if k == '$jif':
          assert(_lit == _LastIfTruthness.TRUE or _lit == _LastIfTruthness.PATH_NOT_FOUND) # can't be False
          if _lit == _LastIfTruthness.TRUE:
            # skip copying #jif it it was true; otherwise, in do-not-touch mode, do not forbid copying
            continue
        #cur_path_k_str = '.'.join(cur_path_k) # what was that for?
        jen_to[k] = v
        pass

      pass
    return


  def _check_cond(root:dict, lst_node:list, defer_jclist:bool):
    # lst_node -> ['a', 12]
    _LastIfTruthness = JIFResolver._LastIfTruthness
    assert(type(root) == dict and type(lst_node) == list)
    value_path, value_expected = lst_node

    try:
      value_actual = jpath_get_s(root, value_path)
    except JPathKeyNotFound as e:
      # key not found
      return _LastIfTruthness.PATH_NOT_FOUND

    if Jen._is_jc_list(value_actual):
      if defer_jclist: #Defer
        return _LastIfTruthness.PATH_NOT_FOUND

    return _LastIfTruthness.TRUE if value_actual == value_expected else _LastIfTruthness.FALSE



def _test(d, rc_expected, inst_expected=None):
  inst = {}
  jr = JIFResolver()
  rc = JIFResolver._ResolveCounters()
  jr.resolve_jifs(d, inst, rc)
  if rc_expected != None and rc != rc_expected:
    print('Expected RC', rc_expected)
    print('Got RC', rc)
    raise RuntimeError('unexpected _ResolveCounters ')
  if inst_expected != None:
    if inst != inst_expected:
      print('Expected inst:')
      pprint(inst_expected)
      print('Got inst:')
      pprint(inst)
      print(f'(however _ResolveCounters() are equal: {rc})')
      raise RuntimeError('unexpected dict instance has been generated')
  return (rc, inst)



def _test_jif_resolver():
  _t = {
    'a': 1,
    'b': {
      '$jif': ['a', 1],
      'alice': { 'e': 3 }
    }
  }
  _test(_t, JIFResolver._ResolveCounters(1, 0, 0))

  _t = {
    'a': 1,
    'b': {
      '$jif': ['a', 2],
      'alice': { 'e': 3 }
    }
  }
  _test(_t, JIFResolver._ResolveCounters(0, 1, 0))

  _t = {
    'a': 1,
    'b': {
      '$jif': ['a', 2],
      'alice': { 'e': 3 }
    },
    'c': {
      '$jif': ['struct.404', 404],
      'some': 8
    }
  }
  _test(_t, JIFResolver._ResolveCounters(0, 1, 1), {'a': 1, 'c': {'$jif': ['struct.404', 404], 'some': 8}})

  _t = { #Defer
    'a': 1,
    'b': {
      '$jif': ['a', 1],
      'alice': {
        'e': 3,
        'son': {
          'eee': 'xxx',
          '$jif': ['b.alice.e', 3]
        }
      }
    },
    'c': {
      '$jif': ['struct.404', 404],
      'some': 8
    }
  }
  _test(_t, JIFResolver._ResolveCounters(2, 0, 1), {
    'a': 1,
    'b': {
      'alice': {
        'e': 3,
        'son': {
          'eee': 'xxx'
        }
      }
    },
    'c': {
      '$jif': ['struct.404', 404],
      'some': 8
    }
  })

def _test_jif_resolver_more():
  #
  # IMPORTANT CASE
  # This gives us _ResolveCounters(nfoundeq=0, nfoundneq=2, nnotfound=0), e.g.  '$jif': ['b.c', '3'] is FOUND, but NOT EQ. However it's only found when b condition is met
  #
  _t = {
    'a': 1,
    'b': {
      '$jif': ['a', 1010101],
      'c': 3
    },
    'c': {
      '$jif': ['b.c', '3']
    }
  }
  _test(_t, JIFResolver._ResolveCounters(0, 2, 0),
        {'a':1})


# $jif should not reference a node which existence is under another $jif because
# the order of resolving is not guaranteed, -> it would lead to improper output.
# This is shown in _test_jif_resolver_mutual_jifs1. The result is non-empty.
def _test_jif_resolver_orderofresolv():
  _t = {
    'a': {
      '$jif': ['b.c', 5], # (statically True)
      'x': 1
    },
    'b': {
      '$jif': ['a.x', 3], # (statically False)
      'c': 5
    }
  }
  _test(_t, JIFResolver._ResolveCounters(1, 1, 0),
        {'a': {'x': 1}})
  pass

# See this. Mutual again as in _test_jif_resolver_orderofresolv. But now both static values are not equal
def _test_jif_resolver_orderofresolv2():
  _t = {
    'a': {
      '$jif': ['b.c', 4], # was 5, now 4 (e.g. now not EQ)
      'x': 1
    },
    'b': {
      '$jif': ['a.x', 3], # statically False
      'c': 5
    }
  }
  _test(_t, JIFResolver._ResolveCounters(0, 2, 0),
        {})
  pass


def test_jif_resolver(argv):
  _test_jif_resolver()
  _test_jif_resolver_more()
  _test_jif_resolver_orderofresolv()
  _test_jif_resolver_orderofresolv2()


if __name__ == '__main__':
  test_jif_resolver(sys.argv[1:])

