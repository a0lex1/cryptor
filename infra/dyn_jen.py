import sys
from typing import List
from pprint import pprint

from c2.infra.jif_resolver import JIFResolver
from c2.infra.jen import *

from c2.common.delete_nodes_containing_keys import *


# class DynJen
#
# A generator, extended Jen; supports $jif (multistep processing), black jack and hoes.
# Doesn't know the total number of iterations, in opposite to Jen
# Ignores non-existing keys in |order_all|
#
# |order_all| #OrderNotMet in some cases (where stage resolves fields and Jen-iterated, therefore, the used order can't be injected on further stages)
# So the most dependent fields change most frequently, which is what we commonly need.
#
# ALSO Read JIFResolver comments: #AvoidDynamicJifs
#
# #PossibleImprovements reverse_values can be specified for each path.to.node if we'll need more precise control over the parts of the config
#

class DynJen:
  def __init__(self, d:dict, order_all:List[str], itergen_class=IterationGeneratorPositional,
               reverse_values=False):
    self.d = d
    self.order_all = order_all
    self.itergen_class = itergen_class
    self.reverse_values = reverse_values
    self._prnfn = lambda msg: None

  def __iter__(self):
    yield from self._iter(self.d)

  def _print_if(self, m):
    if self._prnfn:
      self._prnfn(m)

  def _iter(self, jen_dict):
    _RECURSE = self._iter
    _prn = self._print_if
    _prn(f'jen_dict ->\n{jen_dict}\n')
    jen = Jen(jen_dict, self.order_all, keys_to_ignore_node={'$jif'}, ignore_nonexisting_order_key=True,
              itergen_class=self.itergen_class,
              reverse_values=self.reverse_values)
    jen.build()
    num_iters = jen.number_of_iterations()
    for niter in range(num_iters):

      jen_inst = jen.iteration(niter)
      _prn(f'jen.iteration({niter}) ->\n{jen_inst}\n')

      jen_inst2 = {}
      resolve_counters = JIFResolver._ResolveCounters()
      jifresolver = JIFResolver()
      jifresolver.resolve_jifs(jen_inst, jen_inst2, resolve_counters)

      nfoundTotal = resolve_counters.nfoundeq + resolve_counters.nfoundneq
      if nfoundTotal > 0:

        _prn(f'need more stages resolving $jif, cur jen ->\n{jen_inst2}\n(nfoundTotal={nfoundTotal}, resolve_counters -> {resolve_counters})\n')

        # need to process more dependent $jifs
        yield from _RECURSE(jen_inst2)

      else:
        # done resolving $jifs
        assert(nfoundTotal == 0)
        if resolve_counters.nnotfound > 0:
          # nothing new resolved, but something still not found
          _prn('cant resolve some $jif, clearing .....')
          delete_nodes_containing_keys(jen_inst2, ['$jif'])

        # done resolving, success, YIELD it
        # do NOT set keys_to_exclude_node, but eliminate rest $jif before yielding to user
        jen2 = Jen(jen_inst2, self.order_all, ignore_nonexisting_order_key=True,
                   itergen_class=self.itergen_class, reverse_values=self.reverse_values)
        jen2.build()

        for nfin in range(jen2.number_of_iterations()):

          final_inst = jen2.iteration(nfin)

          _prn(f'all-resolved, yielding final_inst #{nfin} ->\n{final_inst}\n')

          yield final_inst

          _prn('\n')
      pass
    return


def _dynjen_test_expect(d:dict, order: List[str], jens_expected:List[dict], title='', prnfn=None):
  dj = DynJen(d, order)
  dj._prnfn = prnfn
  jens = []
  n = 0
  for jen in dj:
    print(f'DynJen <{title}> INSTANCE#{n}: {jen}')
    jens.append(jen)
    n += 1
  if jens_expected and jens != jens_expected:
    print('Expected jens:')
    print(jens_expected)
    print('Got jens:')
    print(jens)
    raise RuntimeError('unexpected jens')
  print()
  return jens


def _test_dynjen():
  # Need:
  # + single $jif
  # + several $jif
  # + two dependent $jif
  # + several dependent $jif
  #   samename
  #   refs

  _do = True
  #_do = False and False and False and False and False and False and False and False

  if _do:
    _testjen_single1 = {
      'a': ['$jcn', '1', '2', '3'],
      'b': {
        '$jif': ['a', 2],
        'c': ['$jcs', 'hi', 'bitch']
      }
    }
    _dynjen_test_expect(_testjen_single1, [], [{'a': 1}, {'a': 2, 'b': {'c': 'hi'}}, {'a': 2, 'b': {'c': 'bitch'}}, {'a': 3}])


  if _do:
    # 1 depends on 2 that depends on 3 - this case requires #Defer
    _testjen_defer = {
      'a': ['$jcn', '1', '2', '3'],
      'b': {
        '$jif': ['a', 2],
        'c': ['$jcs', 'hi', 'bitch'],
        'd': {
          '$jif': ['b.c', 'bitch'],
          'foobar': 'installed'
        }
      }
    }
    _dynjen_test_expect(_testjen_defer, [] , [{'a': 1}, {'a': 2, 'b': {'c': 'hi'}}, {'a': 2, 'b': {'c': 'bitch', 'd': {'foobar': 'installed'}}}, {'a': 3}])

  if _do:
    # like prev, but depend from another block
    _testjen_defer2 = {
      'a': ['$jcn', '1', '2', '3'],
      'b': {
        '$jif': ['a', 2],
        'c': ['$jcs', 'hi', 'bitch'],
        'd': {
          '$jif': ['b.c', 'bitch'],
          'is_sucks': ['$jcb', 'true', 'false']
        }
      },
      'f': {
        'g': {
          '$jif': ['b.d.is_sucks', True],
          'm': 4
        }
      }
    }
    x=_dynjen_test_expect(_testjen_defer2, [] , [{'a': 1, 'f': {}}, {'a': 2, 'b': {'c': 'hi'}, 'f': {}}, {'a': 2, 'b': {'c': 'bitch', 'd': {'is_sucks': True}}, 'f': {'g': {'m': 4}}}, {'a': 2, 'b': {'c': 'bitch', 'd': {'is_sucks': False}}, 'f': {}}, {'a': 3, 'f': {}}],
                          )
    pprint(x)

  return


def _test_dynjen_order():
  _do = True
  #_do = False and False and False and False and False and False and False and False

  if _do:
    _t = {
      'a': 1,
      'b': ['$jcn', '10', '20', '30'],
      'c': {
        '$jif': ['b', 20],
        'd': ['$jcn', '55', '66'],
        'e': ['$jcn', '888', '999'],
      },
      'z': {
        'y': {
          'x1': ['$jcs', 'test'],
          'x2': ['$jcs', 'h', 'e', 'l', 'l', 'o']
        }
      }

    }
    # non-default order
    order = ['z.y.x2', 'c.e', 'b']
    x=_dynjen_test_expect(_t, order , None,
                          )
    print('#OrderNotMet #OrderNotMet  #OrderNotMet ')
    pprint(x, width=200)
    print('/ #OrderNotMet #OrderNotMet  #OrderNotMet ')


def _eqtest(_t):
  dj = DynJen(_t, [])
  jen = Jen(_t, []).build()
  djinsts = [inst for inst in dj]
  jinsts = [jen.iteration(i) for i in range(jen.number_of_iterations())]
  if djinsts != jinsts:
    print('DynJen returned', djinsts)
    print('Jen returned:', jinsts)
    raise RuntimeError('DynJen and Jen returned different documents')

def _test_dynjen_jen_equality():
  _eqtest({})
  _eqtest({
    'a': 1
  })
  _eqtest({
    'b': ['$jcn', '10', '20', '30']
  })
  _eqtest({
    'b': ['$jcn', '10', '20', '30'],
    'm': ['$jcs', 'mmm']
  })
  _eqtest({
    'a': 1,
    'b': ['$jcn', '10', '20', '30']
  })
  _eqtest({
    'a': 1,
    'b': ['$jcn', '10', '20', '30'],
    'c': {
      'd': ['$jcn', '55', '66'],
      'e': ['$jcn', '888', '999'],
    }
  })
  _eqtest({
    'a': 1,
    'b': ['$jcn', '10', '20', '30'],
    'c': {
      'd': ['$jcn', '55', '66'],
      'e': ['$jcn', '888', '999'],
    },
    'z': {
      'y': {
        'x1': ['$jcs', 'test'],
        'x2': ['$jcs', 'h', 'e', 'l', 'l', 'o']
      }
    }
  })


def test_dyn_jen(argv):
  _test_dynjen()
  _test_dynjen_order()
  _test_dynjen_jen_equality()


if __name__ == '__main__':
  test_dyn_jen(sys.argv[1:])






