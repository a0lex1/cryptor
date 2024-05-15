from typing import Any, Callable, List
from dataclasses import dataclass

from c2.sprayer.ccode.var import Var, VT


# Instantiating the item-level shape gives us vls-like object whose cells can contain value of any type
VlsShapeInstance = List[List[List[Any]]]

# Item-level shape for vls. Stores list of list of listsizes.
# class Shape doesn't encapsulate the form of shape; if it's gonna be something different than vls, the shape will explicitly change
@dataclass
class VlsShape:
  lists: List[List[int]] = None

  def instantiate_with_fn(self, fn_getval:Callable[[int, int, int], Any]) -> VlsShapeInstance:
    vls_dup = []
    for nlist in range(len(self.lists)):
      lst = self.lists[nlist]
      another_lst = []
      for nvar in range(len(lst)):
        sz = lst[nvar]
        another_lst.append([fn_getval(nlist, nvar, _nvalue) for _nvalue in range(sz)])
      vls_dup.append(another_lst)
    return vls_dup

  def instantiate_with_static_value(self, value_to_fill) -> VlsShapeInstance:
    return self.instantiate_with_fn(lambda nvl, nvar, nvalue: value_to_fill)


def vls_shape_from_vls(vls:List[List[Var]]) -> VlsShape:
  ret_shape = VlsShape()
  ret_shape.lists = []
  for nvl in range(len(vls)):
    vl = vls[nvl]
    vl_dup = []
    for nvar in range(len(vl)):
      v = vl[nvar]
      vl_dup.append(len(v.values))
    ret_shape.lists.append(vl_dup)
  return ret_shape


### TEST CODE ###

def _test_from_vls_instantiate(vls, fn_getval, expected_shapeinst:VlsShapeInstance):
  shape = vls_shape_from_vls(vls)
  shapeinst = shape.instantiate_with_fn(fn_getval)
  if expected_shapeinst != None:
    if type(shapeinst) != type(expected_shapeinst):
      raise RuntimeError()
    if shapeinst != expected_shapeinst:
      print('*****')
      print('Expected instance:')
      print(expected_shapeinst)
      print('Got instance:')
      print(shapeinst)
      raise RuntimeError('instances don\'t match, see log')

def _test_copyfn():
  VlsShape(Todo)

def test_vls_shape():
  _test_from_vls_instantiate([], lambda nvl, nvar, nval: 'never_used', []) # empty lists
  _test_from_vls_instantiate([ [], [], [], ], # non-empty lists of empty lists
                             lambda nvl, nvar, nval: 'never used',
                             [ [], [], [] ])
  # non-empty lists of non-empty lists
  _test_from_vls_instantiate([[Var(VT.i32, [1, 2, 3]),Var(VT.u8, [3, 4, 5])],
                              [Var(VT.u16, [9, 3]), Var(VT.i16, [33, 11, 23, 31])]
                              ],
                             lambda nvl, nvar, nval: 1,
                             [
                               [[1, 1, 1], [1, 1, 1]], [[1, 1], [1, 1, 1, 1]]
                             ])
  _test_from_vls_instantiate([[Var(VT.i32, [1, 2, 3]),Var(VT.u8, [3, 4, 5])],
                              [Var(VT.u16, [9, 3]), Var(VT.i16, [33, 11, 23, 31])]
                              ],
                             lambda nvl, nvar, nval: (nvl, nvar, nval), # tup tuples and check if they're at right places
                             [
                               [[(0, 0, 0), (0, 0, 1), (0, 0, 2)], [(0, 1, 0), (0, 1, 1), (0, 1, 2)]], [[(1, 0, 0), (1, 0, 1)], [(1, 1, 0), (1, 1, 1), (1, 1, 2), (1, 1, 3)]]
                             ])

if __name__ == '__main__':
  test_vls_shape()


