import sys
from pprint import pprint
from indexed import IndexedOrderedDict

from c2.common.test_schemas import *


# get textualized paths to props
def get_schema_props(root: dict,
                     collected: IndexedOrderedDict, # output {'name': (typ), ...}}
                     splitter='.', path=None,
                     prefix_to_add=None):
  _RECURSE = get_schema_props
  assert(type(collected) == IndexedOrderedDict)
  if path == None:
    path = []
  assert(root['type'] == 'object')
  props = root['properties']
  for propname in props.keys():
    prop = props[propname]
    if not 'type' in prop:
      raise RuntimeError('expecting \'type\' key; bad json schema')
    typ = prop['type']
    fullname = splitter.join(path+[propname])
    if prefix_to_add:
      fullname = prefix_to_add + fullname
    if typ == 'object':
      _RECURSE(prop, collected, splitter, path+[propname], prefix_to_add)
    elif typ == 'string':
      collected[fullname] = typ
    elif typ == 'number':
      collected[fullname] = typ
    elif typ == 'array':
      collected[fullname] = typ
    elif typ == 'boolean':
      collected[fullname] = typ
    else:
      raise RuntimeError(f'Dont know how to handle node of type {prop["type"]}')


def test_common_get_schema_props(argv):
  collected = IndexedOrderedDict()
  get_schema_props(test_schema_1, collected, '_')
  pprint(collected)
  assert(collected == IndexedOrderedDict([('somelistA', 'array'), ('somelistB', 'array'), ('someintA', 'number'), ('someintB', 'number'), ('someboolA', 'boolean'), ('someboolB', 'boolean'), ('someboolC', 'boolean'), ('sub_sex', 'string'), ('sub_age', 'number'), ('sub_super', 'number'), ('sub_mega', 'number')]))



if __name__ == '__main__':
  test_common_get_schema_props(sys.argv[1:])

