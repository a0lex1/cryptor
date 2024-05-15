import sys, dpath, copy
from enum import Flag, auto
from typing import List


class JPathKeyNotFound(Exception):
  pass

# path specified as: _l = list, _s = string

def jpath_set_l(the_dict, name_parts, value, part_idx):
  _RECURSE = jpath_set_l
  cur_part = name_parts[part_idx]
  if part_idx == len(name_parts) - 1:
    the_dict[cur_part] = value
  else:
    return _RECURSE(the_dict[cur_part], name_parts, value, part_idx+1)

def jpath_set_s(d:dict, path, value):
  return jpath_set_l(d, path.split('.'), value, 0)


class JPathEnumFlag(Flag):
  ENUM_SUBKEYS = auto()
  ENUM_VALUES = auto()

JPATH_ENUM_ALL = JPathEnumFlag.ENUM_SUBKEYS | JPathEnumFlag.ENUM_VALUES

def jpath_enum_l(d:dict, paths:List[List[str]], enum_flag=JPATH_ENUM_ALL, cur_path=None):
  _RECURSE = jpath_enum_l
  if not cur_path:
    cur_path = []
  for key in d.keys():
    value = d[key]
    new_path = cur_path+[key]
    if type(value) == dict:
      if enum_flag & JPathEnumFlag.ENUM_SUBKEYS:
        paths.append(new_path)
      _RECURSE(value, paths, enum_flag, new_path)
    else:
      if enum_flag & JPathEnumFlag.ENUM_VALUES:
        paths.append(new_path)
  return

def jpath_enum_s(d:dict, paths:List[str], enum_flag=JPATH_ENUM_ALL, joinchar='.'):
  lpaths = []
  jpath_enum_l(d, lpaths, enum_flag)
  for lpath in lpaths:
    paths.append(joinchar.join(lpath))

# if path doesn't exist, no action taken
def jpath_delete_l(d:dict, path:List[str], ignore_errors=False):
  if len(path) == 1:
    del_where = d
    del_what = path[0]
  else:
    try:
      parent = jpath_get_l(d, path[:-1])
    except JPathKeyNotFound:
      if not ignore_errors:
        raise #REraise
      return
    del_where = parent
    del_what = path[-1]
  if not del_what in del_where:
    if not ignore_errors:
      raise JPathKeyNotFound('del_what not in del_where at destination node on deletion')
    else:
      return
    pass
  # actually delete child in parent
  del del_where[del_what]
  return

# if path doesn't exist, no action taken
def jpath_delete_s(d:dict, path:str, ignore_errors=False):
  return jpath_delete_l(d, path.split('.'), ignore_errors)

def jpath_get_l(the_dict, name_parts, part_idx=0):
  _RECURSE = jpath_get_l
  cur_part = name_parts[part_idx]
  if not cur_part in the_dict:
    raise JPathKeyNotFound(f'no such key - {cur_part}')
  if part_idx == len(name_parts) - 1:
    return the_dict[cur_part]
  else:
    return _RECURSE(the_dict[cur_part], name_parts, part_idx + 1)

def jpath_get_s(d:dict, path:str, splitchar='.'):
  return jpath_get_l(d, path.split(splitchar), 0)


_test_dict1 ={
  'shit': {
    'a': 1,
    'b': 2
  },
  'x': 10,
  'y': 33,
  'some': {
    'i': 50,
    'f': 'eee',
    'subsome': {
      'g': 15,
      'm': 10
    },
    'n': 20
  }
}

def _test_jpath_set():
  _t = {
    'x': {
      'y': 0,
      'a': 1
    },
    'z': {
    }
  }
  jpath_set_s(_t, 'x.y', 5)
  assert(_t['x']['y'] == 5)

def _test_jpath_get():
  assert( jpath_get_s(_test_dict1, 'x') == 10 )
  assert( jpath_get_s(_test_dict1, 'y') == 33 )
  assert( jpath_get_s(_test_dict1, 'some.f') == 'eee')
  assert( jpath_get_s(_test_dict1, 'some.subsome.m') == 10 )
  assert( jpath_get_s(_test_dict1, 'some.subsome') == {'g': 15, 'm': 10} )
  assert( jpath_get_l(_test_dict1, ['some', 'subsome']) == {'g': 15, 'm': 10} )

def _test_jpath_get_notfound():
  try:
    x = jpath_get_s(_test_dict1, 'shit.ccc')
  except JPathKeyNotFound as e:
    print('OK, EXPECTED JPathException:', e)

def _test_jpath_enum():
  lpaths = []
  jpath_enum_l({}, lpaths, JPathEnumFlag.ENUM_SUBKEYS)
  assert(lpaths == [])

  lpaths = []
  jpath_enum_l({'a': 1}, lpaths, JPathEnumFlag.ENUM_SUBKEYS)
  assert(lpaths == [])

  lpaths = []
  jpath_enum_l(_test_dict1, lpaths, JPathEnumFlag.ENUM_SUBKEYS)
  assert(lpaths == [['shit'], ['some'], ['some', 'subsome']])


def _test_jpath_delete():
  t = copy.deepcopy(_test_dict1)
  jpath_delete_s(t, 'some.subsome')
  print(t)

#delete_longest_first mode enables must-succeed logic
def _jpath_enumdel_test_with(enum_flag, delete_longest_first=False):
  t = copy.deepcopy(_test_dict1)
  paths = []
  jpath_enum_s(t, paths, enum_flag)
  if delete_longest_first:
    # sort and delete from longest to shortest
    spaths = sorted(paths, reverse=True)
    for path in spaths:
      # no ignore-error mode!
      jpath_delete_s(t, path)
  else:
    # simply delete all paths
    for path in paths:
      # WITH ignore-error mode
      jpath_delete_s(t, path, ignore_errors=True)

def _test_jpath_enum_delete_all():
  _jpath_enumdel_test_with(JPathEnumFlag.ENUM_SUBKEYS)
  _jpath_enumdel_test_with(JPathEnumFlag.ENUM_SUBKEYS, True)
  _jpath_enumdel_test_with(JPathEnumFlag.ENUM_VALUES)
  _jpath_enumdel_test_with(JPathEnumFlag.ENUM_VALUES, True)
  _jpath_enumdel_test_with(JPathEnumFlag.ENUM_SUBKEYS|JPathEnumFlag.ENUM_VALUES)
  _jpath_enumdel_test_with(JPathEnumFlag.ENUM_SUBKEYS|JPathEnumFlag.ENUM_VALUES, True)


def test_common_jpath(argv):
  _test_jpath_set()
  _test_jpath_get()
  _test_jpath_get_notfound()
  _test_jpath_enum()
  _test_jpath_delete()
  _test_jpath_enum_delete_all()

if __name__ == '__main__':
  test_common_jpath(sys.argv[1:])

