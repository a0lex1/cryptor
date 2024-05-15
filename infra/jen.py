import sys, json, os
from typing import List, Set
from pprint import pprint

from c2.common.iteration_generator import *
from c2.common.jpath import *

# TODO: choices (type: string, enum: [seq, random, lalala, ...])

# arrays not supported
jen_type2typcod = {'string': 's', 'number': 'n', 'boolean': 'b'}


# does not validate instances (class Jen would need schema to do that)
# Note: |order| may make no effect for some |itergen_class|es, for example, IterationGeneratorDiagonal
class Jen:
  # order -> ['fieldname1', ...]
  # keys_to_exclude_node has NO effect in `not self._itergen` case (1-iter static ) - you must handle it yourself
  def __init__(self,
               d:dict = None,
               order:List[str] = None,
               keys_to_exclude_node:Set[str] = None,
               keys_to_ignore_node:Set[str] = None,
               ignore_nonexisting_order_key = False,
               itergen_class=IterationGeneratorPositional,
               reverse_values=False
               ):
    assert(order != None)
    self.d = d
    self.order = order
    self._poses = None
    self._used_nodes = None
    self._path2node_tups = []
    self._typcods4paths = {}
    if keys_to_exclude_node == None:
      keys_to_exclude_node = []
    self.keys_to_exclude_node = keys_to_exclude_node
    if keys_to_ignore_node == None:
      keys_to_ignore_node = []
    self.keys_to_ignore_node = keys_to_ignore_node
    self.ignore_nonexisting_order_key = ignore_nonexisting_order_key
    self.itergen_class = itergen_class
    self.reverse_values = reverse_values
    self._itergen = None
    self._build_done = False

  # you can do:  for inst in Jen(d, []).build():
  def build(self):
    assert(not self._build_done)
    self._build(self.d)
    self._reorder(self.order)
    self._mk_itergen()
    self._build_done = True
    return self

  def number_of_iterations(self):
    assert(self._build_done)
    if not self._itergen:
      return 1
    return self._itergen.number_of_iterations()
    
  def iteration(self, N):
    assert(self._build_done)
    if not self._itergen:
      return self.d

    self._poses = self._itergen.iteration(N)

    self._used_nodes = []
    new_dict = {}
    self._copy_dict(self.d, new_dict)

    assert(len(self._used_nodes) == len(self._path2node_tups))

    return new_dict

  # xxx because searches either in keys_to_exclude_node or keys_to_ignore_node (|xxx_set|)
  def _does_node_contain_key_to_xxx(self, node:dict, xxx_set:Set[str]):
    for kte in xxx_set:
      if kte in node.keys():
        return True
    return False

  def _copy_dict(self, copy_from, copy_to, cur_path=None):
    _RECURSE = self._copy_dict
    if cur_path == None:
      cur_path = []
    paths = list(map(lambda x: x[0], self._path2node_tups))
    for k in copy_from.keys():
      v = copy_from[k]
      cur_path_k = cur_path + [k]
      if type(v) == dict:
        # recursive enter
        if self._does_node_contain_key_to_xxx(v, self.keys_to_exclude_node):
          pass
        else:
          copy_to[k] = {}
          _RECURSE(v, copy_to[k], cur_path_k)
      else:
        cur_path_k_str = '.'.join(cur_path_k)
        if cur_path_k_str in paths:
          # substitute iteration data
          ordindex = paths.index(cur_path_k_str)
          listidx = self._poses[ordindex]
          listidx += 1 # skip '$jcX'

          if self.reverse_values:
            #
            # reverse the order of the values
            # $jcX A B C
            # 0    1 2 3
            # len()=4
            listidx = len(v) - listidx          

          # convert to type corresponding to typcod
          subsval = None
          typcod = self._typcods4paths[cur_path_k_str]
          if typcod == 's':
            subsval = v[listidx] # simply copy, no convert
          elif typcod == 'n':
            subsval = int(v[listidx])
          elif typcod == 'b':
            if v[listidx] == 'true':
              subsval = True
            elif v[listidx] == 'false':
              subsval = False
            else:
              raise RuntimeError()
          else:
            raise RuntimeError()

          # substitute
          copy_to[k] = subsval

          self._used_nodes.append(v)
        else:
          # default copy
          copy_to[k] = v
        pass
      pass
    return

  # checks + returns typcod or None
  def _is_jc_list(node):
    jcs = [f'$jc{tc}' for tc in jen_type2typcod.values()]  # ['$jcb', '$jcs', ...]
    if type(node) == list and len(node) and node[0] in jcs:
      return node[0][3] # get 3'rd char which is guaranteed to be the typcod char
    return None

  def _build(self, root:dict, cur_path=None):
    _RECURSE = self._build
    if cur_path == None:
      cur_path = []
    for k in root.keys():
      v = root[k]
      cur_path_k = cur_path + [k]
      if type(v) == dict:
        if self._does_node_contain_key_to_xxx(v, self.keys_to_exclude_node):
          pass
        else:
          _RECURSE(v, cur_path_k)
      else:
        if self._does_node_contain_key_to_xxx(root, self.keys_to_ignore_node):
          pass
        else:
          typcod = Jen._is_jc_list(v)
          if typcod != None:
            self._validate_jc_list(v)
            # collect ref to this jc list
            _pathstr = '.'.join(cur_path_k)
            self._path2node_tups.append( (_pathstr, v) )
            self._typcods4paths[_pathstr] = typcod
        pass
      pass
    return
    
  # order -> ['field5', 'field2',]
  def _reorder(self, order:list):
    path2node_tups = self._path2node_tups
    namelist = list(map(lambda x: x[0], path2node_tups))
    for column in reversed(order):
      if not column in namelist:
        # key might be eliminated or didn't even exist
        if self.ignore_nonexisting_order_key:
          continue
        else:
          raise RuntimeError('order list contains key that is not in doc')
      colidx = namelist.index(column)
      val_was = path2node_tups[colidx]
      del path2node_tups[colidx]
      path2node_tups.insert(0, val_was)
      # do rearrange in namelist too
      val_was = namelist[colidx]
      del namelist[colidx]
      namelist.insert(0, val_was)

  def _mk_itergen(self):
    ranges = [len(self._path2node_tups[i][1])-1 for i in range(len(self._path2node_tups))]
    if len(ranges):
      self._itergen = self.itergen_class(ranges)
    else:
      self._itergen = None # indicate we must return single copy

  def _validate_jc_list(self, jc_list):
    for elem in jc_list:
      t = type(elem)
      if t != str:
        raise RuntimeError(f'$jcX elements must be strings, not {t}')


def jen_value_to_str(v):
  if type(v) == bool:
    return {True: 'true', False: 'false'}[v]
  elif type(v) == str:
    return v
  elif type(v) == int:
    return str(v)
  else:
    raise RuntimeError('unknown type(v)')



