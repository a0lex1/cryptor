import argparse, re, json, random, os

from pprint import pprint
from dataclasses import dataclass
from typing import List

from c2.infra.cli_config import *

from c2.chains.vardb import VarDB, VF
from c2.chains.calldb import *
from c2.sprayer.test.srcexec import *


# Can be textualized via ChainTextualizer
@dataclass
class ChainItem:
  cid: int = None                  # identifies call entry in db
  repl_vid_list: List[int] = None  # [vid, vid, vid] - identifies  vid(s) of var(s) to replace with

# Yields new chain elements, base class
class ChainGen:
  def __init__(self, calldb:CallDB, vardb:VarDB, allow_upcast=True):
    self._calldb = calldb
    self._vardb = vardb
    self._allow_upcast = allow_upcast
    self._prnfn = None

  # if __init__ was with None(s), you can set it directly
  def set_calldb(self, calldb):
    self._calldb = calldb

  def set_vardb(self, vardb):
    self._vardb = vardb

  def set_prnfn(self, prnfn):
    self._prnfn = prnfn

  # hook me
  def __iter__(self):
    #cids = self._get_new_cids()
    raise NotImplementedError()

  # does cat A inherit cat B ?
  def _a_inherits_b(self, child_cat:str, base_cat:str) -> bool:
    hier = get_type_hierarchy_list(self._calldb.category_tree, child_cat)
    return base_cat in hier

  # comparand -> typover if VAR_TRASH, category otherwise
  def _searchcond(self, nvar, comparand, one_of_flags=VF.VAR_DEFAULT):
    vflag = self._vardb.list_of_varflags()[nvar]
    vcat = self._vardb.list_of_cats()[nvar]
    vtypover = self._vardb.list_of_typeovers()[nvar]
    # first of all, flags must match
    if not vflag & one_of_flags:
      return False
    if vflag & VF.VAR_TRASH:
      assert(vcat == None)
      assert(vtypover != None)
      # compare typeovers
      return comparand == vtypover
    # not-TRASH case, compare categories; if nothing found, try cast categories; otherwise, false
    if comparand == vcat:
      return True
    else:
      if self._allow_upcast:
        return self._a_inherits_b(vcat, comparand)
    return False

  def _fill_callentry(self, callentry, repl_vid_list):
    assert(len(repl_vid_list) == 0)
    vardb = self._vardb
    db_vcats = vardb.list_of_cats()
    db_vflags = vardb.list_of_varflags() # VarFlag DEFAULT TRASH KILLED
    for descr in callentry.descriptors:
      # descr -> direction, category, typeover, paramdict
      # IN/OUT implementation now doesn't need anything - it just works as IN. If we
      # had some modify flag, we'd updated it (because instead of IN, INOUT is also OUT)
      if descr.direction == Direction.IN or descr.direction == Direction.INOUT:
        # pick IN var from cats
        in_idxes = [i for i in range(len(db_vcats)) if self._searchcond(i, descr.category)]
        PIIIIIIIIIIIIIIIICKED_vid = in_idxes[0]
        repl_vid_list.append(PIIIIIIIIIIIIIIIICKED_vid)
        pass
      elif descr.direction == Direction.OUT:
        # add new var
        new_vid = vardb.add_var(VF.VAR_DEFAULT, descr.category, descr.typeover)
        repl_vid_list.append(new_vid)
        pass
      elif descr.direction == Direction.UNUSED:
        # find reusable trash var or create new
        trashvar_idxes = [i for i in range(len(db_vflags)) if self._searchcond(i, descr.typeover, VF.VAR_TRASH)]
        if 0 == len(trashvar_idxes):
          vid = vardb.add_var(VF.VAR_TRASH, descr.category, descr.typeover)
        else:
          PIPIPIPIPIPIVID = trashvar_idxes[0]
          vid =  PIPIPIPIPIPIVID
        repl_vid_list.append(vid)
        pass
      else:
        raise RuntimeError()
      pass
    return


class ChainGenDFSOrder(Enum):
  DEFAULT = auto()
  REVERSED = auto()

# Iterates all, for testing. Use with all_cids_used_in_chain() to ensure.
class ChainGenDFS(ChainGen):
  def __init__(self, calldb, vardb, order:ChainGenDFSOrder):
    super().__init__(calldb, vardb)
    self.order = order
    self._cid2stepid = {}
    self._cur_stepid = 0
    self._visited_cids = {} # { 1: None, 2: None, }

  def __iter__(self):
    cids = self._get_new_cids()
    assert(self._cur_stepid == 0)
    for cid in cids:
      self._cid2stepid[cid] = self._cur_stepid # 0
    yield from self._do_iteration(cids)

  def _do_iteration(self, cids, lev=0):
    _RECURSE = self._do_iteration
    calldb = self._calldb
    cid2stepid = self._cid2stepid
    prn = self._prnfn
    prn(f'{" "*lev}cur cid list: {cids}')
    prn(f'{" "*lev}cid2stepid  : {self._cid2stepid}')
    for cid in cids:
      # cid still may be added from child step, check it here
      assert(not cid in self._visited_cids)
      # OK, we have a good candidate. Generate new chain item. Add new vars (if we have outs/inouts) and yield it.
      callentry = calldb.entries[cid]
      # callentry.text_line    ->  <unused:Dword> = SomeCall(<in:Path>, 0, &<out:FilePath:char[260]>, 0)
      # callentry.descriptors  ->  {UNUSED      }            {IN      }     {OUT          typeover }
      # callentry.positions    ->  (0, 11)                   {, }           (, )
      # repl_vid_list =        ->  [ vid,                    vid,           vid ]
      repl_vid_list = []
      self._fill_callentry(callentry, repl_vid_list)
      chainentry = ChainItem(cid, repl_vid_list)

      prn(f'{" "*lev}yielding cid {cid}')
      self._visited_cids[cid] = None
      yield chainentry

      # if list changed, recurse into new list
      new_cids = self._get_new_cids()
      if len(new_cids) == 0:
        prn(f'{" " * lev}no new cids, continuing cur list')
      else:
        prn(f'{" "*lev}new cids found after yield: {new_cids}')
        self._cur_stepid += 1
        for new_cid in new_cids:
          self._cid2stepid[new_cid] = self._cur_stepid

        yield from _RECURSE(new_cids, lev+1)
      pass
    pass

  def _get_new_cids(self):
    calldb = self._calldb
    vardb = self._vardb
    cids = []
    for cid in range(len(calldb.entries)):
      if cid in self._cid2stepid:
        continue
      callentry = calldb.entries[cid]
      ok = True
      for descr in callentry.descriptors:
        if descr.direction == Direction.IN or descr.direction == Direction.INOUT:
          #if not descr.category in vardb.list_of_cats():
          _idxes = [i for i in range(len(vardb.list_of_cats())) if self._searchcond(i, descr.category)]
          if 0 == len(_idxes):
            ok = False
            break
        pass
      if not ok:
        continue
      cids.append(cid)
      pass
    if self.order == ChainGenDFSOrder.DEFAULT:
      pass
    elif self.order == ChainGenDFSOrder.REVERSED:
      cids = list(reversed(cids))
    else:
      raise RuntimeError()

    return cids


class ChainGenRandom(ChainGen):
  def __init__(self, calldb, vardb, max_cid_use_count:int, rng):
    super().__init__(calldb, vardb)
    self._max_cid_use_count = max_cid_use_count
    self._rng = rng
    self._cid_use_counts = {}
    self._cid_stages = {}
    self._cur_stage = 0

  def _grab_portion(self):
    prn = self._prnfn
    calldb = self._calldb
    vardb = self._vardb
    cids = []
    for cid in range(len(calldb.entries)):
      if cid in self._cid_stages:
        if self._cid_stages[cid] < self._cur_stage-1:
          continue
      callentry = calldb.entries[cid]
      ok = True
      for descr in callentry.descriptors:
        if descr.direction == Direction.IN or descr.direction == Direction.INOUT:
          #if not descr.category in self._vardb.list_of_cats():
          _idxes = [i for i in range(len(vardb.list_of_cats())) if self._searchcond(i, descr.category)]
          if 0 == len(_idxes):
            ok = False
            break
        pass
      if not ok:
        continue
      cids.append(cid)
      pass
    if len(cids):
      for cid in cids:
        # part of them are from previous step, e.g. already has an associated stage
        if not cid in self._cid_stages:
          self._cid_stages[cid] = self._cur_stage
      self._cur_stage += 1
      prn(f'grabbed portion ({len(cids)}), now stage {self._cur_stage}, cid_stages-> {self._cid_stages}')
    else:
      print(f'grabbed NO portion')
    return cids

  def __iter__(self):
    calldb = self._calldb
    prn = self._prnfn
    rng = self._rng
    while True:
      cids = self._grab_portion()
      if len(cids) == 0:
        break  # is it right?
      _i = rng.randint(0, len(cids)-1)
      prn(f'picked cid {_i} (pick was from 0 to {len(cids)-1})')
      cid = cids[_i]
      callentry = calldb.entries[cid]

      # make call
      repl_vid_list = []
      self._fill_callentry(callentry, repl_vid_list)
      chainentry = ChainItem(cid, repl_vid_list)

      if not cid in self._cid_use_counts:
        self._cid_use_counts[cid] = 0
      if self._cid_use_counts[cid] == self._max_cid_use_count:
        print('max cid use count reached, break!')
        break
      self._cid_use_counts[cid] += 1
      prn(f'yielding cid {cid} (use count now {self._cid_use_counts[cid]})')

      yield chainentry

      pass
    return


def all_cids_used_in_chain(calldb, chainitems:List[ChainItem]) -> bool:
  # make list of used cids, unique it (remove duplicates), sort and compare with [0..num db cids]
  num_db_cids = len(calldb.entries)
  item_cids = list(map(lambda item: item.cid, chainitems))
  item_cids_uniq = list(set(item_cids))
  # python seems to sort it without sorted(), but for sure
  item_cids_uniq_sorted = sorted(item_cids_uniq)
  print(list(item_cids), item_cids_uniq, item_cids_uniq_sorted)
  return item_cids_uniq_sorted == [i for i in range(num_db_cids)]


def make_chain_var_names(calldb, vardb) -> List[str]:
  ret = []
  cthelp = CategoryTreeHelper(calldb.category_tree, calldb.category_deftypes)
  cnts = {}
  for i in range(len(vardb.list_of_cats())):
    cat, tover = vardb.get_var_tuple(i)
    if not cat in cnts:
      cnts[cat] = 0 # may be cnts[None] = 0
    if cat != None:
      title = cat
    else:
      assert(tover != None)
      title = 'unused'
    varname = f'v_{title}{cnts[cat]}'
    ret.append(varname)
    cnts[cat] += 1
  assert(len(ret) == len(vardb.list_of_cats()))
  return ret


def make_chain_vars_decl(calldb, vardb, varnames, tabs=0, tabchar='  ') -> str:
  assert(len(vardb.list_of_cats()) == len(varnames))
  ret = ''
  cthelp = CategoryTreeHelper(calldb.category_tree, calldb.category_deftypes)
  for i in range(len(vardb.list_of_cats())):
    cat, tover = vardb.get_var_tuple(i)
    varname = varnames[i]
    c_typ = None
    # find C type to declare as
    if tover:
      c_typ = tover
    else:
      if cat:
        c_typ = cthelp.get_deftype_of_base(cat)
        assert(c_typ and len(c_typ) >= 1)
      else:
        raise RuntimeError('Both CAT and tover is None')
      pass
    # declare variable
    ret += f'{tabchar*tabs}{c_typ} {varname};\n'
    pass
  return ret


class ChainTextualizer:
  def __init__(self, calldb, vardb, varnames):
    self.calldb = calldb
    self.vardb = vardb
    self.varnames = varnames

  def tex_one(self, chainitem:ChainItem) -> str:
    e = self.calldb.entries[chainitem.cid]
    repls = [self.varnames[vid] for vid in chainitem.repl_vid_list]
    text = string_repl_positions(e.text_line, e.positions, repls)
    #chainitem._repl_vid_list
    #self.vardb.list_(chainitem._cid)
    return text





