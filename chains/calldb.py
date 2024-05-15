import sys, json, random

from enum import Enum, auto, Flag
from dataclasses import dataclass
from typing import List, Tuple

from c2.common.string_repl_positions import *
from c2.common.get_all_keys import *
from c2.common.dict_keychar_expander import *
from c2.chains.parse_descrip import get_descrips
from c2.base.dynconfig import DynconfigWithProperties

class Direction(Enum):
  IN = auto()
  OUT = auto()
  INOUT = auto()
  UNUSED = auto()

# <direction:category[:typeover][,k=v,...]>
@dataclass
class Descriptor:
  direction: Direction = None
  category: str = None   # example: FilePath
  typeover: str = None   # example: char[260]
  paramdict: dict = None  # example: dealloc=,slot=,unused=


# DB call entry
@dataclass
class CallDBEntry:
  text_line: str = None
  descriptors: List[Descriptor] = None
  positions: List[Tuple[int, int]] = None


# DB Model
@dataclass
class CallDB:
  entries: List[CallDBEntry] = None
  entry_infos: List = None
  group_infos: List = None
  category_tree: dict = None
  category_deftypes: dict = None

def collect_group_info(calldb:CallDB, callgroup_whitelist=None,
                       includes:List=None,
                       libs:List=None):
  for group_info in calldb.group_infos:
    if callgroup_whitelist:
      if not group_info['name'] in callgroup_whitelist:
        continue
    if includes != None:
      includes += group_info['includes']
    if libs != None:
      libs += group_info['libs']
    pass
  pass


def shuffle_db_entry_order(calldb, seed:int):
  # Hack: shuffle all lists with same seed
  for the_list in [calldb.entries, calldb.entry_infos]:
    rng = random.Random(seed)
    rng.shuffle(the_list)

# get_type_hierarchy_list(calldb.category_tree, 'EventHandle', lst); lst -> ['Handle', 'WaitableHandle', 'EventHandle]
def _get_type_hierarchy_list(cat_tree, subj_cat, out_list):
  _RECURSE = _get_type_hierarchy_list
  for key in cat_tree.keys():
    value = cat_tree[key]
    if type(value) != dict:
      raise RuntimeError('Type hierarchy must be constructed only from dicts, no values allowed')
    #self._prnfn(f'checking {out_list + [key]}, value = {value}')
    out_list += [key]
    if key == subj_cat:
      # found. the result is in out_list
      return 1
    r = _RECURSE(value, subj_cat, out_list)
    if 1 == r:
      # quit iterating keys
      break
    out_list.pop()  # we were adding cur key, remove it
  return

def get_type_hierarchy_list(cat_tree, subj_cat):
  out_list = []
  _get_type_hierarchy_list(cat_tree, subj_cat, out_list)
  return out_list


class CallDBValidator:
  def __init__(self, calldb:CallDB, prnfn=None):
    if prnfn == None:
      prnfn = lambda s: None
    self._prnfn = prnfn
    self.calldb = calldb

  def validate(self):
    db = self.calldb
    assert(len(db.entries) == len(db.entry_infos))
    all_cats = []

    _msghdr = lambda: f'[Group#{gid} {grpname}, cid {cid}, ndesc {ndesc}] '

    num_entries = len(db.entries)

    # [[Verify no bad categories in entries]]
    get_all_keys(db.category_tree, all_cats)
    for cid in range(num_entries):
      e = db.entries[cid]
      gid = db.entry_infos[cid]['group']
      grpname = db.group_infos[gid]['name']
      for ndesc in range(len(e.descriptors)):

        d = e.descriptors[ndesc]
        assert(d.category != '')
        if d.category != None:
          # unuseds can't have categories
          if d.direction == Direction.UNUSED:
            raise RuntimeError(_msghdr()+f'Descriptors with direction=UNUSED can\'t have categories; only typeovers')
          if not d.category in all_cats:
            raise RuntimeError(_msghdr()+f'Unknown category - {d.category}')
        else:
          # d.category is None, this case is ok only for UNUSED direction
          if d.direction != Direction.UNUSED:
            raise RuntimeError(_msghdr()+f'Empty categories allowed only for UNUSED dir, but dir now is {d.direction}')
          pass
      # add descrs for cid dumped
      pass
      # add cids dumped

    # [[Verify OUT descrs has typeovers if their categories don't have deftypes]]
    for cid in range(num_entries):
      e = db.entries[cid]
      for d in e.descriptors:
        if d.direction != Direction.OUT:
          # we want to check only OUTs
          continue
        assert(d.category != '')
        assert(d.typeover != '')
        if d.category == None:
          if d.typeover == None:
            raise RuntimeError(_msghdr()+f'Both category and typeover is empty')
          else:
            continue
        type_hierarchy = get_type_hierarchy_list(db.category_tree, d.category)
        #assert(type_hierarchy[-1] == d.category) #no, it can be derived
        deftype_found = False
        for typ in type_hierarchy:
          if typ in db.category_deftypes:
            deftype_found = True
            break
        if not deftype_found:
          # typeover must be present
          assert(d.typeover != '')
          if d.typeover == None:
            raise RuntimeError(_msghdr()+f'No types in hierarchy present, need typeover, but it\'s None')
        pass
      pass

    # [[Verify category_deftypes don't have keys that are not known categories]]
    for cat_name in db.category_deftypes.keys():
      #deftype = db.category_deftypes[cat]
      self._prnfn('------- '+cat_name)
      if not self._is_known_category(cat_name):
        raise RuntimeError(_msghdr()+f'Unknown category in category_deftypes - {cat_name}')

    # [[Verify inouts don't have typeovers (var is already declared, we can't redeclare)]]
    for cid in range(num_entries):
      e = db.entries[cid]
      for d in e.descriptors:
        if d.direction == Direction.INOUT:
          assert(d.typeover != '')
          if d.typeover != None:
            raise RuntimeError(_msghdr()+f'Can\'t have typeover in INOUT')
    return

  def _is_known_category(self, cat_name):
    hier = get_type_hierarchy_list(self.calldb.category_tree, cat_name)
    return len(hier) != 0


class CallDBPrinter:
  def __init__(self, calldb, test_substitution=False):
    self.calldb = calldb
    self.test_substitution = test_substitution

  def print_all(self, fout):
    self.print_banner(fout)
    self.print_entry_table(True, fout)
    self.print_group_infos(fout)
    self.print_category_tree(fout)
    self.print_category_deftypes(fout)

  def print_banner(self, fout):
    calldb = self.calldb
    fout.write(f'{len(calldb.entries)} call entries:\n')

  def print_entry_table(self, with_header, fout):
    calldb = self.calldb
    if with_header:
      fout.write('CID\tGID\tGRPNAME\tINs\tINOUTs\tOUTs\tUNUSEDs\tTEXT_LINE\n')
      for cid in range(len(calldb.entries)):
        e = calldb.entries[cid]
        gid = calldb.entry_infos[cid]['group']
        descr_dirs = list( map(lambda x: x.direction, e.descriptors) )
        num_ins, num_inouts, num_outs, num_unuseds =\
          descr_dirs.count(Direction.IN), descr_dirs.count(Direction.INOUT), descr_dirs.count(Direction.OUT), descr_dirs.count(Direction.UNUSED)
        groupname = calldb.group_infos[gid]['name']
        text = e.text_line
        if self.test_substitution:
          repls = []
          for d in e.descriptors:
            dirlow = d.direction.name.lower()
            repls.append(f'v_{dirlow}_{d.category}_{d.typeover}_{d.paramdict}')
          text = string_repl_positions(text, e.positions, repls)
        fout.write(f'{cid}\t{gid}\t{groupname}\t{num_ins}\t{num_inouts}\t{num_outs}\t{num_unuseds}\t{text}\n')

  def print_group_infos(self, fout):
    calldb = self.calldb
    fout.write(f'Group infos ({len(calldb.group_infos)} groups):\n')
    for gid in range(len(calldb.group_infos)):
      group_info = calldb.group_infos[gid]
      fout.write(f' Group #{gid} info: '+json.dumps(group_info))
      fout.write('\n')

  def print_category_tree(self, fout):
    calldb = self.calldb
    fout.write('Category tree:\n')
    fout.write(json.dumps(calldb.category_tree, indent=2) + '\n')

  def print_category_deftypes(self, fout):
    calldb = self.calldb
    fout.write('Category default types:\n')
    fout.write(json.dumps(calldb.category_deftypes, indent=2) + '\n')


# Loads DB from .calldb file. Format it dynconfig with extra programs.
class CallDBDReader(DynconfigWithProperties):
  def __init__(self, callgroup_whitelist=None, prnfn=None):
    super().__init__()
    if callgroup_whitelist == None:
      callgroup_whitelist = []
    self.callgroup_whitelist = callgroup_whitelist
    if prnfn == None:
      prnfn = lambda s: None
    self._prnfn = prnfn
    self._loaded_db = CallDB()

    # Init DB fields
    self._loaded_db.entries = []
    self._loaded_db.entry_infos = []
    self._loaded_db.group_infos = []
    self._loaded_db.category_tree = None # in _finalize
    self._loaded_db.category_deftypes = None # in _finalize

    self._add_program('add_callgroup', self._prg_add_callgroup)

  def loaded_db(self):
    # _finalize() already called
    return self._loaded_db

  def _prg_add_callgroup(self, argdict, input_lines):
    # Check whitelist if needed
    if len(self.callgroup_whitelist):
      if not argdict['/name'] in self.callgroup_whitelist:
        self._prnfn(f'whitelist not empty - skipping this group - {argdict["/name"]}')
        return
    # Add group info
    cur_gid = len(self._loaded_db.group_infos)
    self._prnfn(f'adding callgroup #{cur_gid} (argdict={argdict}, {len(input_lines)} lines')
    self._loaded_db.group_infos.append({
      'name': argdict['/name'],
      'libs': argdict['/libs'].split(';') if '/libs' in argdict else [],
      'includes': argdict['/includes'].split(';') if '/includes' in argdict else [],
    })
    for input_line in input_lines:
      assert(not '\n' in input_line)
      if '@' in input_line:
        # TCHAR support, expand to two variants such as in category_tree case (where DictKeycharExpander is used)
        self._add_callgroup_line(input_line.replace('@', 'A'), cur_gid)
        self._add_callgroup_line(input_line.replace('@', 'W'), cur_gid)
      else:
        self._add_callgroup_line(input_line, cur_gid)
      pass
    return

  def _add_callgroup_line(self, input_line, gid:int):
    # Parse descrips
    raw_descrips, raw_positions = [], []
    get_descrips(input_line, raw_descrips, raw_positions)
    # self._prnfn(raw_descrips)

    # Convert descrips
    conv_descrips = []
    for direc, cat, typeover, paramdict in raw_descrips:
      conv_direc = {'in': Direction.IN, 'out': Direction.OUT,
                    'inout': Direction.INOUT, 'unused': Direction.UNUSED}[direc]
      descr = Descriptor(conv_direc, cat, typeover, paramdict)
      conv_descrips.append(descr)

    # Add converted descrips to call entry
    callentry = CallDBEntry()
    callentry.text_line = input_line
    callentry.descriptors = conv_descrips
    callentry.positions = raw_positions

    # Add call entry to db
    self._loaded_db.entries.append(callentry)
    self._loaded_db.entry_infos.append({'group': gid})  # 'src_line': nline  -- can be added

  # hook
  def _finalize(self):
    super()._finalize()
    # we must have category_tree and category_deftypes
    if not 'category_tree' in self.props():
      raise RuntimeError('category_tree dict must be present in dynconfig')
    if not 'category_deftypes' in self.props():
      raise RuntimeError('category_deftypes dict must be present in dynconfig')
    # Set it up in loaded db
    self._loaded_db.category_tree = self.props()['category_tree']
    self._loaded_db.category_deftypes = self.props()['category_deftypes']
    # TCHAR support: expand categories with '@' in names to A and W variants
    kchexp = DictKeycharExpander('@', ['A', 'W'])
    new_category_tree = {}
    kchexp.expand(self._loaded_db.category_tree, new_category_tree)
    self._loaded_db.category_tree = new_category_tree


def load_and_validate_calldb(text_lines, callgroup_whitelist=None) -> CallDB:
  rdr = CallDBDReader(callgroup_whitelist=callgroup_whitelist)
  rdr.load_from_lines(text_lines)
  valer = CallDBValidator(rdr.loaded_db())
  valer.validate()
  return rdr.loaded_db()


class CategoryTreeHelper:
  def __init__(self, category_tree:dict, category_deftypes:dict):
    self.category_tree = category_tree
    self.category_deftypes = category_deftypes

  def get_path_from_base(self, srctype) -> List[str]:
    return self._visitfind(srctype, self.category_tree)

  def get_deftype_of_base(self, srctype):
    pt = self.get_path_from_base(srctype)
    assert(pt)
    for t in pt:
      if t in self.category_deftypes:
        return self.category_deftypes[t]
    return None

  def _visitfind(self, needtyp:str, d:dict, cur_path=None):
    _RECURSE = self._visitfind
    if cur_path == None:
      cur_path = []
    for k in d.keys():
      if needtyp == k:
        return cur_path+[k]
      r = _RECURSE(needtyp, d[k], cur_path+[k])
      if r:
        return r
    return None


import os, sys
_sd = os.path.dirname(__file__)

def test_chains_calldb(argv):
  calldb_lines = open(f'{_sd}/test.calldb', 'r').readlines()
  rdr = CallDBDReader()
  rdr.load_from_lines(calldb_lines)

  valer = CallDBValidator(rdr.loaded_db())
  valer.validate()

  hlp = CategoryTreeHelper(rdr.loaded_db().category_tree, rdr.loaded_db().category_deftypes)
  p = hlp.get_path_from_base('Extra1')
  assert(p == ['Base', 'Derived1', 'Extra1'])
  p = hlp.get_path_from_base('Derived2')
  assert (p == ['Base', 'Derived2'])
  p = hlp.get_path_from_base('Base')
  assert (p == ['Base'])
  p = hlp.get_path_from_base('404')
  assert (p == None)

  dt = hlp.get_deftype_of_base('XExtra1')
  assert(dt == 'i64')
  dt = hlp.get_deftype_of_base('XDerived1')
  assert(dt == 'i64')
  dt = hlp.get_deftype_of_base('XBase')
  assert(dt == 'i64')
  #dt = hlp.deftype_of_base('NonExisting') # would raise
  #assert(dt == None)

  prn = CallDBPrinter(rdr.loaded_db())
  print('\n*** CALL DB ***\n')
  prn.print_all(sys.stdout)
  print('\n*** END OF CALL DB ***\n')

  # Just for test
  shuffle_db_entry_order(rdr.loaded_db(), random.randint(0, sys.maxsize))

  pass



if __name__ == '__main__':
  test_chains_calldb(sys.argv[1:])





