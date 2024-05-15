import os, sys, argparse, copy, json, jsonschema
from indexed import IndexedOrderedDict
from pprint import pprint
from enum import Enum, auto

from c2._internal_config import get_tmp_dir
from c2.common.jpath import *
from c2.common.schema2instance import *
from c2.common.merge_dicts import *
from c2.common.get_schema_props import get_schema_props
from c2.common.test_schemas import *


# class CLIConfig is a 'cook' class used by CLIConfigAggregator
# Cook example: .set_jen_conf(), .set_conf(), .apply_file_conf()
class CLIConfig:
  def __init__(self, schema, userarg=None, userarg_def=None,
               validate_userconf_schema=True,
               userconf_allow_onlyA=True, userconf_allow_onlyB=False,  # by default, allow incomplete userconf only
               use_filearg_prefix=False
               ):
    assert(not userarg_def or userarg != None)
    self.schema = schema
    self.userarg = userarg
    self.userarg_def = userarg_def
    self.validate_userconf_schema = validate_userconf_schema
    self._uc_allow_onlyA, self._uc_allow_onlyB = userconf_allow_onlyA, userconf_allow_onlyB

    self._cur_conf = None
    self._schemaprops_names = IndexedOrderedDict() # { 'age': 21, 'agreed': false, }
    self._schemaprops_paths = IndexedOrderedDict()  # { 'age': 21, 'agreed': false, }
    self._cmdline_opts = None   # { fullname: 'v', fullname: 123 }

    self._prefix = userarg+'_' if use_filearg_prefix else None
    get_schema_props(self.schema, self._schemaprops_names, splitter='_', prefix_to_add=self._prefix)
    get_schema_props(self.schema, self._schemaprops_paths, splitter='.', prefix_to_add=self._prefix) # for dpath

    self._fileconf = None # in set_parsed_args()

  # Warning, NAME CONFLICT. If multiple CLIConfigs, their fields must NOT have duplicate names/paths, because no prefixes used
  # NO default= supported, except for the arg that is the path to a json file (userarg)
  # E.g. it's ok to do: CC_xxx_opts.set_conf(UNI_xxx_opts.make_default_instance()). Default instance will have 'default', but CLIConfig doesn't use it
  def add_to_argparser(self, parser, required=False):
    # Add functionality to load user JSON
    if self.userarg != None:
      _otherargs = {}
      if self.userarg_def:
        _otherargs['default'] = self.userarg_def # default= ADDED only here
      parser.add_argument(f'--{self.userarg}', type=str, required=False, help='User JSON file',
                          **_otherargs)
    # Add functionality to override conf with cmdline args
    # default= NOT added
    for fullname in self._schemaprops_names.keys():
      typ = self._schemaprops_names[fullname]
      kwargs = {'required': required}
      if typ == 'boolean':
        #kwargs['action'] = 'store_true'
        kwargs['type'] = str
        kwargs['choices'] = ['true', 'false']
      elif typ == 'string':
        kwargs['type'] = str
      elif typ == 'number':
        kwargs['type'] = int
      elif typ == 'array':
        kwargs['type'] = str
        kwargs['nargs'] = '*'
      else:
        raise RuntimeError()
      #_prefix = ''
      #if self._use_filearg_prefix:
      #  _prefix = f'{self.userarg}_'
      parser.add_argument(f'--{fullname}', **kwargs)
    return

  def set_parsed_args(self, args):
    # here we set self._fileconf and self._cmdline_opts, they're processed later
    if self.userarg in args:
      userarg_val = args.__dict__[self.userarg]
      if userarg_val != None:
        self._fileconf = json.load(open(args.__dict__[self.userarg], 'r'))
        if self.validate_userconf_schema:
          jsonschema.validate(self.schema, self._fileconf)
    self._cmdline_opts = IndexedOrderedDict()
    for fullname  in self._schemaprops_names.keys():
      typ = self._schemaprops_names[fullname]
      v = args.__dict__[fullname]
      if v != None:
        # can be None if var not present in cl
        #print('set_parsed_args: parsed_dict['+fullname+']->', v)
        v2 = v
        if typ == 'boolean':
          # Manage booleans, need to CONVERT them: str('true') or str('false') to bool
          assert(v2 == 'true' or v2 == 'false')
          v2 = True if v2 == 'true' else False
        self._cmdline_opts[fullname] = v2

  # sugar; do this after set_parsed_args or manually #SugarDiet #DeleteMe
  #def finalize(self):
  #  self.make_empty_conf()
  #  self.apply_file_conf()
  #  self.apply_cmdline()

  # get current conf
  def conf(self) -> dict:
    return self._cur_conf

  # you are free not to use make_empty_conf() neither finalize(); you can setup things yourself
  def make_empty_conf(self):
    self._cur_conf = {}
    schema2instance(SchemaVarInitType.NullValues, self.schema, self._cur_conf, None)
    pass

  def set_conf(self, conf:dict, no_validate=False):
    if not no_validate:
      jsonschema.validate(conf, self.schema)
    self._cur_conf = conf

  def set_jen_conf(self, jen_conf:dict):
    # JEN docs are not ok with schema cuz instead of values, their fields have arrays (for $jc lists)
    # So we just don't use validation here
    self.set_conf(jen_conf, no_validate=True)

  def apply_file_conf(self):
    # if there is --userarg in cmd line (JSON file), use it
    if self._fileconf:
      merge_dicts(self._cur_conf, self._fileconf, self._uc_allow_onlyA, self._uc_allow_onlyB)

  def apply_cmdline(self):
    for nopt in range(len(self._cmdline_opts)):
      optname, optval = self._cmdline_opts.items()[nopt]
      optpath = self._optname2optpath(optname)
      #dpath.set(self._conf, pkey, val) # dpath doesn't append new values, only replaces existing, fuck it

      #print(f'apply_cmdline: {optpath} -> {optval} (optname: {optname})')

      # wow, we can erase fucking prefix here and we get real jpath path
      optpath2 = optpath
      if self._prefix:
        optpath2 = optpath[ len(self._prefix) : ] # cut some char from beginning

      jpath_set_s(self._cur_conf, optpath2, optval)

  def _optname2optpath(self, optname):
    idx = list(self._schemaprops_names.keys()).index(optname)
    k, v = self._schemaprops_paths.items()[ idx ]
    return k


_sd = os.path.dirname(__file__)
_my_tmpdir = get_tmp_dir()+'/cli_config'

def _test_CLIConfig0():
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('--another_arg', required=False)
  cc = CLIConfig(schema=test_schema_1, userarg='userconf')
  cc.add_to_argparser(parser, False)
  os.makedirs(_my_tmpdir, exist_ok=True)
  open(f'{_my_tmpdir}/tmp.json', 'w').write(json.dumps(
    {
      'somelistA': [10, 20, 30],
      'somelistB': ['A','B','C'],
      'someintA': 100,
      'someintB': 200,
      'someboolA': False,
      'someboolB': False,
      'sub': {
        'sex': 'transgender',
        'age': 18
      }}))
  args = parser.parse_args( # simulate cmdline
    ['--somelistB', 'X', 'Y', 'Z',
     '--someintB', '500',
     '--someboolA', 'true', # no someboolB
     '--sub_sex', 'censored',
     '--sub_super', '999',
     '--userconf', f'{_my_tmpdir}/tmp.json'
     ]) # jail bait
  cc.set_parsed_args(args)
  cc.make_empty_conf()
  cc.apply_file_conf()
  cc.apply_cmdline()
  print()
  print(cc.conf())
  expected = {
    'somelistA': [10, 20, 30],
    'somelistB': ['X', 'Y', 'Z'],
    'someintA': 100,
    'someintB': 500,
    'someboolA': True,
    'someboolB': False,
    'someboolC': None,
    'sub': {
      'sex': 'censored',
      'age': 18, # in schema+file
      'super': 999, # in schema+cmdline
      'mega': None # in schema only
    }
  }
  if cc.conf() != expected:
    print('expectation:')
    print(expected)
    print('got config:')
    print(cc.conf())
    raise RuntimeError('test failed - unexpected result dict')



# test attching multiple configs
# Alternative way - CC.make_empty_conf() (which calls schema2instance(NullValues), then overwrite it from file , then from cmdline
def _test_CLIConfigs():
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('--another_arg', required=False)
  cc1 = CLIConfig(schema=test_schema_1, userarg='userconf1')
  cc2 =  CLIConfig(schema=test_schema_2, userarg='userconf2')
  cc1.add_to_argparser(parser, False)
  cc2.add_to_argparser(parser, False)
  os.makedirs(_my_tmpdir, exist_ok=True)
  open(f'{_my_tmpdir}/tmp1.json', 'w').write(json.dumps(
    {
      'somelistA': [10, 20, 30],
      'somelistB': ['A','B','C'],
      'someintA': 100,
      'someintB': 200,
      'someboolA': False,
      'someboolB': False,
      'sub': {
        'sex': 'transgender',
        'age': 18
      }}))
  open(f'{_my_tmpdir}/tmp2.json', 'w').write(json.dumps(
    {
      'hex': {
        'fuck1': False,
        'fuck2': False,
      }
    }))

  args = parser.parse_args( # simulate cmdline
    ['--somelistB', 'X', 'Y', 'Z',
     '--someintB', '500',
     '--someboolA', 'true', # no someboolB
     '--sub_sex', 'censored',
     '--sub_super', '999',
     '--hex_fuck2', 'true', # for tmp2.json
     '--userconf1', f'{_my_tmpdir}/tmp1.json',
     '--userconf2', f'{_my_tmpdir}/tmp2.json'
     ]) # jail bait


  print('CC1: ****************************')
  cc1.set_parsed_args(args)
  cc1.make_empty_conf()
  cc1.apply_file_conf()
  cc1.apply_cmdline()
  print()
  print(cc1.conf())

  print('CC2: ****************************')
  cc2.set_parsed_args(args)
  cc2.make_empty_conf()
  cc2.apply_file_conf()
  cc2.apply_cmdline()
  print()
  print(cc2.conf())

  expected1 = {
    'somelistA': [10, 20, 30],
    'somelistB': ['X', 'Y', 'Z'],
    'someintA': 100,
    'someintB': 500,
    'someboolA': True,
    'someboolB': False,
    'someboolC': None,
    'sub': {
      'sex': 'censored',
      'age': 18, # in schema+file
      'super': 999, # in schema+cmdline
      'mega': None # in schema only
    }
  }
  if cc1.conf() != expected1:
    print('expectation1:')
    print(expected1)
    print('got config1:')
    print(cc1.conf())
    raise RuntimeError('test failed - unexpected result dict (1)')

  print('EXPECTATION 1 OK')

  expected2 = {
    'hex': {
      'fuck1': False,
      'fuck2': True,
    }
  }
  if cc2.conf() != expected2:
    print('expectation2:')
    print(expected2)
    print('got config2:')
    print(cc2.conf())
    raise RuntimeError('test failed - unexpected result dict (2)')

def _test_CLIConfig_boolean_in_cmdline():
  argv = ['--someboolA', 'false', '--someboolB', 'true']

  schema_to_use = test_schema_1
  def_conf = {}
  schema2instance(SchemaVarInitType.NullValues, schema_to_use, def_conf, None)
  assert(def_conf['someboolA'] == None and def_conf['someboolB'] == None and def_conf['someboolC'] == None)
  ###
  cc = CLIConfig(schema_to_use, 'opts')
  cc.set_conf(def_conf, no_validate=True)
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  cc.add_to_argparser(parser, False)
  args = parser.parse_args(argv)

  cc.conf()['someboolA'] = True # argv will swap true/false in A/B

  cc.set_parsed_args(args)
  cc.apply_file_conf()
  assert(cc.conf()['someboolA'] == True and cc.conf()['someboolB'] == None) # nothing changed
  cc.apply_cmdline() # this should apply argv to conf
  assert(cc.conf()['someboolA'] == False and cc.conf()['someboolB'] == True) # A and B swapped
  assert(cc.conf()['someboolC'] == None) # C not changed since cc.set_conf(def_conf
  #TODO: someboolC: use it as preset to true and check that it hasnt be reset to false after apply_cmdline


def test_cli(argv):
  _test_CLIConfig0()
  _test_CLIConfigs()
  _test_CLIConfig_boolean_in_cmdline()


if __name__ == '__main__':
  test_cli(sys.argv[1:])



