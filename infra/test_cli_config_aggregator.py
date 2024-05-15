import sys, argparse, os, json, jsonschema

from c2._internal_config import get_tmp_dir
from c2.infra.unischema import Unischema
from c2.infra.cli_config_aggregator import CLIConfigAggregator, CLIConfigAggregatorException
from c2.common.recreate_dir import recreate_dir

# --apple_seeds_seed2 myseed
_UNI_apple = {
  'type': 'object',
  'properties': {
    'diameter': {'type':'number', 'default': 9381},
    'color': {'type': 'string', 'default': 'red'},
    'seeds': {
      'type': 'object',
      'properties': {
        'seed1': {'type':'string','default':'lala1'},
        'seed2': {'type':'string','default':'lala2'},
        'seed3': {'type':'string','default':'lala3'}
      }
    }
  }
}

# --banana_bananainfo_bananaid 123456
_UNI_banana = {
  'type': 'object',
  'properties': {
    'length': {'type':'number','default':992},
    'is_from_africa': {'type': 'boolean','default':True},
    'is_from_south': {'type': 'boolean','default':True},
    'bananainfo': {
      'type': 'object',
      'properties': {
        'bananaid': {'type':'number','default':64731},
        'bananahash': {'type':'number', 'default':39812938},
        'bananacount': {'type':'number','default':16}
      }
    }
  }
}

# What we need: default; override from cmdline; override from file; from file+cmdline

# imported by test_cli_config_aggregator_with_jen.py
class CliConfigAggregatorTestBase:
  def __init__(self):
    self.aggregator = CLIConfigAggregator()
    self.parser = argparse.ArgumentParser(os.path.basename(__file__))
  def print_fields(self):
    for id in self.aggregator.config_ids():
      c = self.aggregator.config(id)
      print(id, '->', c)
  def as_checkbook(self):
    checkbook = {}
    for id in self.aggregator.config_ids():
      checkbook[id] = self.aggregator.config(id)
    return checkbook
  def check_expectation(self, checkbook):
    for key in checkbook.keys():
      value = checkbook[key]
      if self.aggregator.config(key) != value:
        raise RuntimeError('expectation failed')
  def execute(self, argv):
    raise NotImplementedError()

class _AppleBananaTest(CliConfigAggregatorTestBase):
  def execute(self, argv):
    self.aggregator.add_config('apple', Unischema(_UNI_apple))
    self.aggregator.add_config('banana', Unischema(_UNI_banana))
    self.parser.add_argument('--another_argument', type=int)
    self.aggregator.add_to_argparser(self.parser)
    args = self.parser.parse_args(argv)
    self.aggregator.set_parsed_args(args)


def _test_ovr_from_cmdline():
  test = _AppleBananaTest()
  test.execute(['--apple_seeds_seed2', 'myseed', '--banana_bananainfo_bananaid', '123456'])
  test.print_fields()
  print(test.as_checkbook())
  test.check_expectation({'apple': {'diameter': 9381, 'color': 'red', 'seeds': {'seed1': 'lala1', 'seed2': 'myseed', 'seed3': 'lala3'}},
                          'banana': {'length': 992, 'is_from_africa': True, 'is_from_south': True, 'bananainfo': {'bananaid': 123456, 'bananahash': 39812938, 'bananacount': 16}}})

_sd = os.path.dirname(__file__)
_tmpdir = f'{get_tmp_dir()}/cli_config_aggregator_test'
_overriding_apple_file = f'{_tmpdir}/overriding_apple_opts.json'
_overriding_banana_file = f'{_tmpdir}/overriding_banana_opts.json'
_overriding_apple_opts = {
  'diameter': 513,
  'seeds': {
    'seed2': 'hello',
    'seed3': 'blablabla'
  }
}
_overriding_banana_opts = {
  'is_from_africa': False,
  'is_from_south': False,
  'bananainfo': {
    'bananaid': 137
  }
}
def _put_ovropts_to_temp_files():
  json.dump(_overriding_apple_opts, open(_overriding_apple_file, 'w'))
  json.dump(_overriding_banana_opts, open(_overriding_banana_file, 'w'))

def _test_ovr_from_file():
  _put_ovropts_to_temp_files()
  test = _AppleBananaTest()
  test.execute(['--apple', _overriding_apple_file, '--banana', _overriding_banana_file])
  test.print_fields()
  print(test.as_checkbook())
  test.check_expectation({'apple': {'diameter': 513, 'color': 'red', 'seeds': {'seed1': 'lala1', 'seed2': 'hello', 'seed3': 'blablabla'}}, 'banana': {'length': 992, 'is_from_africa': False, 'is_from_south': False, 'bananainfo': {'bananaid': 137, 'bananahash': 39812938, 'bananacount': 16}}})
  pass

def _test_ovr_from_file_and_cmdline():
  # file makes banana is_from_africa False, cmdline makes it back True
  _put_ovropts_to_temp_files()
  test = _AppleBananaTest()
  argv = ['--apple', _overriding_apple_file, # file overrides default from schema
            '--apple_seeds_seed2', 'OVERRIDEN', # cmdline overrides file
            '--apple_color', 'green', # cmdlines overrides default from schema
            '--banana', _overriding_banana_file, # file overrides default from schema
            '--banana_is_from_south', 'true', # restore true, was true by default and then false by file
            '--banana_bananainfo_bananaid', '123123123123' # cmdline overrides file
            ]
  test.execute(argv)
  for id in test.aggregator.config_ids():
    c = test.aggregator.config(id)
    print(id, '->', c)
  print(test.as_checkbook())
  expected = {
    'apple': {
      'diameter': 513,  # by file
      'color': 'green',  # by cmdline
      'seeds': {
        'seed1': 'lala1',  # default from schema
        'seed2': 'OVERRIDEN',  # by file, THEN by cmdline
        'seed3': 'blablabla'  # by file
      }
    },
    'banana': {
      'length': 992,
      'is_from_africa': False,  # by file
      'is_from_south': True,  # by file, THEN by cmdline (True->False->True)
      'bananainfo': {
        'bananaid': 123123123123,  # by file, THEN by cmdline
        'bananahash': 39812938,  # default from schema
        'bananacount': 16  # default from schema
      }
    }
  }
  test.check_expectation(expected)

  # extra validate for fun and profit
  jsonschema.validate(expected['apple'], test.aggregator.get_unischema('apple').schema)
  jsonschema.validate(expected['banana'], test.aggregator.get_unischema('banana').schema)
  # and through Unischema too
  test.aggregator.get_unischema('apple').validate_instance(expected['apple'])
  test.aggregator.get_unischema('banana').validate_instance(expected['banana'])

  pass

def _test_conflicting_field_names_in_different_configs():
  agr = CLIConfigAggregator()
  u1 = Unischema({
    'type': 'object',
    'properties': {
      'a': {'type':'number','default':5}, 'b': {'type':'number','default':6}, 'c': {'type':'number','default':7}
    }
  })
  u2 = Unischema({
    'type': 'object',
    'properties': {
      'A': {'type':'number','default':8}, 'B': {'type':'number','default':9}, 'c': {'type':'number','default':10}
    }
  })
  agr.add_config('opts1', u1)
  try:
    agr.add_config('opts1', u2)
    raise RuntimeError('expected exception NOT OCCURRED')
  except CLIConfigAggregatorException as e:
    print('*** expected exception:', e)
  pass


def test_cli_config_aggregator(argv):
  recreate_dir(_tmpdir)
  _test_ovr_from_cmdline()
  _test_ovr_from_file()
  _test_ovr_from_file_and_cmdline()
  _test_conflicting_field_names_in_different_configs()

if __name__ == '__main__':
  test_cli_config_aggregator(sys.argv[1:])







