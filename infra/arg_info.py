import argparse
from typing import List, Dict, Any
from dataclasses import dataclass

from c2.infra.option_string import validate_option_string

# To KEEP this argparse-COMPATIBLE, we are limiting argparse functionality (conceptually), not extending.
# For example, argparse supports names like ---this, and we don't. We require - or -- as a prefix.

# https://docs.python.org/3/library/argparse.html
# ...
# The add_argument() method
#   name or flags - Either a name or a list of option strings, e.g. foo or -f, --foo.
# ...
# The add_argument() method must know whether an optional argument, like -f or --foo, or a positional argument, like a list of filenames, is expected. 
# ...

# parse_args() will return Namespace that contains args named with following rule:
# if there are -- args, use the name of the first; otherwise (e.g. if there are only - args), use first - arg's name (see main_name())

### ignore
# Cheap immitation of argparse.ArgumentParser logic here. It's cheap because we don't test it for equality 
# single or double `-`, then any non zero-length mix of \w, \d and _
##def is_valid_named_opt_name(key):
##  return re.match('^--?[_\w\d]+$', key)

# class ArgInfo represents [currently argparser-compatible] information of a single argument
@dataclass
class ArgInfo:
  option_strings: List[str]              # ['-n', '--num_cocks_ur_mom_sucked','--numkoks'] - they are all ALIASES
  addargument_kwargs: Dict[str, Any]     # {'required': True, 'help': 'any help', }

  def validate_option_strings(self):
    for option_string in self.option_strings:
      pass

  def validate_addargument_kwargs(self):
    for k in self.addargument_kwargs.keys():
      if type(k) != str:
        raise RuntimeError('key should be str')
    # some more check can be done probably



def _test_find_main_name():
  ai = ArgInfo(['penis_radius', ], {'required': False, 'nargs': '*'})
  raise

def _test_validation():
  # validate_option_strings()
  # validate_addargument_kwargs
  raise

def _test():
  _test_find_main_name()

if __name__ == '__main__':
  _test()

