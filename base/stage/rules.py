import argparse
from typing import List, Dict, Any
from collections import namedtuple

from c2.infra.arg_processor import ArgProcessor
from c2.infra.arg_info import ArgInfo


Rule = namedtuple('Rule', ['stagename_fnmatch', 'catname_fnmatch', 'propname_fnmatch', 'operation', 'args'])

class RuleArgProcessor(ArgProcessor):
  def __init__(self):
    self.rules = None # [Rule(), Rule(), ...] # output, after _put_mentioned_parsed_args()
    
  def _get_arginfos(self) -> List[ArgInfo]:
    return [
      ArgInfo(['--rule'], {'nargs': '*', 'action': 'append'}),
    ]
  
  def _put_mentioned_parsed_args(self, argdict:Dict[str, Any]):
    assert(len(argdict) == 1)
    assert('rule' in argdict)
    self.rules = []
    if argdict['rule']:
      for arule in  argdict['rule']:
        if len(arule) < 5:
          raise RuntimeError(f'rule should be at least 5 elements, not {len(arule)}')
        s,c,p,o = arule[:4]
        a = arule[4:]
        ruleobj = Rule(s,c,p,o, a)
        self.rules.append(ruleobj)


def _test_eq(argv:List[str], expected_rules:List[Rule]):
  parser = argparse.ArgumentParser()

  rap = RuleArgProcessor()
  rap.add_to_argparser(parser)

  args = parser.parse_args(argv)

  rap.set_parsed_args(args)

  if rap.rules != expected_rules:
    print('Expected rules:')
    print(expected_rules);
    print('Got rules:')
    print(rap.rules);
    raise RuntimeError('rap.rules != expected_rules, see log')

def test_rule_arg_processor():
  rap = RuleArgProcessor()
  #rap.
  _test_eq([], [])
  _test_eq(['--rule', 'stage1*', 'cat1*', 'prop1*', 'operat1', 'argA', 'argB', 'argC',
            '--rule', 'stage2*', 'cat2*', 'prop2*', 'operat2', 'argA', 'argB', 'argC',
            ],
            [Rule('stage1*', 'cat1*', 'prop1*', 'operat1', ['argA', 'argB', 'argC']),
             Rule('stage2*', 'cat2*', 'prop2*', 'operat2', ['argA', 'argB', 'argC'])])

def test_rules():
  test_rule_arg_processor()

if __name__ == '__main__':
  test_rules()

