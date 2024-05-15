import os, sys, argparse, jsonschema
from pprint import pprint

from c2.infra.unischema import *
from c2.infra.dyn_jen import *
from c2.infra.cli_config import *

_sd = os.path.dirname(__file__)

#
# '$j' is extra prop key which is a special thing for SCHEMA
# it contains special jen properties that are COPIED when instantiating from Unischema.make_dynjen_doc()
#
_test_unischema = {
  'type': 'object',
  # market.fruit -> qiwi | orange | lemon
  'properties': {
    'market': {
      'type': 'object',
      'properties': {
        'fruit': {'type': 'string', '$jdefault': ['$jcs', 'qiwi', 'orange', 'lemon']},
        'recipe': {'type': 'string', '$jdefault': ['$jcs', 'food', 'ice'],
                   'default': 'ice'},
        'amount': {'type': 'number', '$jdefault': ['$jcn', '50', '100']}
      }
    },
    # qiwi_opts, orange_opts, lemon_opts
    'qiwi_opts': {
      'type': 'object',
      'properties': {
        'qiwi_size': {'type': 'number', '$jdefault': ['$jcn', '10', '20', '30'],
                      'default': 20},
        'qiwi_country': {'type': 'string', '$jdefault': ['$jcs', 'africa', 'costarica']}
      },
      '$j': {'$jif': ['market.fruit', 'qiwi']}
    },
    'orange_opts': {
      'type': 'object',
      'properties': {
        'orangeness': {'type': 'number', '$jdefault': ['$jcn', '500', '600', '700']},
      },
      '$j': {'$jif': ['market.fruit', 'orange']}
    },
    'lemon_opts': {
      'type': 'object',
      'properties': {
        'acid': {'type': 'boolean', '$jdefault': ['$jcb', 'true', 'false']},
      },
      '$j': {'$jif': ['market.fruit', 'lemon']}
    }
  }
}

def _test_unischema1():
  u = Unischema(_test_unischema)
  dj = u.make_dynjen_doc()
  cs = u.make_jen_schema_for_cli()
  pass

def _do_uni_cli_test(schema:dict, argv, insts_expected):
  u = Unischema(schema)
  cs = u.make_jen_schema_for_cli()
  doc = u.make_dynjen_doc()

  cc = CLIConfig(cs, 'opts', None)
  cc.set_conf(doc)

  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('--jen_order', nargs='*', action='append')
  cc.add_to_argparser(parser)

  args = parser.parse_args(argv)
  cc.set_parsed_args(args)
  cc.apply_file_conf()
  cc.apply_cmdline()

  jen_order = []
  if args.jen_order:
    jen_order = args.jen_order[0]
  dj = DynJen(cc.conf(), jen_order)
  insts = []
  for inst in dj:
    insts.append(inst)
  if insts != insts_expected:
    print('!!! !!! !!! !!!EXPECTATION FAILED!!! !!! !!! !!!')
    print('insts:')
    pprint(insts)
    print('insts_expected:')
    pprint(insts_expected)
    raise  RuntimeError('unexpected test output')

# with CLI, overriding order
def _test_unischema2():
  argv = ['--jen_order', 'market.amount', 'market.recipe', 'market.fruit',
          'qiwi_opts.qiwi_country', 'qiwi_opts.qiwi_size']
  _do_uni_cli_test(_test_unischema,
                   argv,
                   [{'market': {'fruit': 'qiwi', 'recipe': 'food', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 10, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'food', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 10, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'food', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 20, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'food', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 20, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'food', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 30, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'food', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 30, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'food', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 10, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'food', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 10, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'food', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 20, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'food', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 20, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'food', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 30, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'food', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 30, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'ice', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 10, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'ice', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 10, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'ice', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 20, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'ice', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 20, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'ice', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 30, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'ice', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 30, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'ice', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 10, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'ice', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 10, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'ice', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 20, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'ice', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 20, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'ice', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 30, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'ice', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 30, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'orange', 'recipe': 'food', 'amount': 50}, 'orange_opts': {'orangeness': 500}}, {'market': {'fruit': 'orange', 'recipe': 'food', 'amount': 50}, 'orange_opts': {'orangeness': 600}}, {'market': {'fruit': 'orange', 'recipe': 'food', 'amount': 50}, 'orange_opts': {'orangeness': 700}}, {'market': {'fruit': 'orange', 'recipe': 'food', 'amount': 100}, 'orange_opts': {'orangeness': 500}}, {'market': {'fruit': 'orange', 'recipe': 'food', 'amount': 100}, 'orange_opts': {'orangeness': 600}}, {'market': {'fruit': 'orange', 'recipe': 'food', 'amount': 100}, 'orange_opts': {'orangeness': 700}}, {'market': {'fruit': 'orange', 'recipe': 'ice', 'amount': 50}, 'orange_opts': {'orangeness': 500}}, {'market': {'fruit': 'orange', 'recipe': 'ice', 'amount': 50}, 'orange_opts': {'orangeness': 600}}, {'market': {'fruit': 'orange', 'recipe': 'ice', 'amount': 50}, 'orange_opts': {'orangeness': 700}}, {'market': {'fruit': 'orange', 'recipe': 'ice', 'amount': 100}, 'orange_opts': {'orangeness': 500}}, {'market': {'fruit': 'orange', 'recipe': 'ice', 'amount': 100}, 'orange_opts': {'orangeness': 600}}, {'market': {'fruit': 'orange', 'recipe': 'ice', 'amount': 100}, 'orange_opts': {'orangeness': 700}}, {'market': {'fruit': 'lemon', 'recipe': 'food', 'amount': 50}, 'lemon_opts': {'acid': True}}, {'market': {'fruit': 'lemon', 'recipe': 'food', 'amount': 50}, 'lemon_opts': {'acid': False}}, {'market': {'fruit': 'lemon', 'recipe': 'food', 'amount': 100}, 'lemon_opts': {'acid': True}}, {'market': {'fruit': 'lemon', 'recipe': 'food', 'amount': 100}, 'lemon_opts': {'acid': False}}, {'market': {'fruit': 'lemon', 'recipe': 'ice', 'amount': 50}, 'lemon_opts': {'acid': True}}, {'market': {'fruit': 'lemon', 'recipe': 'ice', 'amount': 50}, 'lemon_opts': {'acid': False}}, {'market': {'fruit': 'lemon', 'recipe': 'ice', 'amount': 100}, 'lemon_opts': {'acid': True}}, {'market': {'fruit': 'lemon', 'recipe': 'ice', 'amount': 100}, 'lemon_opts': {'acid': False}}])

# with overriding some opts
def _test_unischema4():
  argv = ['--jen_order', 'market.amount', 'market.recipe', 'market.fruit',
          'qiwi_opts.qiwi_country', 'qiwi_opts.qiwi_size',
          '--qiwi_opts_qiwi_size', '$jcn', '888888', '999999', '--market_recipe', '$jcs', 'newrecipe1', 'newrecipe2']
  _do_uni_cli_test(_test_unischema,
                   argv,
                   [{'market': {'fruit': 'qiwi', 'recipe': 'newrecipe1', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 888888, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe1', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 888888, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe1', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 999999, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe1', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 999999, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe1', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 888888, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe1', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 888888, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe1', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 999999, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe1', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 999999, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe2', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 888888, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe2', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 888888, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe2', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 999999, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe2', 'amount': 50}, 'qiwi_opts': {'qiwi_size': 999999, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe2', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 888888, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe2', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 888888, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe2', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 999999, 'qiwi_country': 'africa'}}, {'market': {'fruit': 'qiwi', 'recipe': 'newrecipe2', 'amount': 100}, 'qiwi_opts': {'qiwi_size': 999999, 'qiwi_country': 'costarica'}}, {'market': {'fruit': 'orange', 'recipe': 'newrecipe1', 'amount': 50}, 'orange_opts': {'orangeness': 500}}, {'market': {'fruit': 'orange', 'recipe': 'newrecipe1', 'amount': 50}, 'orange_opts': {'orangeness': 600}}, {'market': {'fruit': 'orange', 'recipe': 'newrecipe1', 'amount': 50}, 'orange_opts': {'orangeness': 700}}, {'market': {'fruit': 'orange', 'recipe': 'newrecipe1', 'amount': 100}, 'orange_opts': {'orangeness': 500}}, {'market': {'fruit': 'orange', 'recipe': 'newrecipe1', 'amount': 100}, 'orange_opts': {'orangeness': 600}}, {'market': {'fruit': 'orange', 'recipe': 'newrecipe1', 'amount': 100}, 'orange_opts': {'orangeness': 700}}, {'market': {'fruit': 'orange', 'recipe': 'newrecipe2', 'amount': 50}, 'orange_opts': {'orangeness': 500}}, {'market': {'fruit': 'orange', 'recipe': 'newrecipe2', 'amount': 50}, 'orange_opts': {'orangeness': 600}}, {'market': {'fruit': 'orange', 'recipe': 'newrecipe2', 'amount': 50}, 'orange_opts': {'orangeness': 700}}, {'market': {'fruit': 'orange', 'recipe': 'newrecipe2', 'amount': 100}, 'orange_opts': {'orangeness': 500}}, {'market': {'fruit': 'orange', 'recipe': 'newrecipe2', 'amount': 100}, 'orange_opts': {'orangeness': 600}}, {'market': {'fruit': 'orange', 'recipe': 'newrecipe2', 'amount': 100}, 'orange_opts': {'orangeness': 700}}, {'market': {'fruit': 'lemon', 'recipe': 'newrecipe1', 'amount': 50}, 'lemon_opts': {'acid': True}}, {'market': {'fruit': 'lemon', 'recipe': 'newrecipe1', 'amount': 50}, 'lemon_opts': {'acid': False}}, {'market': {'fruit': 'lemon', 'recipe': 'newrecipe1', 'amount': 100}, 'lemon_opts': {'acid': True}}, {'market': {'fruit': 'lemon', 'recipe': 'newrecipe1', 'amount': 100}, 'lemon_opts': {'acid': False}}, {'market': {'fruit': 'lemon', 'recipe': 'newrecipe2', 'amount': 50}, 'lemon_opts': {'acid': True}}, {'market': {'fruit': 'lemon', 'recipe': 'newrecipe2', 'amount': 50}, 'lemon_opts': {'acid': False}}, {'market': {'fruit': 'lemon', 'recipe': 'newrecipe2', 'amount': 100}, 'lemon_opts': {'acid': True}}, {'market': {'fruit': 'lemon', 'recipe': 'newrecipe2', 'amount': 100}, 'lemon_opts': {'acid': False}}])

def _test_unischema_mkclischema():
  u = Unischema(None)

  new_schema = {}
  u._mkclischema(_test_unischema, new_schema, defkey_to_wrap_jcx=None)
  assert(new_schema == {'type': 'object', 'properties': {'market': {'type': 'object', 'properties': {'fruit': {'type': 'array'}, 'recipe': {'type': 'array'}, 'amount': {'type': 'array'}}}, 'qiwi_opts': {'type': 'object', 'properties': {'qiwi_size': {'type': 'array'}, 'qiwi_country': {'type': 'array'}}, '$j': {'$jif': ['market.fruit', 'qiwi']}}, 'orange_opts': {'type': 'object', 'properties': {'orangeness': {'type': 'array'}}, '$j': {'$jif': ['market.fruit', 'orange']}}, 'lemon_opts': {'type': 'object', 'properties': {'acid': {'type': 'array'}}, '$j': {'$jif': ['market.fruit', 'lemon']}}}})

  new_schema = {}
  u._mkclischema(_test_unischema, new_schema, defkey_to_wrap_jcx='default')
  assert(new_schema == {'type': 'object', 'properties': {'market': {'type': 'object', 'properties': {'fruit': {'type': 'array', 'default': ['$jcs', 'None']}, 'recipe': {'type': 'array', 'default': ['$jcs', 'ice']}, 'amount': {'type': 'array', 'default': ['$jcn', 'None']}}}, 'qiwi_opts': {'type': 'object', 'properties': {'qiwi_size': {'type': 'array', 'default': ['$jcn', '20']}, 'qiwi_country': {'type': 'array', 'default': ['$jcs', 'None']}}, '$j': {'$jif': ['market.fruit', 'qiwi']}}, 'orange_opts': {'type': 'object', 'properties': {'orangeness': {'type': 'array', 'default': ['$jcn', 'None']}}, '$j': {'$jif': ['market.fruit', 'orange']}}, 'lemon_opts': {'type': 'object', 'properties': {'acid': {'type': 'array', 'default': ['$jcb', 'None']}}, '$j': {'$jif': ['market.fruit', 'lemon']}}}})


def _test_unischema_validate():
  u = Unischema(_test_unischema)
  jen = u.make_dynjen_doc()
  dj = DynJen(jen, [])
  for inst in dj:
    print(inst)
    jsonschema.validate(inst, u.schema)
    u.validate_instance(inst)
  return

def _test_unischema_dynjen_single():
  u = Unischema(_test_unischema)
  x = u.make_dynjen_single()
  x = x

def _test_unischema_rawvalidate():
  u = Unischema(_test_unischema)
  dj = DynJen(u.make_dynjen_doc(), [])
  inst0 = next(x for x in dj)
  # Do the thing we're testing -- validate by raw schema
  jsonschema.validate(inst0, _test_unischema)
  u.validate_instance(inst0) #NewCode
  pass

def _test_unischema_loader():
  _td_dir = f'{_sd}/../test/td/unischema_loader'
  uniloader = UnischemaLoader(_td_dir)
  unidict = uniloader.load_unischema(_td_dir+'/1.UNISCHEMA')
  u = Unischema(unidict)
  jsonschema.validate(u.make_default_config(), u.schema)
  inst = u.make_default_config()
  u.validate_instance(inst)
  pass


def test_unischema(argv):
  _test_unischema1()
  _test_unischema2()
  _test_unischema_mkclischema()
  _test_unischema_validate()
  _test_unischema_dynjen_single()
  _test_unischema_rawvalidate()
  _test_unischema_loader()


if __name__ == '__main__':
  test_unischema(sys.argv[1:])

