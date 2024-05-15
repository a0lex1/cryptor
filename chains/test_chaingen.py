import os, sys, jsonschema, random
from pprint import pprint

from c2.chains.chaingen import *
from c2.infra.cli_config import *

_sd = os.path.dirname(__file__)

# opts for class ChainGenTest
chgentest_opts_schema = {
  "type": "object",
  "properties": {
    "class_to_test": {"type": "string", "enum": ["dfs", "random"], "default": "dfs"},
    "calldb": {"type": "string", "default": "./test.calldb" }, # no default value
    "shuffle_db": {"type": "bool", "default": True},
    "callgroup_whitelist": {"type": "array", "default": []},
    "print_db": {"type": "bool"}
  }
}
chgentest_dfs_opts_schema = {
  "type": "object",
  "properties": {
    "reserved": {"type": "string", "default": ""},
    "order": {"type": "string", "enum": ["default", "reversed"], "default": "default"}
  }
}
chgentest_random_opts_schema = {
  "type": "object",
  "properties": {
    "max_cid_use_count": {"type": "number", "default": 3}
  }
}
# multivariant (dfs opts + random opts)
chgentest_dynopts_schema = {
  "type": "object",
  "properties": {
    "oneOf": [ # mutual exclusion list
      { "dfs": chgentest_dfs_opts_schema },  # $ref
      { "random": chgentest_random_opts_schema }  # $ref
    ]
  }
}

class ChainGenTest:
  def __init__(self, chgentest_opts, chgentest_dynopts):
    self._RNG = random.Random()
    if 'dfs' in chgentest_opts['class_to_test']:
      assert ('dfs' in chgentest_dynopts)
    if 'random' in chgentest_opts['class_to_test']:
      assert ('random' in chgentest_dynopts)
    jsonschema.validate(chgentest_opts_schema, chgentest_opts)
    jsonschema.validate(chgentest_dynopts_schema, chgentest_dynopts)
    self.opts = chgentest_opts
    self.dynopts = chgentest_dynopts
    self._calldb = None  # need init()

  def run(self):
    # Load DB
    # ./file means file from directory where this python script is stored
    calldb_realp = os.path.join(_sd, self.opts['calldb'])
    self._calldb = load_and_validate_calldb(open(calldb_realp).readlines(),
                                            callgroup_whitelist=self.opts['callgroup_whitelist'])
    calldb = self._calldb

    # Optionally print DB
    if self.opts['print_db']:
      prn = CallDBPrinter(calldb)
      prn.print_entry_table(True, sys.stdout)
      # prn.print_category_tree(sys.stdout)
      print()

    # create ChainGen object
    vardb = VarDB()
    if self.opts['class_to_test'] == 'dfs':
      _ord = {'default': ChainGenDFSOrder.DEFAULT,
              'reversed': ChainGenDFSOrder.REVERSED}[self.dynopts['dfs']['order']]
      chaingen = ChainGenDFS(calldb,
                             vardb,
                             _ord)
    elif self.opts['class_to_test'] == 'random':
      rng = self._RNG
      chaingen = ChainGenRandom(calldb, vardb,
                                self.dynopts['random']['max_cid_use_count'],
                                rng)
    else:
      raise RuntimeError()

    # Prepare to generate chain
    chainitems = []

    chaingen.set_calldb(self._calldb)
    chaingen.set_vardb(vardb)
    chaingen.set_prnfn(print)

    # Generate chain
    for new_item in chaingen:
      chainitems.append(new_item)
      pass

    print()
    print(f'Chain generated ({len(chainitems)} items).')
    print()

    # Make textualized declarations
    varnames = make_chain_var_names(calldb, vardb)

    locdecls = make_chain_vars_decl(calldb, vardb, varnames, tabs=1)
    print(locdecls)

    # Textualize to lines
    lines = []
    chaintexer = ChainTextualizer(calldb, vardb, varnames)
    for item in chainitems:
      text = chaintexer.tex_one(item) + ';'
      print(text)
      lines.append('  ' + text)

    print()

    # HACK
    if type(chaingen) == ChainGenDFS:
      print('ChainGenDFS special case - checking if all cids were used')
      if not all_cids_used_in_chain(calldb, chainitems):
        raise RuntimeError("not all cids from DB were used in chain")

    # Exec source code
    includes, libs = [], []
    collect_group_info(calldb, self.opts['callgroup_whitelist'], includes, libs)
    hlphdr = os.path.join(_sd, 'chaingen_hlp_hdr.h')
    helper_srcexec(test_cpp_from_template('', locdecls, '', '',
                                          '\n'.join(lines),
                                          includes+[hlphdr]))
    pass


def test_chaingen(argv):
  print('*'*1000)
  print('TODO TASKS: ')
  print('  Why ChainGenRandom doesnt use all cids? -- cls && py -m c2.chains.test_chaingen --class_to_test $jcs random -s --calldb $jcs real1.calldb')
  print('  upcast not complete! need order from base to derived, etc')
  print('  class ChgenDFSVarPicking(Enum): DEFAULT, REVERSED, RANDOM?')
  print('  deallocator')
  print('  slots')
  print('  Fill real1.calldb with real calls')
  exit()

  # test_chaingen --opts_jen_order calldb shuffle_db --calldb 1.calldb 2.calldb
  # test_chaingen --calldb $jcs real1.calldb --dry --dfs_opts_jen_order dfs.order dfs.reserved --random_opts_jen_order random.max_cid_use_count
  #
  # prepare CLI objects: main opts
  chgentest_opts_jen_schema = schema2jenschema(chgentest_opts_schema)
  cc_opts = CLIConfig(chgentest_opts_jen_schema, 'opts', f'{_sd}/test_chaingen.jen', False, False)

  # dyn opts
  chgentest_dfs_opts_jen_schema = schema2jenschema(chgentest_dfs_opts_schema)
  cc_dfs_opts = CLIConfig(chgentest_dfs_opts_jen_schema, 'dfs_opts', f'{_sd}/test_chaingen_dfs.jen', False, False)

  chgentest_random_opts_jen_schema = schema2jenschema(chgentest_random_opts_schema)
  cc_random_opts = CLIConfig(chgentest_random_opts_jen_schema, 'random_opts', f'{_sd}/test_chaingen_random.jen', False, False)

  # CLIConfig objects
  cliconfs = [cc_opts, cc_dfs_opts, cc_random_opts]

  # parse args
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('-s', '--single', action='store_true', help='only first iteration')
  parser.add_argument('--dry', action='store_true', help='don\'t run test, print generated opts')
  parser.add_argument('--opts_jen_order', nargs='*', action='append', required=False)
  parser.add_argument('--dfs_opts_jen_order', nargs='*', action='append', required=False, help='prefix must be `dfs.`')
  parser.add_argument('--random_opts_jen_order', nargs='*', action='append', required=False, help='prefix must be `random.`')
  for cliconf in cliconfs:
    cliconf.add_to_argparser(parser)
  args = parser.parse_args(argv)
  for cliconf in cliconfs:
    cliconf.set_parsed_args(args)
    cliconf.finalize() # you will se error if you exec this line cuz we commented out the sugar (finalize was sugar)

  # execute test
  opts_jen_order, dfs_opts_jen_order, random_opts_jen_order = [], [], []
  if args.opts_jen_order:
    opts_jen_order = args.opts_jen_order[0]
  if args.dfs_opts_jen_order:
    dfs_opts_jen_order = args.dfs_opts_jen_order[0]
  if args.random_opts_jen_order:
    random_opts_jen_order = args.random_opts_jen_order[0]

  jen_opts = Jen(cc_opts.conf(), opts_jen_order)
  for njo in range(jen_opts.number_of_iterations()):
    cur_opts = jen_opts.iteration(njo)
    print(f'### opts for iter {njo}:')
    print('opts', cur_opts)

    cur_dynopts_jen, cur_dynopts_jen_order = {}, []
    if cur_opts['class_to_test'] == 'dfs':
      cur_dynopts_jen['dfs'] = cc_dfs_opts.conf()
      cur_dynopts_jen_order = dfs_opts_jen_order
    elif cur_opts['class_to_test'] == 'random':
      cur_dynopts_jen['random'] = cc_random_opts.conf()
      cur_dynopts_jen_order = random_opts_jen_order
    else:
      raise RuntimeError()

    jen_dynopts = Jen(cur_dynopts_jen, cur_dynopts_jen_order)
    for njd in range(jen_dynopts.number_of_iterations()):
      cur_dynopts = jen_dynopts.iteration(njd)

      if args.dry:
        print(f'  ### dynopts for .iter {njd} (class to test = {cur_opts["class_to_test"]})')
        print(' ', cur_dynopts)
      else:
        testobj = ChainGenTest(cur_opts, cur_dynopts)
        testobj.run()
      print()
      if args.single:
        break
    if args.single:
      break
  print('all done')
  pass


if __name__ == '__main__':
  test_chaingen(sys.argv[1:])


