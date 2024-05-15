import os, sys
from typing import List
from functools import partial

from c2.backend import BackendFactory
from c2.infra.tool_cli import ToolCLI
from c2.infra.unischema import unischema_load
from c2.infra.dynjen_from_aggregator import dynjen_from_aggregator
from c2.infra.parse_worker import parse_worker
from c2.test.case_runner import CaseRunner
from c2.test.fix_crp_opts_for_test import fix_crp_opts_for_test
from c2.common.strlist_to_argparser import add_strlist_to_argparser, strlist_from_parsed_args


_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/..'

# #PossibleImprovements
#   !) count or print all counters from 1 so they're fitted to CUR_IDX/TOTAL form
#   !) print speed/elapsed/left
#

class CasetestCLI(ToolCLI):
  # tst_opts['limit'] is global
  # gentypes should match casegen's gentypes (example: CASEGEN_PAYTYPES for PaytestCaseGenerator)
  def __init__(self,
               argv,
               casegen,
               gentypes:List[str],
               jen_tag:str,
               repls:dict,
               progname:str):

    super().__init__(argv)
    self._casegen = casegen
    self._gentypes = gentypes
    self._jen_tag = jen_tag
    self._repls = repls
    self._progname = progname

    self._UNI_tst_opts = unischema_load(f'{_sd}/tst_opts.UNISCHEMA', None)
    self._UNI_casetest_opts = unischema_load(f'{_sd}/casetest_opts.UNISCHEMA', None)
    self._UNI_crp_opts = unischema_load(f'{_sd}/../crp_opts.UNISCHEMA', _inclroot)
    self._UNI_rnd_opts = unischema_load(f'{_sd}/../rnd_opts.UNISCHEMA', None)
    self._UNI_bld_opts = unischema_load(f'{_sd}/../bld_opts.UNISCHEMA', None)


  def _initialize(self):
    pass

  def _notes(self) -> List[str]:
    return ['Each case has crp_opts JEN sub-iters.',
            '--tst_limit is GLOBAL, for nglobal which equals to (ncase*num_jen_iters)+cur_jen_iter',
            'This test doesn\'t use TestLoopRunner, integrating tst_opts its own way']


  def _setup_args(self):
    args = self._args
    agr = self._agr
    parser = self._parser

    # add aggregated opts
    agr.add_config('tst', self._UNI_tst_opts)
    agr.add_config('opts', self._UNI_casetest_opts, jen_tag=self._jen_tag)
    agr.add_config('crpo', self._UNI_crp_opts, jen_tag=self._jen_tag)
    agr.add_config('rndo', self._UNI_rnd_opts) # not JEN!
    #agr.add_config('bldo', self._UNI_bld_opts) # No, bld_opts controlled privately in this test.

    # add gentypes as args
    add_strlist_to_argparser(self._gentypes, parser, action='store_true', help=f'Enable gentype')

    # add other args
    #parser.add_argument('--case_limit', type=int, default=-1, help='controls case counter') #now there is the only limit, tst_opts['limit'], and in this program it's global
    parser.add_argument('--no_cleanup', action='store_true')
    parser.add_argument('--dont_disable_trasher', action='store_true')
    parser.add_argument('--log_stdout', action='store_true')
    parser.add_argument('--title', required=False)


  def _do_work(self):
    args = self._args
    agr = self._agr
    tst_opts = agr.config('tst')

    chosen_paytypes = strlist_from_parsed_args(self._gentypes, args)
    if len(chosen_paytypes) == 0:
      chosen_paytypes = self._gentypes
    print('[ ] chosen paytypes (order is important):', chosen_paytypes)
    title = args.title if args.title else ''

    # Put source material to case generator
    self._casegen.set_source_material(agr.config('opts'), [], chosen_paytypes)

    total_cases = self._casegen.number_of_cases()
    # tst_opts['limit'] is global

    _dj = dynjen_from_aggregator(agr, 'crpo')
    total_crpopts = len([inst for inst in _dj]) # dry run DynJen only to count insts
    ntotalglobal = total_cases*total_crpopts
    print(f'CASETEST ({title=}): {total_cases=} {total_crpopts=}, global total {ntotalglobal}')

    self._bld_opts = {'target_configs': 'Debug,ReleaseSprayed',
                      'target_projects': 'virprog,virlib'}

    self._backend_fac = BackendFactory('class', 'normal')

    worker_index, worker_count = None, None
    if tst_opts['worker'] != '':
      worker_index, worker_count = parse_worker(tst_opts['worker'])

    ncase = 0
    nskipped = 0
    nmatched = 0
    for case in self._casegen:
      if tst_opts['limit'] != -1 and tst_opts['limit'] == ncase:
        print(f'\ntst limit {tst_opts["limit"]} has been REACHED\n')
        break

      print()
      print('~' * 80)
      print(f'CaseTest ({self._progname}, "{title}") -- CASE #{ncase}/{self._casegen.number_of_cases()}:', case)
      print('~' * 80)
      print()

      crp_opts_dynjen = dynjen_from_aggregator(agr, 'crpo')
      nglobal = ncase * total_crpopts
      ninst = 0
      for crp_opts in crp_opts_dynjen:
        skip = False
        if worker_index != None:
          assert(worker_count != None)
          if nglobal % worker_count != (worker_index-1):
            skip = True # not our part, skip it
            print(f'[skipped {nglobal=} % {worker_count} (={nglobal % worker_count}), != our part (we are {worker_index}/{worker_count})]')
        if not skip:
          nmatched += 1
          print(f'<<jen iter (case {self._progname}, "{title}")>> global #{nglobal}, total global {ntotalglobal} (case #{ncase}, total {self._casegen.number_of_cases()}; inst #{ninst}, total {total_crpopts})  [counting from 0!]  crp_opts=>', crp_opts)
          if not tst_opts['dry']:
            self._fn_dispatch_inst(case, crp_opts)
        else:
          nskipped += 1

        print()

        nglobal += 1
        ninst += 1

      if ninst != total_crpopts:
        raise RuntimeError(f'DynJen didn\'t return all the crp_opts! It returned only {ninst} of {total_crpopts} crp_opts')

      ncase += 1

    if ncase != total_cases:
      raise RuntimeError(f'Casegen didn\'t return all the cases! It returned only {ncase} of {total_cases} cases')

    print(f'casetest `{title}` done; {nmatched=} {nskipped=}')
    return


  def _fn_dispatch_inst(self, case, crp_opts):
    fix_crp_opts_for_test(crp_opts)
    caserunner = CaseRunner(self._backend_fac, case, crp_opts, self._agr.config('rndo'),
                            self._bld_opts['target_configs'].split(','),
                            log_stdout=self._args.log_stdout)
    caserunner.set_replacements(self._repls)

    if self._args.no_cleanup:
      caserunner.dont_cleanup(True)

    caserunner.run()



