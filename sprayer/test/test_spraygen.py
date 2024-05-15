import json, random, re, os, sys
from pprint import pprint
from typing import List

from c2._internal_config import get_tmp_dir
from c2.sprayer.spraygen import SpraygenCLI
from c2.sprayer.test.spraytest_project import SpraytestProject
from c2.infra.tool_cli import ToolCLI
from c2.infra.testloop_runner import TestloopRunner
from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE
from c2.infra.unischema import unischema_load
from c2.infra.dynjen_from_aggregator import dynjen_from_aggregator
from c2.infra.cli_conf_to_argv import cli_conf_to_argv
from c2.test.spraytest_project_from_billet import ProjectFromBillet


_sd = os.path.dirname(__file__)
_spraytest_dir = fr'{get_tmp_dir()}/test_spraygen'
_inclroot = f'{_sd}/../..'

_PROGS = ['testprog_stk_g_threads', ]


class TestSpraygen(ToolCLI):
  def _initialize(self):
    self._progname = os.path.basename(__file__)

  def _setup_args(self):
    agr = self._agr
    parser = self._parser

    self._cli_seed = CLISeed(os.getcwd(), DEFAULT_SEED_SIZE)
    self._add_arg_processor(self._cli_seed)

    agr.add_config('tst', unischema_load(f'{_sd}/../../test/tst_opts.UNISCHEMA', _inclroot))
    agr.add_config('opts', unischema_load(f'{_sd}/../spraygen_opts.UNISCHEMA', _inclroot), jen_tag='$jdefault')
    agr.add_config('aux', unischema_load(f'{_sd}/../spgaux_opts.UNISCHEMA', _inclroot))

    grp = parser.add_mutually_exclusive_group(required=False)
    grp.add_argument('--include_progs', nargs='*', action='append')
    grp.add_argument('--exclude_progs', nargs='*', action='append')


  def _do_work(self):
    args = self._args
    agr = self._agr

    if args.include_progs:
      self._progs = sum(args.include_progs, [])
    else:
      print('will run default progs')
      self._progs = _PROGS
    if args.exclude_progs:
      removed = 0
      for excl in sum(args.exclude_progs, []):
        self._progs.remove(excl)
        removed += 1
      print(f'excluded {removed} self._progs')
    print('[*] OK, will run these PROGS:', self._progs)

    self._aux_argv = cli_conf_to_argv('aux', agr.config('aux'))
    self._seed_argv = self._cli_seed.to_argv()

    dj = dynjen_from_aggregator(agr, 'opts')

    lr = TestloopRunner(agr.config('tst'), dj, self._fn_dispatch_inst)
    lr.run()


  def _fn_dispatch_inst(self, sgopts_inst):
    sgopts_argv = cli_conf_to_argv('opts', sgopts_inst)
    print(f'sgopts dispatcher: testing progs: {self._progs}')
    for prog in self._progs:
      assert(re.match(r'^[\w\d_]+$', prog)) #Security
      proj_from_billy = ProjectFromBillet(
        _spraytest_dir, 'test_spraygen',
        billet_cpp_file=f'{_sd}/{prog}.cpp', expect_code=770,
        spraygen_tool_extra_opts=[*sgopts_argv, *self._aux_argv, *self._seed_argv])
      proj_from_billy.prepare()
      proj_from_billy.fast_compile_and_test()


if __name__ == '__main__':
  TestSpraygen(sys.argv[1:]).execute()
