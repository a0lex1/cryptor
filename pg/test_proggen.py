import argparse, os, sys
import shutil

from c2._internal_config import get_tmp_dir
from c2.pg.proggen import ProggenCLI
from c2.sprayer.test.spraytest_project import SpraytestProject
from c2.infra.cli_config_aggregator import CLIConfigAggregator
from c2.infra.tool_cli import ToolCLI
from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE
from c2.infra.unischema import unischema_load


_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/..'
_testprj_dir = f'{get_tmp_dir()}/test_proggen'

class TestProggenCLI(ToolCLI):
  def _initialize(self): self._progname = os.path.basename(__file__)

  def _setup_args(self):
    self._cli_seed = CLISeed(os.getcwd(), DEFAULT_SEED_SIZE)
    self._add_arg_processor(self._cli_seed)
    #self._agr.add_config('tst', unischema_load(f'{_sd}/../test/tst_opts.UNISCHEMA', _inclroot))
    self._agr.add_config('opts', unischema_load(f'{_sd}/pgopts.UNISCHEMA', _inclroot), jen_tag='$jdefault')
    self._agr.add_config('sgopts', unischema_load(f'{_sd}/../sprayer/spraygen_opts.UNISCHEMA', _inclroot))

  def _do_work(self):
    inst = self._agr.config('opts')

    st = SpraytestProject(_testprj_dir)
    st.put(allow_exist=True)
    st.write_spraypreparebat_file(True, True)
    st.get_src_dir()

    pgsrc_dir = f'{_testprj_dir}/extra/pg'
    if os.path.exists(pgsrc_dir):
      shutil.rmtree(pgsrc_dir)
    os.makedirs(pgsrc_dir)

    pgargv = ['-d', pgsrc_dir]
    pgcli = ProggenCLI(pgargv)
    pgcli.execute()
    assert(os.path.exists(f'{pgsrc_dir}/program.cpp'))

    st.fast_compile(sprayed_build=False)
    st.run_fast_compiled_program(12340)

    st.run_tools(True, True)
    st.fast_compile(sprayed_build=True)
    st.run_fast_compiled_program(12340)





if __name__ == '__main__':
  TestProggenCLI(sys.argv[1:]).execute()


