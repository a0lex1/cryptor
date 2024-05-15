import random, os, sys
from dataclasses import dataclass
from typing import List, Tuple

from c2.evp.sec_mem_chars import SecMemChars
from c2.evp.page_prot import PageProt
from c2.evp.prot_logic import SecProtLogic
from c2.evp.prot_logic_gen import SecProtLogicGen
from c2.evp.prot_logic_checker import ProtLogicChecker
from c2.evp.getprot import getprot
from c2.infra.tool_cli import ToolCLI
from c2.infra.testloop_runner import TestloopRunner
from c2.infra.dynjen_from_aggregator import dynjen_from_aggregator
from c2.infra.unischema import unischema_load


_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/../..'

class TestProtLogicCLI(ToolCLI):
  def _initialize(self):
    self._progname = os.path.basename(__file__)

  def _setup_args(self):
    self._agr.add_config('tst', unischema_load(f'{_sd}/../test/tst_opts.UNISCHEMA', _inclroot))
    self._agr.add_config('opts', unischema_load(f'{_sd}/protlogic_opts.UNISCHEMA', _inclroot),
                         jen_tag='$jSecProtTest')

  def _do_work(self):
    rng = random.Random()

    testsecs_stock = [
      [SecMemChars.IMAGE_SCN_MEM_EXECUTE|SecMemChars.IMAGE_SCN_MEM_READ,
       SecMemChars.IMAGE_SCN_MEM_READ,
       SecMemChars.IMAGE_SCN_MEM_READ|SecMemChars.IMAGE_SCN_MEM_WRITE,
       ],
    ]

    dj = dynjen_from_aggregator(self._agr, 'opts')

    def fn_dispatch_inst(protlogic_opts):
      for testsecs in testsecs_stock:
        logic = SecProtLogic()
        gen = SecProtLogicGen(logic, testsecs, protlogic_opts, rng)
        gen.prnfn = print
        gen.generate()
        tester = ProtLogicChecker(testsecs, logic, protlogic_opts)
        tester.check()
        print('logic checked')

    lr = TestloopRunner(self._agr.config('tst'), dj, fn_dispatch_inst)
    lr.run()



if __name__ == '__main__':
  TestProtLogicCLI(sys.argv[1:]).execute()



