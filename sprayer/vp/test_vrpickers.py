import os, sys, random
from functools import partial

from c2.sprayer.vp.vrpicker_factory import create_vrpicker_factory
from c2.sprayer.vp.vrpicker import VRPicker, UsePurpose
from c2.sprayer.vp.stock import STOCK_vls1_vls
from c2.sprayer.vp.vls_shape import vls_shape_from_vls
from c2.infra.unischema import unischema_load
from c2.infra.tool_cli import ToolCLI
from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE, textualize_seed
from c2.infra.seed_get_or_generate import seed_get_or_generate
from c2.infra.dynjen_from_aggregator import dynjen_from_aggregator
from c2.infra.testloop_runner import TestloopRunner

_sd = os.path.dirname(__file__)
_inclroot = _sd+'/../..'


class VRPickersTest(ToolCLI):
  def _initialize(self): self._progname = os.path.basename(__file__)

  def _setup_args(self):
    self.__cli_seed = CLISeed(os.getcwd(), DEFAULT_SEED_SIZE)
    self._add_arg_processor(self.__cli_seed)
    self._parser.add_argument('--tests', nargs='*', action='append', choices=['seqbased', 'insular', 'linear'], help='by default, do all tests')
    self._agr.add_config('tst', unischema_load(f'{_inclroot}/test/tst_opts.UNISCHEMA', _inclroot))
    self._agr.add_config('seqbased', unischema_load(f'{_sd}/seqbased_opts.UNISCHEMA', _inclroot), jen_tag='$jdefault')
    self._agr.add_config('insular', unischema_load(f'{_sd}/insular_opts.UNISCHEMA', _inclroot), jen_tag='$jdefault')

  def _do_work(self):
    do_all_tests = False
    if not self._args.tests:
      do_all_tests = True

    seed = seed_get_or_generate(self.__cli_seed, DEFAULT_SEED_SIZE)
    self.__rng = random.Random(seed)
    print(f'<test_vrpickers.py rng probe: {self.__rng.randint(0, sys.maxsize)}>')

    self.__vls = STOCK_vls1_vls

    for vrpname in ['seqbased', 'insular']:
      if do_all_tests or (vrpname in self._args.tests):
        dj = dynjen_from_aggregator(self._agr, vrpname)
        lr = TestloopRunner(self._agr.config('tst'), dj, partial(self.__fn_dispatch_opts_inst, vrpname))
        lr.run()
        print(f'--- | Tests for VRPicker \'{vrpname}\' have passed')
      else:
        print(f'--- | SKIPPED tests for VRPicker \'{vrpname}\'')
    print('--- | ALL TESTS DONE')

  def __create_objects(self, vrpname, opts_inst):
    self.__fac = create_vrpicker_factory(vrpname)
    self.__vls_shape = vls_shape_from_vls(self.__vls)
    self.__state = self.__fac.create_vrpicker_state(self.__vls_shape)
    self.__vrpicker = self.__fac.create_vrpicker(self.__vls, self.__state, opts_inst, self.__rng)

  # bound func
  def __fn_dispatch_opts_inst(self, vrpname, opts_inst):
    # Test single picker on simple tests,
    # then single picker on manypicks test,
    # then on BOTH
    print(f'--- | Dispatching opts instance for VRPicker \'{vrpname}\'')
    self.__create_objects(vrpname, opts_inst)
    self.__test_vrpicker_simple(self.__vrpicker)

    self.__create_objects(vrpname, opts_inst)
    self.__test_vrpicker_manypicks(self.__vrpicker)

    self.__create_objects(vrpname, opts_inst)
    self.__test_vrpicker_simple(self.__vrpicker)
    self.__test_vrpicker_manypicks(self.__vrpicker)


  def __test_vrpicker_simple(self, vrpicker:VRPicker):
    rl = vrpicker.pick_value_range(UsePurpose.WRITE, 1, None)
    vrpicker.commit_picked_value_range(UsePurpose.WRITE, rl)
    rl = vrpicker.pick_value_range(UsePurpose.WRITE, 5, None)
    vrpicker.commit_picked_value_range(UsePurpose.WRITE, rl)

    rl = vrpicker.pick_value_range(UsePurpose.READ, 1, None)
    vrpicker.commit_picked_value_range(UsePurpose.READ, rl)
    rl = vrpicker.pick_value_range(UsePurpose.READ, 5, None)
    vrpicker.commit_picked_value_range(UsePurpose.READ, rl)

    # ... (same block using requested_item_count instead of requested_byte_count)
    rl = vrpicker.pick_value_range(UsePurpose.WRITE, None, 1)
    vrpicker.commit_picked_value_range(UsePurpose.WRITE, rl)
    rl = vrpicker.pick_value_range(UsePurpose.WRITE, None, 3)
    vrpicker.commit_picked_value_range(UsePurpose.WRITE, rl)

    rl = vrpicker.pick_value_range(UsePurpose.READ, None, 1)
    vrpicker.commit_picked_value_range(UsePurpose.READ, rl)
    rl = vrpicker.pick_value_range(UsePurpose.READ, None, 3)
    vrpicker.commit_picked_value_range(UsePurpose.READ, rl)


  def __test_vrpicker_manypicks(self, vrpicker:VRPicker):
    # (write 5, read 4) many times
    for i in range(100):
      rl = vrpicker.pick_value_range(UsePurpose.WRITE, 10, None)
      vrpicker.commit_picked_value_range(UsePurpose.WRITE, rl)
      rl = vrpicker.pick_value_range(UsePurpose.READ, 7, None)
      vrpicker.commit_picked_value_range(UsePurpose.READ, rl)


if __name__ == '__main__':
  VRPickersTest(sys.argv[1:]).execute()

