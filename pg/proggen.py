import argparse, random, os, sys

from c2.pg.pm_processor import PMProcessorEmpty, PMProcessor, ThreadCreationActAdder
from c2.pg.intermed import ProgramIntermed
from c2.pg.program_model import ProgramModel
from c2.pg.output_gen import PGOutputGenCppparts
from c2.pg.pm_generator import PMGeneratorEmpty, PMGeneratorAlpha, PMGeneratorFull
from c2.infra.tool_cli import ToolCLI
from c2.infra.unischema import unischema_load
from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE, textualize_seed
from c2.base.stage_runner import StageRunner
from c2.common.execcmd import execcmd

_sd = os.path.dirname(__file__)
_pg_cpp_dir = f'{_sd}/pg_cpp'
_inclroot = f'{_sd}/..'
_slashes = lambda s: s.replace('/', '\\')

class ProggenCLI(ToolCLI):
  def _initialize(self): self._progname = os.path.basename(__file__)

  def _setup_args(self):
    self._cli_seed = CLISeed(os.getcwd(), DEFAULT_SEED_SIZE)
    self._add_arg_processor(self._cli_seed)
    self._parser.add_argument('-d', '--out_dir', required=True)
    self._agr.add_config('opts', unischema_load(f'{_sd}/pgopts.UNISCHEMA', _inclroot))

  def _do_work(self):
    pgopts = self._agr.config('opts')
    seed = seed_get_or_generate(self._cli_seed, DEFAULT_SEED_SIZE)
    print(f'ProggenCLI._do_work() using seed {textualize_seed(seed)}')
    rng = random.Random(seed)
    self._proggen = Proggen(pgopts, self._args.out_dir, rng)
    self._proggen.all_stages()


### PMGenerator  ->  PMProcessor  ->  IntermedToOutput -> act_xxx, program.cpp, etc.

class Proggen(StageRunner):
  def __init__(self, pgopts, out_dir, rng):
    super().__init__()

    #TODO: validate_xxx_opts
    unischema_load(f'{_sd}/pgopts.UNISCHEMA', _inclroot).validate_instance(pgopts)

    self.opts = pgopts
    self.out_dir = out_dir
    self._rng = rng

    self._pmgen = None
    self._pm = None
    self._pmproc = None
    self._pi = None
    self._intermed_to_output = None

    self._proceed_to_next_stage(self._st_gen_pm, 'generate program model')

  def _st_gen_pm(self):
    self._pm = ProgramModel()
    self._pmgen = self._create_pm_gen()
    self._pmgen.execute()
    # result in self._pm
    self._proceed_to_next_stage(self._st_process_pm, 'generate intermediate data from model')

  def _st_process_pm(self):
    # we have self._pm from prev step, use it
    self._pi = ProgramIntermed()
    self._pmproc = self._create_pm_processor()
    self._pmproc.execute()
    self._proceed_to_next_stage(self._st_generate_program, 'generate program')

  def _st_generate_program(self):
    self._intermed_to_output = PGOutputGenCppparts(self._pi, self.out_dir, self.opts)
    self._intermed_to_output.execute()
    self._proceed_to_next_stage(None, None) # we're done

  def _create_pm_gen(self):
    pgopts = self.opts
    pm = self._pm
    if pgopts['generator'] == 'empty':
      return PMGeneratorEmpty({}, pm)
    elif pgopts['generator'] == 'alpha':
      return PMGeneratorAlpha(pgopts['alphagen'], pm)
    elif pgopts['generator'] == 'full':
      return PMGeneratorFull(pgopts['fullgen'], pm)
    else: raise RuntimeError(f'unknown generator - {pgopts["generator"]}')

  def _create_pm_processor(self):
    pgopts = self.opts
    pm, pi = self._pm, self._pi
    if pgopts['processor'] == 'empty':
      return PMProcessorEmpty(pm, pi)
    elif pgopts['processor'] == 'normal':
      return PMProcessor(pm, pi, True, 770)
    else: raise RuntimeError(f'unknown processor - {pgopts["processor"]}')






if __name__ == '__main__':
  ProggenCLI(os.path.basename(sys.argv[0]), sys.argv[1:]).execute()



