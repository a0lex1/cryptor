import argparse, json, re, random, os, sys

from c2.trasher.touchgen import TouchgenPicker
from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE, textualize_seed
from c2.infra.seed_get_or_generate import seed_get_or_generate
from c2.infra.tool_cli import ToolCLI
from c2.infra.unischema import unischema_load
from c2.common.mix_lists import mix_lists
from c2.common.sx import Sx


# Modifies |spraytab|
# Always inserts at least one module and at least one function (line)
class TrashAdder:
  # percent_sx -> for 100%, added that much lines as already were (x2)
  def __init__(self, spraytab, trash_opts, rng, touchprj_dir=None):
    self._spraytab = spraytab
    self._opts = trash_opts
    #self._percent_sx = percent_sx
    #self._use_all = use_all
    self._rng = rng
    self._touchprj_dir = touchprj_dir
    self._picker = None

  def execute(self):
    spraytab = self._spraytab
    rng = self._rng

    total_lines = sum([len(spraytab['lines'][procname]) for procname in spraytab['lines'].keys()])

    print(f'using {self._touchprj_dir=}')
    if not self._opts['use_all']:
      sxpercent = Sx(self._opts['trash_percent_sx'], rng)
      num_lines_min = total_lines * sxpercent.minimum // 100
      num_lines_max = total_lines * sxpercent.maximum // 100
      num_lines = rng.randint(num_lines_min, num_lines_max)

      have_mods = len(TouchgenPicker.enumerate_modules(self._touchprj_dir))

      sxnum_mods = Sx(self._opts['num_mods_sx'], rng)
      #num_mods = rng.randint(1, have_mods)
      num_mods_picked = sxnum_mods.make_number()
      num_mods = min(have_mods, num_mods_picked)

      #block AAA1 was here
      average_lines_per_mod = num_lines // num_mods
      l_per_m_sx = f'0..{average_lines_per_mod*2}'
      num_mods_str = f'{num_mods}'

      print(f'{have_mods=}, using {num_mods=} (num_mods_sx={self._opts["num_mods_sx"]}, {num_mods_picked=}), {average_lines_per_mod=}')
    else:
      l_per_m_sx = None
      num_mods_str = None

      print(f'using ALL modules and functions that exist in touchprj')

    self._picker = TouchgenPicker(num_mods_str, l_per_m_sx, rng, touchprj_dir=self._touchprj_dir)
    #num_generated = len(self._picker.piece['lines'])
    # need to distribute num_generated lines to all spraytab's procs, proportionally to the size of the proc
    coeffs = []

    for nproc in range(len(spraytab['procs'])):
      procname = spraytab['procs'][nproc]
      num_proc_lines = len(spraytab['lines'][procname])
      coeffs.append(num_proc_lines / total_lines) # float; always <1; reflects size of this proc / size of all procs

    assert(len(coeffs) == len(spraytab['procs']) == len(spraytab['lines']))
    picker = self._picker
    picker.pick()
    all_picked_lines = picker.piece['lines']
    chunk_sizes = [int(coeff*len(all_picked_lines)) for coeff in coeffs]
    print(f'adding trash lines: {len(all_picked_lines)=} {[round(x,3) for x in coeffs]} {chunk_sizes=}, spraytab has {total_lines=}')
    for nproc in range(len(spraytab['procs'])):
      procname = spraytab['procs'][nproc]
      proclines = spraytab['lines'][procname]

      #we have: self._picker.piece['lines'] self._picker.piece['headers'] self._picker.piece['libs']
      chunk_size = chunk_sizes[nproc]
      chunk = all_picked_lines[:chunk_size]
      all_picked_lines = all_picked_lines[chunk_size:]

      #wrapped_lines = [f'TRASHCALL({_pl});' for _pl in chunk]

      MIN_ARGS, MAX_ARGS = 3, 6
      wrapped_lines = [f'NEVER_EXEC(((void* (__stdcall*)(...) )({_pl}))({self._make_randargs_str(MIN_ARGS, MAX_ARGS)}));/*trasher*/' for _pl in chunk]
      new_proclines = mix_lists(proclines, wrapped_lines, rng)

      spraytab['lines'][procname] = new_proclines

    spraytab.setdefault('headers', [])
    spraytab.setdefault('libs', [])
    for extra_header in picker.piece['headers']:
      if not extra_header in spraytab['headers']:
        spraytab['headers'].append(extra_header)
    for extra_lib in picker.piece['libs']:
      if not 'libs' in spraytab or not extra_lib in spraytab['libs']:
        spraytab['libs'].append(extra_lib)
    #spraytab['privdefs']['TRASHCALL(API)'] = 'NEVER_EXEC( ((void* (__stdcall*)(...) )(API))(1, 2, 3, _xarg[1]) )'
    spraytab['raw_lines'] = []


  def _make_randargs_str(self, min_args, max_args):
    num_args = self._rng.randint(min_args, max_args)
    args = []
    for _ in range(num_args):
      cho = self._rng.randint(0, 2)
      if cho == 0:
        args.append('0')
      elif cho == 1:
        args.append(str(self._rng.randint(0, 0xffffffff)))
      elif cho == 2:
        args.append('_xarg[1]')
      else:
        raise RuntimeError()
    return ', '.join(args)



_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/..'

class TrashAddCLI(ToolCLI):
  def _initialize(self): self._progname = os.path.basename(__file__)

  def _setup_args(self):
    self._agr.add_config('opts', unischema_load(f'{_sd}/trasher_opts.UNISCHEMA', _inclroot))
    self._cli_seed = CLISeed(os.getcwd(), DEFAULT_SEED_SIZE)
    self._add_arg_processor(self._cli_seed)
    self._parser.add_argument('-i', '--input_spraytab', required=True)
    self._parser.add_argument('-o', '--output_spraytab', required=True)
    self._parser.add_argument('--touchprj_dir', required=False)
    ###self._parser.add_argument('--touchprjs', nargs='*', action='append')
    ###self._parser.add_argument('--touchrep_dir', required=False)

  def _do_work(self):
    opts = self._agr.config('opts')
    seed = seed_get_or_generate(self._cli_seed, DEFAULT_SEED_SIZE)
    print(f'TrashAddCLI._do_work() using seed {textualize_seed(seed)}')
    rng = random.Random(seed)
    # spraytab is modified at place
    spraytab = json.load(open(self._args.input_spraytab, 'r'))
    trash_adder = TrashAdder(spraytab, opts, rng, touchprj_dir=self._args.touchprj_dir)
    trash_adder.execute()
    json.dump(spraytab, open(self._args.output_spraytab, 'w'),
              indent=2)


if __name__ == '__main__':
  TrashAddCLI(sys.argv[1:]).execute()


# old code in PAPERS/_trash_add_old.py.txt



