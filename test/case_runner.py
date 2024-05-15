import os, sys
from typing import List, Tuple, Dict
from collections import OrderedDict

from c2._internal_config import get_tmp_dir
from c2.backend import BackendFactory, BackendArgs
from c2.infra.unischema import unischema_load
from c2.test.case import Case
from c2.test.run_info import RunInfo
from c2.test.p2gen_py import p2gen_gen_tbdemo
from c2.common.execcmd import execcmd


class CaseRunner:
  def __init__(self, backend_fac: BackendFactory, case: Case, crp_opts=None, rnd_opts=None,
               target_configs=None,
               log_stdout=False):
    self._backend_fac = backend_fac
    self._case = case
    if crp_opts == None:
      crp_opts = unischema_load(f'{_sd}/../crp_opts.UNISCHEMA', f'{_sd}/..').make_default_config()
    self._crp_opts = crp_opts
    if rnd_opts == None:
      rnd_opts = unischema_load(f'{_sd}/../rnd_opts.UNISCHEMA', None).make_default_config()
    self._rnd_opts = rnd_opts
    self._target_configs = target_configs
    self._log_stdout = log_stdout

    self._repls = None

    self._dont_clean_up = None


  # too much args in CTOR

  # repls extends the default repls which are $dll, $exe
  def set_replacements(self, repls:dict):
    self._repls = repls

  def dont_cleanup(self, dont_clean_up:bool):
    self._dont_clean_up = dont_clean_up


  def run(self):
    # case -> title pay_info file_path target_configs prj2runinfo
    case = self._case
    # the order of virlib/virprog is important
    assert(type(case.prj2runinfo) == OrderedDict)

    # backrgs -> file_path pay_info crp_opts rnd_opts bld_opts
    target_projects = list(case.prj2runinfo.keys())
    bld_opts = {'target_configs': ','.join(self._target_configs),
                'target_projects': ','.join(target_projects)}

    # we use log_stream=None and set it a bit later, after creation of backend
    backargs = BackendArgs(case.file_path, case.pay_info, self._crp_opts, self._rnd_opts, bld_opts)

    backend = self._backend_fac.create_backend(backargs)
    #backend._prnfn = print # temporary enable Backend's logging

    print('@@@ CASE RUNNER -- calling backend.do_init()')
    backend.do_init()

    print(f'@@@ CASE RUNNER -- calling backend.do_crypt(\'.../cryptor.log\', log_stdout={self._log_stdout}) ... ... ...')
    backend.do_crypt(f'{backend.get_evil_dir()}/cryptor.log', self._log_stdout)

    bin_paths = backend.get_out_bin_paths()

    # now test crypted bin(s)
    for target_config in self._target_configs:
      print(f'@@@ CASE RUNNER -- configuration {target_config}')
      for prj_to_test in case.prj2runinfo.keys():
        runinfo = case.prj2runinfo[prj_to_test]
        print(f'@@@   CASE RUNNER -- {target_config}|{prj_to_test} - {len(runinfo.shell_cmd_tups)} test commands (bin file: {bin_paths[target_config][prj_to_test]})')
        # runinfo.shell_cmd_tups
        for  shell_cmd,  expect_ret  in  runinfo.shell_cmd_tups:
          # shell_cmd can contain: $tester $exe $dll

          exe_path = bin_paths[target_config]['virprog']
          dll_path = bin_paths[target_config]['virlib']
          all_repls = {'$exe': exe_path,
                       '$dll': dll_path,
                       **self._repls}

          for macro in all_repls:
            replacement = all_repls[macro]
            while macro in shell_cmd:
              shell_cmd = shell_cmd.replace(macro, replacement)
          print(f'@@@   executing cmd [expect ret {expect_ret}] -- {shell_cmd}')

          execcmd(shell_cmd, expect_ret=expect_ret)

        print(f'@@@ All test commands executed for {target_config}|{prj_to_test}')
        print()
      print(f'@@@ All projects tested for configuration {target_config}')
      print()

    print('@@@ All configurations tested')
    if not self._dont_clean_up:
      backend.do_clear()
    else:
      print('@ CLEANUP DISABLED, FILES STILL ON DISK!')
    print('@@@ cleanup done')
    print()
    print()


_sd = os.path.dirname(__file__)
_tmp_dir = f'{get_tmp_dir()}/case_runner'
_tb64_bin = f'{_tmp_dir}/tb64.bin'
_tb86_bin = f'{_tmp_dir}/tb86.bin'

def _test_case(case):
  backend_fac = BackendFactory('class', 'normal')
  runner = CaseRunner(backend_fac, case, target_configs=['Debug'])
  runner.run()

def _test1():
  pay_info = unischema_load(f'{_sd}/../pay_info.UNISCHEMA', None).make_default_config()
  case = Case('demo case', {**pay_info, 'cpu':'intel64', 'bin_type':'win_shellcode',
                            'export_name':'DllInstall',
                            'export_decl_args': 'BOOL a1, LPWSTR a2',
                            'export_def_call_args': 'FALSE, L``'},
              _tb64_bin,
              OrderedDict({
                'virprog': RunInfo([
                  (f'$tester sc-in-exe $exe', 0),
                ])
              })
              )
  #unischema_load(f'{_sd}/../pay_info.UNISCHEMA', None).validate_instance(case.pay_info)
  _test_case(case)


def test_caserunner(argv):
  os.makedirs(_tmp_dir, exist_ok=True)
  p2gen_gen_tbdemo('intel64', _tb64_bin)
  p2gen_gen_tbdemo('intel86', _tb86_bin)
  _test1()


if __name__ == '__main__':
  test_caserunner(sys.argv[1:])



