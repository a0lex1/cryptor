import os, sys, random, argparse

from c2._internal_config import get_tmp_dir
from c2.backend import Backend, BackendFactory, BackendArgs, backend_shortcut_names
from c2.cryptor import CryptorFactory
from c2.infra.unischema import unischema_load
from c2.test.fix_crp_opts_for_test import fix_crp_opts_for_test
from c2.test.p2gen_py import p2gen_gen_tbdemo
from c2.common.parse_scheme_address import parse_scheme_address


_sd = os.path.dirname(__file__)
_tmp_dir = f'{get_tmp_dir()}/test_backend'

def test_backend_main(argv):
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('--backend', default='class://normal')
  parser.add_argument('--bla', required=False)
  #parser.add_argument('--no_cleanup', action='store_true')
  args = parser.parse_args(argv)

  backname, backinitstr = parse_scheme_address(args.backend)
  backfac = BackendFactory(backname, backinitstr)

  os.makedirs(_tmp_dir, exist_ok=True)
  tbdemo64_path = f'{_tmp_dir}/tbdemo64.bin'
  p2gen_gen_tbdemo('intel64', tbdemo64_path)

  def_pay_info = unischema_load(f'{_sd}/../pay_info.UNISCHEMA', f'{_sd}/..').make_default_config()
  bld_opts = { 'target_configs': 'Debug',
               'target_projects': 'virprog' }
  crp_opts = unischema_load(f'{_sd}/../crp_opts.UNISCHEMA', f'{_sd}/..').make_default_config()
  fix_crp_opts_for_test(crp_opts)
  rnd_opts = unischema_load(f'{_sd}/../rnd_opts.UNISCHEMA', f'{_sd}/..').make_default_config()

  backend = backfac.create_backend(
    BackendArgs(tbdemo64_path,
                {**def_pay_info, 'bin_type': 'win_shellcode', 'cpu': 'intel64' },
                crp_opts,
                rnd_opts,
                bld_opts))

  backend.do_init()
  open(f'{backend.get_evil_dir()}/BLABLA' ,'w').write('this file is to test that we can create evil dir, THEN put some files, THEN execute cryptor. This order is useful.')
  try:

    backend.do_crypt(f'{backend.get_evil_dir()}/cryptor.log')

  except Exception as e:
    print('****** EXCEPTION:', e)
    raise
  finally:
    #if not args.no_cleanup:
    #  print('[ ! ] FINALLY: doing do_clear() ...')
    #  backend.do_clear()
    pass
  print('test done')


# *** NOT ADDED TO TESTS ***
if __name__ == '__main__':
  test_backend_main(sys.argv[1:])



