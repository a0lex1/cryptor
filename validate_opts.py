import os, sys

from c2.infra.unischema import Unischema, unischema_load
from c2.common.sx import Sx


_sd = os.path.dirname(__file__)

def validate_pay_info(inst:dict):
  unischema_load(f'{_sd}/pay_info.UNISCHEMA', _sd).validate_instance(inst)
  ### validate export_name - idk how to put this extra check in regex
  if inst['export_name'][:1].isdigit(): # pick first character if not empty string
    raise RuntimeError('export_name cannot start with digit')

def validate_crp_opts(inst:dict):
  # children opts are on their own
  unischema_load(f'{_sd}/crp_opts.UNISCHEMA', _sd).validate_instance(inst)
  ### validate soi_mul_percent_sx
  sx = Sx(inst['soi_mul_percent_sx'])
  sx.make_number() # probe
  if sx.minimum < 0:
    raise RuntimeError('bad soi_mul_percent_sx minimum')

def validate_sys_opts(inst:dict):
  # Nothing to validate yet.
  pass

def validate_rnd_opts(inst:dict):
  unischema_load(f'{_sd}/rnd_opts.UNISCHEMA', _sd).validate_instance(inst)


def validate_bld_opts(inst:dict):
  unischema_load(f'{_sd}/bld_opts.UNISCHEMA', _sd).validate_instance(inst)



def test_validate_opts(argv):
  validate_pay_info(unischema_load(f'{_sd}/pay_info.UNISCHEMA', _sd).make_default_config())
  validate_crp_opts(unischema_load(f'{_sd}/crp_opts.UNISCHEMA', _sd).make_default_config())
  validate_rnd_opts(unischema_load(f'{_sd}/rnd_opts.UNISCHEMA', _sd).make_default_config())
  validate_bld_opts(unischema_load(f'{_sd}/bld_opts.UNISCHEMA', _sd).make_default_config())

if __name__ == '__main__':
  test_validate_opts(sys.argv[1:])
