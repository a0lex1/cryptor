import os
from c2.infra.unischema import Unischema, unischema_load

_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/..'


# every opts only validates its level. children are on their own

def validate_spraygen_opts(spraygen_opts:dict):
  unischema_load(f'{_sd}/spraygen_opts.UNISCHEMA', _inclroot).validate_instance(spraygen_opts)
  

def validate_spgaux_opts(spgaux_opts:dict):
  unischema_load(f'{_sd}/spgaux_opts.UNISCHEMA', _inclroot).validate_instance(spgaux_opts)


# TODO: fgmin_opts, df, etc.

def validate_fgfull_opts(fgfull_opts:dict):
  unischema_load(f'{_sd}/fgfull_opts.UNISCHEMA', _inclroot).validate_instance(fgfull_opts)

def validate_rgdumb_opts(rgdumb_opts:dict):
  unischema_load(f'{_sd}/rgdumb_opts.UNISCHEMA', _inclroot).validate_instance(rgdumb_opts)

def validate_rgold_opts(rgold_opts:dict):
  unischema_load(f'{_sd}/rgold_opts.UNISCHEMA', _inclroot).validate_instance(rgold_opts)

def validate_rgspray_opts(rgspray_opts:dict):
  unischema_load(f'{_sd}/rgspray_opts.UNISCHEMA', _inclroot).validate_instance(rgspray_opts)


