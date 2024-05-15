import os
from c2.infra.unischema import unischema_load


_sd = os.path.dirname(__file__)
_inclroot = _sd+'/../..'

def eg_default_opts(egname) -> dict:
  if egname == 'random':
    return unischema_load(_sd+'/egrandom_opts.UNISCHEMA', _inclroot).make_default_config()
  elif egname == 'bijective':
    return unischema_load(_sd+'/egbijective_opts.UNISCHEMA', _inclroot).make_default_config()
  else: raise