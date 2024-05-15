import os

from c2.infra.unischema import unischema_load

_sd = os.path.dirname(__file__)
_inclroot = _sd+'/../..'

def vrp_default_opts(vrpname):
  if vrpname == 'seqbased':
    return unischema_load(_sd+'/seqbased_opts.UNISCHEMA', _inclroot).make_default_config()
  elif vrpname == 'insular':
    return unischema_load(_sd+'/insular_opts.UNISCHEMA', _inclroot).make_default_config()
  else: raise
