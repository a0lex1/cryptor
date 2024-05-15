import os, sys
from c2.infra.unischema import unischema_load


_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/..'

def _test_unischema_file(filepath, dont_test_make_default_config=False):
  unischema = unischema_load(filepath, _inclroot)

  djdoc = unischema.make_dynjen_doc()
  djsingle = unischema.make_dynjen_single()
  djschema_cli = unischema.make_jen_schema_for_cli()

  if not dont_test_make_default_config:
    djdefconf = unischema.make_default_config()
    unischema.validate_instance(djdefconf)

  djnullinst = unischema.make_null_instance()

  print(f'OK, unischema in {filepath} has been validated')


def test_all_unischemas(argv):
  root = _inclroot

  _test_unischema_file(f'{root}/test/casetest_opts.UNISCHEMA')

  _test_unischema_file(f'{root}/sprayer/rgdumb_opts.UNISCHEMA')
  _test_unischema_file(f'{root}/sprayer/spraygen_opts.UNISCHEMA')
  _test_unischema_file(f'{root}/sprayer/rgold_opts.UNISCHEMA')
  _test_unischema_file(f'{root}/sprayer/rgspray_opts.UNISCHEMA')
  _test_unischema_file(f'{root}/sprayer/fgmin_opts.UNISCHEMA')
  _test_unischema_file(f'{root}/sprayer/spgaux_opts.UNISCHEMA')

  _test_unischema_file(f'{root}/pg/fullgen.UNISCHEMA')
  _test_unischema_file(f'{root}/pg/pgopts.UNISCHEMA')
  _test_unischema_file(f'{root}/pg/alphagen.UNISCHEMA')

  _test_unischema_file(f'{root}/pay_info.UNISCHEMA')
  _test_unischema_file(f'{root}/crp_opts.UNISCHEMA')
  _test_unischema_file(f'{root}/rnd_opts.UNISCHEMA')
  _test_unischema_file(f'{root}/bld_opts.UNISCHEMA')

  _test_unischema_file(f'{root}/trasher/trasher_opts.UNISCHEMA')

  _test_unischema_file(f'{root}/evp/evp_opts.UNISCHEMA')
  _test_unischema_file(f'{root}/evp/protlogic_opts.UNISCHEMA')


if __name__ == '__main__':
  test_all_unischemas(sys.argv[1:])





