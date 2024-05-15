import sys
from c2.common.jpath import *

def cli_conf_to_argv(confname:str, conf:dict):
  paths, paths_underscore = [], [] # [ 'opts_b_d', '', ]
  # we can't use '_' only, because we're leveraging on jpath_get_s() which splits path. '.' is ok to use as splitter cuz it can't be met in opt name
  # so we need two variants of paths
  jpath_enum_s(conf, paths, JPathEnumFlag.ENUM_VALUES) # default jpath's '.'
  jpath_enum_s(conf, paths_underscore, JPathEnumFlag.ENUM_VALUES, joinchar='_') # our underscore
  assert(len(paths) == len(paths_underscore))
  argv = []
  for npath in range(len(paths)):
    path = paths[npath]
    val = jpath_get_s(conf, path)
    if type(val) == str or type(val) == int:
      vl = [ str(val) ]
    elif type(val) == bool:
      vl = [ 'true' if val else 'false' ]
    elif type(val) == list:
      vl = [ str(x) for x in val ]
    else:
      raise RuntimeError(f'unknown type(val) - {type(val)}')
    path_underscore = paths_underscore[npath]
    argv += [ '--'+confname+'_'+path_underscore, *vl]
  return argv


def _expect(confname, conf:dict, expected_argv:list):
  argv = cli_conf_to_argv(confname, conf)
  if argv != expected_argv:
    print(f'UNEXPECTED ARGV\nEXPECTED: {expected_argv}\nGOT: {argv}')
    raise RuntimeError('unexpected argv')

def _test():
  #   string number bool
  _expect('opts', {'a': 1,'b': {'c': 2}}, ['--opts_a', '1', '--opts_b_c', '2'])

  _expect('opts', {'a': 1,'b': {'c': 'demostr', 'd': True, 'e': False}},
          ['--opts_a', '1', '--opts_b_c', 'demostr', '--opts_b_d', 'true', '--opts_b_e', 'false'])
  pass

def test_cli_conf_to_argv(argv):
  _test()

if __name__ == '__main__':
  test_cli_conf_to_argv(sys.argv[1:])

