import base64, argparse, os, sys
from typing import ByteString, List, Dict, Any

from c2._internal_config import get_tmp_dir
from c2.infra.arg_processor import ArgProcessor, ArgInfo
from c2.infra.seed_db import SeedDB, _seed_db_encode
from c2.infra.seed_generate import seed_generate
from c2.infra.seed import DEFAULT_SEED_SIZE
from c2.stub_tools.create_seed_file import create_seed_file_main


class CLISeedException(Exception): pass

# To use sid as arg in cmdline, textualize it with following func
def textualize_seed(seed:str) -> str:
  # base64 returns bytes, need to .decode()
  return base64.b64encode(seed).decode()


class CLISeed(ArgProcessor):
  # by default, --seed_file is seeds file from |workdir|
  # Don't use it as default value for default_seed_size, to make code more explicit and protect from bugz.
  def __init__(self, work_dir, seed_size):
    self.work_dir = work_dir
    self.seed_size = seed_size
    self.__seed = None

  def _get_arginfos(self) -> List[ArgInfo]:
    return [
      ArgInfo(['--seed_string'], {'help': 'base64 string'}),
      ArgInfo(['--seed_section'], {}),
      ArgInfo(['--seed_file'], {})
    ]

  def _put_mentioned_parsed_args(self, argdict:Dict[str, Any]) -> None:
    self._seed_string = argdict['seed_string']
    self._seed_section = argdict['seed_section']
    self._seed_file = argdict['seed_file']
    self._validate()
    self.__seed = None
    if self._seed_string != None:
      if self._seed_section != None or self._seed_file != None:
        raise RuntimeError('seed_string can\'t be used with seed_section/seed_file')
      #self.__seed = self._seed_string.encode('ascii')
      self.__seed = base64.b64decode(self._seed_string)
      return
    if self._seed_section != None:
      assert(self._seed_string == None)
      seed_file = self._seed_file
      if seed_file == None:
        if self.work_dir != None:
          seed_file = f'{self.work_dir}/seedfile'
        else:
          raise CLISeedException('both work dir and seed file is None, can\'t process --seed_section which is set')
      # Read the database from file
      seed_db = SeedDB(self.seed_size)
      seed_db.read_from_file(open(seed_file, 'r'))
      if not self._seed_section in seed_db._seeddict:
        raise CLISeedException(f'no seed section {self._seed_section} in file {seed_file}')
      self.__seed = seed_db._seeddict[self._seed_section]
      return
    # if we got here, seed is not specified
    assert(self.__seed == None)
    return

  def is_specified(self):
    #return self._seed_string != None or self._seed_section != None
    return self.__seed != None

  def get_seed(self) -> ByteString:
    assert(self.is_specified())
    return self.__seed

  def to_argv(self):
    #delegate parsing to another CLISeed
    if self._seed_file:
      return ['--seed_file', self._seed_file, '--seed_section', self._seed_section]
    else:
      if self._seed_string:
        return ['--seed_string', self._seed_string]
      else:
        return []

  def _validate(self):
    if self._seed_file != None:
      if self._seed_section == None:
        raise CLISeedException('--seed_file needs --seed_section')
    if self._seed_string != None:
      if self._seed_section != None or self._seed_file != None:
        raise CLISeedException('--seed_string can\'t be combined with --seed_section/--seed_file')


_sd = os.path.dirname(__file__)
_work_dir = f'{get_tmp_dir()}/cli_seed/'

def _test_expect(argv, expect_seed:ByteString=None) -> CLISeed:
  cli_seed = CLISeed(_work_dir, DEFAULT_SEED_SIZE)
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  cli_seed.add_to_argparser(parser)
  args = parser.parse_args(argv)
  cli_seed.set_parsed_args(args)
  if expect_seed != None:
    # need to test
    if expect_seed != cli_seed.get_seed():
      print('SEEDS NOT EQUAL !!!')
      print('expected seed:')
      print(expect_seed)
      print('got seed:')
      print(cli_seed.get_seed())
      raise RuntimeError()
  return cli_seed


def test_cli_seed(argv):
  _seedfile = f'{_work_dir}/seedfile'

  os.makedirs(_work_dir, exist_ok=True)
  #open(_seedfile, 'w').write('sec->FILEDATA=\nsec2->FILEDATA2\n')
  #create_seed_file_main(['-o', _seedfile, '-s', 'sec', 'sec2' ])
  seed_db = SeedDB(DEFAULT_SEED_SIZE)
  seed_db._seeddict = {}
  expectedBigA = b'A'*DEFAULT_SEED_SIZE
  expectedBigB = b'B'*DEFAULT_SEED_SIZE
  seed_db._seeddict['sec'] = expectedBigA
  seed_db._seeddict['sec2'] = expectedBigB
  seed_db.write_to_file(open(_seedfile, 'w'))

  # Possible variants:
  #   (nothing); --seed_string; --seed_section; --seed_section AND --seed_file
  assert(_test_expect([]).is_specified() == False)
  _test_expect(['--seed_string', 'eHh4'], b'xxx') # base64, remember?
  _test_expect(['--seed_section', 'sec'], expectedBigA)
  _test_expect(['--seed_file', _seedfile, '--seed_section', 'sec2'], expectedBigB)
  # bad cases
  try:
    _ = _test_expect(['--seed_file', _seedfile]) # --seed_file needs --seed_section
    raise RuntimeError('not reached')
  except CLISeedException as e:
    print('expected exception:', e)
  try:
    _ = _test_expect(['--seed_section', 'sec', '--seed_string', 'xxx']) # --seed_section incompatible with --seed_string
    raise RuntimeError('not reached')
  except CLISeedException as e:
    print('expected exception:', e)


if __name__ == '__main__':
  test_cli_seed(sys.argv[1:])


