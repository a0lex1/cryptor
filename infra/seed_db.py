import base64, os, sys, json, binascii
from dataclasses import dataclass
from typing import List, Dict

from c2._internal_config import get_tmp_dir
from c2.infra.seed_generate import seed_generate


def _seed_db_encode(buffer) -> str:
  # base64 returns bytes, need to .decode()
  return base64.b64encode(buffer).decode()

def _seed_db_decode(text:str) -> bytes:
  try:
    assert(type(text) == str)
    return base64.b64decode(text)
  except binascii.Error as e:
    raise RuntimeError('bad underlying base64, exception:', e)


class SeedDB:
  def __init__(self, seed_size):
    self._seeddict = None # Dict[str, bytes]
    self.seed_size = seed_size

  def generate(self, sections:List[str]):
    self._seeddict = {}
    for secname in sections:
      self._seeddict[secname] = seed_generate(self.seed_size)

  def read_from_dict(self, src_dict, generate_where_empty=False):
    self._seeddict = self._seeddict_decode(src_dict, generate_where_empty)

  def write_to_dict(self) -> dict:
    return self._seeddict_encode(self._seeddict)


  def read_from_file(self, fp):
    self.read_from_json(fp)

  def write_to_file(self, fp):
    self.write_to_json(fp)


  def read_from_json(self, fp, generate_where_empty=False):
    encoded_seeddict = json.load(fp)
    self._seeddict = self._seeddict_decode(encoded_seeddict, generate_where_empty)

  def write_to_json(self, fp):
    encoded_seeddict = self._seeddict_encode(self._seeddict)
    json.dump(encoded_seeddict, fp, indent=2)


  def _seeddict_decode(self, encoded_dict:dict, generate_where_empty:bool):
    ret = {}
    for k, v in encoded_dict.items():
      if v != '':
        decoded = _seed_db_decode(v)
        if len(decoded) != self.seed_size:
          raise RuntimeError(f'the size {len(decoded)} is wrong, need {self.seed_size}')
        ret[k] = decoded
      else:
        ret[k] = seed_generate(self.seed_size)
    return ret

  def _seeddict_encode(self, decoded_dict:dict):
    return {k: _seed_db_encode(v) for k, v in decoded_dict.items()}


_sd = os.path.dirname(__file__)
_tmp_dir = f'{get_tmp_dir()}/seed_db'

def test_seed_db(argv):
  _seedfile = f'{_tmp_dir}/TheSeedFile'
  seedsize = 13

  os.makedirs(_tmp_dir, exist_ok=True)
  sdb = SeedDB(seedsize)
  sdb.generate(['sec1', 'sec2', 'sec3'])
  with open(_seedfile, 'w') as f:
    sdb.write_to_file(f)

  sdb = SeedDB(seedsize)
  sdb.read_from_file(open(_seedfile, 'r'))
  assert(list(sdb._seeddict.keys()) == ['sec1', 'sec2', 'sec3'])
  for key in sdb._seeddict.keys():
    value = sdb._seeddict[key]
    print(f'sec {key}, len(value) -> {len(value)}')
    assert(type(value) == bytes)
    assert(len(value) == seedsize)


if __name__ == '__main__':
  test_seed_db(sys.argv[1:])




