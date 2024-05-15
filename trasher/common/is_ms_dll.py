import os, sys
from pprint import pprint


# returns None if not in PATH
def locate_file_with_PATH(filename) -> str:
  paths = os.environ['PATH'].split(';')
  for path in paths:
    fullp = f'{path}/{filename}'
    if os.path.exists(fullp):
      return fullp

def is_path_in_windir(fullpath) -> bool:
  windir = os.environ['WINDIR']
  windir_real_up = os.path.realpath(windir).upper()
  fullpath_real_up = os.path.realpath(windir)
  lm = min(len(windir), len(fullpath_real_up))
  is_equal = windir[:lm] == fullpath_real_up[:lm]
  return is_equal

def is_ms_dll(filename) -> bool:
  fullpath = locate_file_with_PATH(filename)
  if fullpath == None:
    return False
  return is_path_in_windir(fullpath)

def test_is_ms_dll(argv):
  tups = [('kernel32.dll', True), ('wbemcore.dll', True), ('fufufu328932.dll', False), ]
  for dll, expect_ret in tups:
    actual_ret = is_ms_dll(dll)
    print(dll, ' is ms ->', actual_ret)
    if actual_ret != expect_ret:
      raise RuntimeError('unexpected ret')


if __name__ == '__main__':
  test_is_ms_dll(sys.argv[1:])



