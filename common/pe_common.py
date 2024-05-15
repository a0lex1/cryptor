import pefile, sys

from typing import List, Tuple

def pe_get_exports(filename) -> List[Tuple[str, str]]:
  d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
  pe = pefile.PE(filename, fast_load=True)
  pe.parse_data_directories(directories=d)
  exports = [(e.ordinal, e.name, e.address) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
  return exports

def pe_get_export_rva(filename, exp_func_name):
  exports = pe_get_exports(filename)
  for ordinal, name, address in exports:
    if name == exp_func_name.encode('ascii'):
      return address
  raise RuntimeError(f'PE export not found - {exp_func_name}')

def _test():
  rva = pe_get_export_rva(r'C:\windows\system32\kernel32.dll', 'CloseHandle')
  print(f'* * * RVA of CloseHandle in kernel32.dll is {rva:x}')
  assert(rva > 0 and rva < 0xffff000000000000) # finger in the sky, but guaranteed to work

def test_common_pe_common(argv):
  _test()

if __name__ == '__main__':
  test_common_pe_common(sys.argv[1:])

