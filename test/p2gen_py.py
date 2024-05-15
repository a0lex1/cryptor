import os

from c2._internal_config import get_cppbuild_dir

_sd = os.path.dirname(__file__)


def p2gen_gen_tbdemo(cpu:str, path:str):
  if cpu == 'intel64':
     r = os.system(f'{get_cppbuild_dir()}/p2gen64/Release/x64/p2gen64.exe gen-tbdemo {path}')
  elif cpu == 'intel86':
     r = os.system(f'{get_cppbuild_dir()}/p2gen86/Release/Win32/p2gen86.exe gen-tbdemo {path}')
  else: raise RuntimeError()
  assert(r == 0)



