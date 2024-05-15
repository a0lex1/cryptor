import os
from typing import List

# operation -> 'build' | 'rebuild' | 'clear'
# vspplatforms->['x86', 'x64'] (not 'Win32')
def buildsol(sol_path, operation:str, vspconfigs:List[str], vspplatforms:List[str], single_project_name:str=None):
  verbos = True
  assert(operation in ['build', 'rebuild', 'clear'])
  for vspconfig in vspconfigs:
    for vspplatform in vspplatforms:

      xx = f' /project {single_project_name}' if single_project_name != None else ''
      cmd = f'devenv "{sol_path}" /{operation} "{vspconfig}|{vspplatform}"{xx}'
      if verbos:
        print(fr'[buildsol] executing {cmd}')

      ret_code = os.system(cmd)

      if verbos:
        print(fr'[buildsol] devenv ...\{os.path.basename(sol_path)} -> returned {ret_code}')
      if ret_code != 0:
        raise RuntimeError(f'devenv returned non-null ({ret_code})')
