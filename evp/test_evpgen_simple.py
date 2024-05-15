import os, sys

from c2._internal_config import get_tmp_dir
from c2.evp.evpgen import EVPGenCLI


_sd = os.path.dirname(__file__)
_tmpdir = f'{get_tmp_dir()}/test_evpgen_simple'

def test_evpgen_simple(argv):
  egargv = ['-t', 'template', '-o', 'outfile', '--bin_type', 'bt', '--pe', 'pe', '--no_spread_section_load']

  # all 64-bit now
  exepath = f'{_sd}/td/nc.exe'
  dllpath = f'{_sd}/td/makeidt.dll'
  testarglists = [
    ['--bin_type', 'win_shellcode'],
    ['--bin_type', 'win_exe', '--no_spread_section_load'],
    ['--bin_type', 'win_exe', '--pe', exepath],
    ['--bin_type', 'win_dll', '--no_spread_section_load'],
    ['--bin_type', 'win_dll', '--pe', dllpath],
  ]

  os.makedirs(_tmpdir, exist_ok=True)
  template_path = f'{_sd}/../cpp_parts/EVILPROC_TEMPLATE.cpp'
  outfile_path = f'{_tmpdir}/out_evilproc.cpp'
  niter = 0
  for testargs in testarglists:
    egargv = [*testargs, '--t', template_path, '-o', outfile_path]
    print(f'-- {niter=}, argv to evpgen: {egargv}')
    evpgen = EVPGenCLI(egargv)
    evpgen.execute()
    print(f'iter {niter} done')
    print()
    niter += 1

if __name__ == '__main__':
  test_evpgen_simple(sys.argv[1:])
