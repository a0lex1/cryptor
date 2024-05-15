import os, sys
from collections import OrderedDict

from c2._internal_config import get_cppbuild_dir
from c2.test.casetest import CasetestCLI
from c2.test.case import Case
from c2.test.run_info import RunInfo
from c2.test.case_generator import CaseGenerator
from c2.infra.unischema import unischema_load


_sd = os.path.dirname(__file__)

EVPTEST_GENTYPES = ['lta_exe', 'lta_dll']

class EVPTestCaseGenerator(CaseGenerator):
  def _gen_case_with_casetest_opts(self, casetest_opts): #rename to casetest_opts
    tbconf = casetest_opts['testbin_configuration']
    tbbitness = casetest_opts['testbin_bitness']
    assert (tbbitness == 32 or tbbitness == 64)

    CPPBUILD = get_cppbuild_dir()
    vsarch = 'Win32' if tbbitness == 32 else 'x64'
    lta1_exe = f'{CPPBUILD}/lta1/{tbconf}/{vsarch}/lta1.exe'
    lta1lib_dll = f'{CPPBUILD}/lta1lib/{tbconf}/{vsarch}/lta1lib.dll'

    def_pay_info = unischema_load(f'{_sd}/../pay_info.UNISCHEMA', f'{_sd}/..').make_default_config()
    def_pay_info['cpu'] = 'intel86' if tbbitness == 32 else 'intel64'

    ldrtest4exe = f'$ldrtest_dll{tbbitness}'
    ldrtest4dll = f'$ldrtest_exe{tbbitness}'

    for gentype in self._gentypes:
      if gentype == 'lta_exe':
        yield Case(gentype, {**def_pay_info, 'bin_type': 'win_exe', 'dll_evil_from_dllmain': True},
                   lta1_exe,
                   OrderedDict({
                     'virprog': RunInfo([
                       (f'{ldrtest4exe} exe $exe', 812739),
                     ]),
                     'virlib': RunInfo([
                       # Why #LoosingPayloadRetCode is not applicable in this case?
                       # Cuz this is exe inside dll. Exe's main() will do ExitProcess
                       # so DllMain never returns. This means the exit code of the process will be 812739.
                       (f'{ldrtest4dll} dll $dll', 812739),
                     ]),
                   }))
      elif gentype == 'lta_dll':
        yield Case(gentype, {**def_pay_info, 'bin_type': 'win_dll', 'dll_evil_from_dllmain': True},
                   lta1lib_dll,
                   OrderedDict({
                     'virprog': RunInfo([
                       (f'{ldrtest4exe} exe $exe', 812739), #LoosingPayloadRetCode
                     ]),
                     'virlib': RunInfo([
                       # #LoosingPayloadRetCode
                       # Why we're not checking dll ret code eq 812739 in lta_dll|virlib ? Here's why.
                       # We're using dll_evil_from_dllmain (cuz we don't have any kind of call-export option in our loader)
                       # But we can't check the return code of DllMain, cuz cpp_parts/dllmain.cpp returns TRUE
                       # instead of proxyfing the return code of the payload. The last circumstance is due to
                       # we can't always rely on what payload returns, cuz of thirdparty payloads; we need
                       # to force the ret code to TRUE. The opposite would imply DllMain have failed and is not
                       # acceptable. Another solution is to make some #define to choose whether to proxyfing the return
                       # code or not.
                       (f'{ldrtest4dll} dll $dll', 1),
                     ]),
                   }))
      else:
        raise RuntimeError(f'unknown {gentype=}')


def test_evptest_case_generator(argv):
  evptgen = EVPTestCaseGenerator()
  for case in evptgen:
    print(case)

if __name__ == '__main__':
  test_evptest_case_generator(sys.argv[1:])
