import json, re, random, argparse, os, sys

from c2._internal_config import get_tmp_dir
from c2.trasher.trash_add import TrashAddCLI
from c2.sprayer.test.spraytest_project import SpraytestProject
from c2.infra.tool_cli import ToolCLI
from c2.infra.cli_conf_to_argv import cli_conf_to_argv
from c2.infra.unischema import unischema_load


_sd = os.path.dirname(__file__)
_tmpdir = f'{get_tmp_dir()}/test_trash_add'
_test_touchprj_dir = f'{_sd}/td/test_touchprj'

_input_spraytab = f'{_sd}/td/test_spraytab.json'
_output_spraytab = f'{_tmpdir}/trashed_spraytab.json'


def _get_libs_from_spraytab(spraytab):
  if not 'libs' in spraytab:
    return []
  ret_libs = []
  for pragma_comment_lib_line in spraytab['libs']:
    m = re.match('#pragma comment\(lib,\s*"(.+?)"\)', pragma_comment_lib_line)
    if not m:
      raise RuntimeError(f'not a program comment(lib, ) line - {pragma_comment_lib_line}')
    #if not m:
    #  continue
    ret_libs.append(m[1])
  return ret_libs

def _test_with(targv):
  st = SpraytestProject(_tmpdir, 'test_trash_add')
  st.put(allow_exist=True)

  TrashAddCLI(targv).execute()

  modified_spraytab = json.load(open(_output_spraytab))
  st.init_from_spraytab(modified_spraytab)
  # <Can't compile projects created from spraytab (e.g. with no source) with sprayed_build=False>
  st.write_spraypreparebat_file(False, True)
  st.run_tools(False, True)
  #pragma comment(lib, "wsock32.lib")
  libs_from_spraytab = _get_libs_from_spraytab(modified_spraytab)
  extra_cl_args = libs_from_spraytab + ['/DSECURITY_WIN32']
  st.fast_compile(sprayed_build=True, extra_cl_args=extra_cl_args) #sspi.h needs this
  st.run_fast_compiled_program()

# we host special tests in this file. this is a second entry point with its own argv
def test_trash_special_main(argv):
  _inpst, _outst = _input_spraytab, _output_spraytab
  _test_with([*argv, '-i', _inpst, '-o', _outst, '--opts_use_all', 'true'])
  _test_with([*argv, '-i', _inpst, '-o', _outst, '--opts_trash_percent_sx', '0'])
  #_test_with([*argv, '-i', _inpst, '-o', _outst, '--opts_trash_percent_sx', '1'])
  _test_with([*argv, '-i', _inpst, '-o', _outst, '--opts_trash_percent_sx', '49'])
  #_test_with([*argv, '-i', _inpst, '-o', _outst, '--opts_trash_percent_sx', '99'])
  _test_with([*argv, '-i', _inpst, '-o', _outst, '--opts_trash_percent_sx', '100'])
  _test_with([*argv, '-i', _inpst, '-o', _outst, '--opts_trash_percent_sx', '0..100'])
  #_test_with([*argv, '-i', _inpst, '-o', _outst, '--opts_trash_percent_sx', '1..100'])
  #_test_with([*argv, '-i', _inpst, '-o', _outst, '--opts_trash_percent_sx', '100..100'])

_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/..'

class TestTrashAddMainCLI(ToolCLI):
  def _initialize(self): self._progname = os.path.basename(__file__)

  def _setup_args(self):
    self._agr.add_config('opts', unischema_load(f'{_sd}/trasher_opts.UNISCHEMA', _inclroot))
    self._parser.add_argument('--special', action='store_true')
    self._parser.add_argument('--real_touchprj', action='store_true')

  def _do_work(self):
    if self._args.special:
      return test_trash_special_main(['--touchprj_dir', _test_touchprj_dir])
    xtraargs = []
    if not self._args.real_touchprj:
      # if not real, use touchprj from test data dir (td)
      xtraargs = ['--touchprj_dir', _test_touchprj_dir]
      print('******* using td/test_touchprj *******')
    else:
      print('******* USING REAL touchprj *******')
    opts_argv = cli_conf_to_argv('opts', self._agr.config('opts'))
    assert(not '-i' in opts_argv)
    assert(not '-o' in opts_argv)
    _test_with([*xtraargs, '-i', _input_spraytab, '-o', _output_spraytab, *opts_argv])


if __name__ == '__main__':
  TestTrashAddMainCLI(sys.argv[1:]).execute()

