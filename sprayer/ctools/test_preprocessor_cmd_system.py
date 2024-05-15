import sys
from typing import List, Tuple

from c2.sprayer.ctools.preprocessor_cmd_system import PreprocessorCmdSystem, CmdInfo, SubcommandDepthLimitReached, UnknownControlCommand, UnclosedCommands, WrongNumberOfArguments
from c2.sprayer.ctools.macro_follower import MacroFollower
from c2.sprayer.ctools.preprocessor_cmd_system import PreprocessorCmdSystem


class TestPreprocCmdSystem(PreprocessorCmdSystem):
  def __init__(self, max_depth, open_minmax_args: Tuple[int, int], close_minmax_args: Tuple[int, int],
               macro_follower:MacroFollower, control_chars, skip_comments):
    super().__init__(macro_follower, control_chars, skip_comments)
    if open_minmax_args == None:
      open_minmax_args = (None, None)
    if close_minmax_args == None:
      close_minmax_args = (None, None)
    self.__max_depth = max_depth
    self.__open_minmax_args = open_minmax_args
    self.__close_minmax_args = close_minmax_args
    self.history = []

  def _setup(self):
    self._set_max_subcommand_depth(self.__max_depth)
    self._register_cmd_pair(CmdInfo('open', self.__open_minmax_args[0], self.__open_minmax_args[1]),
                            CmdInfo('close', self.__close_minmax_args[0], self.__close_minmax_args[1]))

  # text msg name contains part after _cmdsys_xxx_, e.g. _cmdsys_handle_outside_line -> outside_line
  def _cmdsys_handle_outside_line(self, line):
    self.history.append(f'outside_line:{line}')

  def _cmdsys_handle_inside_line(self, line):
    self.history.append(f'inside_line:{line}')

  def _cmdsys_opencmd_hook(self, macro_name, macro_opts):
    self.history.append(f'opencmd_hook:{macro_name}')

  def _cmdsys_closecmd_hook(self, macro_name, macro_opts):
    self.history.append(f'closecmd_hook:{macro_name}')



def _verify_hist(cmdsys, expected_history):
  if cmdsys.history != expected_history:
    print('expected history:')
    print(expected_history)
    print('got history:')
    print(cmdsys.history)
    raise RuntimeError('unexpected history, see log')

def _expect_exception(max_depth, lines:List[str], expected_exception_class,
                      open_minmax_args=None, close_minmax_args=None,
                      control_chars='@@@', skip_comments=True):
  mf = MacroFollower()
  cmdsys = TestPreprocCmdSystem(max_depth, open_minmax_args, close_minmax_args, mf, control_chars, skip_comments)
  cmdsys.initialize()
  try:
    for line in lines:
      cmdsys.input_line(line)
    cmdsys.finalize()
  except (SubcommandDepthLimitReached, UnknownControlCommand, UnclosedCommands, WrongNumberOfArguments) as e:
    if type(e) != expected_exception_class:
      raise RuntimeError('expected exception, but with wrong type')
    # OK
    return
  raise RuntimeError('expected exception not ocurred')

def _expect_success(max_depth, lines:List[str], expected_history,
                    open_minmax_args=None, close_minmax_args=None,
                    control_chars='@@@', skip_comments=True):
  mf = MacroFollower()
  cmdsys = TestPreprocCmdSystem(max_depth, open_minmax_args, close_minmax_args, mf, control_chars, skip_comments)
  cmdsys.initialize()
  for line in lines:
    cmdsys.input_line(line)
  cmdsys.finalize()
  _verify_hist(cmdsys, expected_history)


_test_lines0 = ['a\n', 'b\n', 'c\n', 'd\n']
_test_lines1 = ['a\n', 'b\n', '//@@@open /apple 1 /banana 2\n', 'INSIDE1\n', '//@@@close\n', 'c\n']
_test_lines2 = [
  'a\n',
  'b\n',
  '//@@@open\n',
  '//@@@open\n',
  'INSIDE2\n',
  '//@@@close\n',
  '//@@@close\n',
  'c\n'
]
_test_lines_bad = ['a\n', '//@@@nonexisting_cmd\n', '//@@@endnonexisting_cmd\n']
_test_lines_cmnt = [
  'a\n',
  '\n',
  '//\n',
  '  //  \n',
  '   //     aaa   \n',
  'b\n'
]
_test_lines_unclosed0 = ['//@@@open\n', 'test line\n']
_test_lines_unclosed1 = ['//@@@open\n', 'test line']

_test_lines_withargs1 = ['abc\n', '//@@@open /a 1\n', '//@@@close /a 1\n', 'xyz\n']
_test_lines_withargs2 = ['abc\n', '//@@@open /a 1 /b 2\n', '//@@@close /a 1 /b 2\n', 'xyz\n']
_test_lines_withargs3 = ['abc\n', '//@@@open /a 1 /b 2 /c 3\n', '//@@@close /a 1 /b 2 /c 3\n', 'xyz\n']


def _test():
  _expect_success(0, _test_lines0, ['outside_line:a', 'outside_line:b', 'outside_line:c', 'outside_line:d'])
  _expect_success(1, _test_lines0, ['outside_line:a', 'outside_line:b', 'outside_line:c', 'outside_line:d'])

  _expect_exception(0, _test_lines1, SubcommandDepthLimitReached)
  _expect_success(1, _test_lines1, ['outside_line:a', 'outside_line:b', 'opencmd_hook:open', 'inside_line:INSIDE1', 'closecmd_hook:close', 'outside_line:c'])
  _expect_success(2, _test_lines1, ['outside_line:a', 'outside_line:b', 'opencmd_hook:open', 'inside_line:INSIDE1', 'closecmd_hook:close', 'outside_line:c'])

  _expect_exception(1, _test_lines2, SubcommandDepthLimitReached)

  _expect_exception(999, _test_lines_bad, UnknownControlCommand)

  # test comments elimination
  _expect_success(2, _test_lines_cmnt, ['outside_line:a', 'outside_line:b'])
  _expect_success(2, _test_lines_cmnt, ['outside_line:a', 'outside_line://', 'outside_line://', 'outside_line://     aaa', 'outside_line:b'], skip_comments=False)

  # unclosed
  _expect_exception(999, _test_lines_unclosed0, UnclosedCommands)
  _expect_exception(999, _test_lines_unclosed1, UnclosedCommands)

  # minmax args
  _expect_success(1, _test_lines_withargs1,
                  ['outside_line:abc', 'opencmd_hook:open', 'closecmd_hook:close', 'outside_line:xyz'],
                  open_minmax_args=(1, 2), close_minmax_args=(1, 2))
  _expect_exception(1, _test_lines_withargs1,
                    WrongNumberOfArguments,
                    open_minmax_args=(2, 3), close_minmax_args=(2, 3))
  _expect_exception(1, _test_lines_withargs2, WrongNumberOfArguments, open_minmax_args=(3, 5), close_minmax_args=(3, 5))
  _expect_exception(1, _test_lines_withargs2, WrongNumberOfArguments, open_minmax_args=(0, 1), close_minmax_args=(0, 1))


def test_preprocessor_cmd_system(argv):
  _test()


if __name__ == '__main__':
  test_preprocessor_cmd_system(sys.argv[1:])


