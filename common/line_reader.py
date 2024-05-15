import io, sys
from typing import IO


class LineReader:
  def __init__(self, stm:IO, support_comments=True):
    self._stm = stm
    self._support_comments = support_comments

  def __iter__ (self):
    return self

  def __next__ (self):
    while True:
      line = self._stm.readline()
      if line == '':
        raise StopIteration()
      line = line.rstrip()
      if not self._support_comments or not line.lstrip().startswith(';'):
        # break when all comment lines skipped
        break
    return line


def _test_with(inp_text, support_comments, expected_lines):
  stm = io.StringIO(inp_text)
  rdr = LineReader(stm, support_comments)
  got_lines = [line for line in rdr]
  if got_lines != expected_lines:
    print('*** got lines:')
    print(got_lines)
    print('*** expected lines:')
    print(expected_lines)
    raise RuntimeError('got lines != unexpected lines')


def test_line_reader(argv):
  _test_with('', False, [])
  _test_with('\n', False, [''])#####???????????????
  _test_with('hello', False, ['hello'])
  _test_with('hello\n', False, ['hello'])
  _test_with('hello\n\n', False, ['hello', ''])
  _test_with('\nhello\n\n', False, ['', 'hello', ''])
  _test_with('\nhello1\n\nhello2\nhello3', False, ['', 'hello1', '', 'hello2', 'hello3'])
  _test_with('\nhello1\n\nhello2\n;lalala\nhello3', False, ['', 'hello1', '', 'hello2', ';lalala', 'hello3'])

  _test_with('hello', True, ['hello'])
  _test_with('hello\n', True, ['hello'])
  _test_with('hello\n\n', True, ['hello', ''])
  _test_with('\nhello\n\n', True, ['', 'hello', ''])
  _test_with('\nhello1\n\nhello2\nhello3', True, ['', 'hello1', '', 'hello2', 'hello3'])
  _test_with('\nhello1\n\nhello2\n;lalala\nhello3', True, ['', 'hello1', '', 'hello2', 'hello3'])

  # edge cases with support_comments=True
  _test_with(';lalala', True, [])
  _test_with(';lalala\n', True, [])
  _test_with(';lalala\n\n', True, [''])
  _test_with(';lalala\n;test\n', True, [])
  _test_with(';lalala\nnormal\n;ooo\n', True, ['normal'])


if __name__ == '__main__':
  test_line_reader(sys.argv[1:])



