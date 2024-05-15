import sys

def string_repl_positions(s, positions, replacements):
  ret = ''
  assert (len(positions) == len(replacements))
  x = 0
  for i in range(len(positions)):
    start, end = positions[i]
    cut1 = s[x:start]
    if i == len(positions) - 1:  # last iter?
      cut2 = s[end:]
    else:
      next_start, next_end = positions[i + 1]
      cut2 = s[end:next_start]
    ret += cut1
    ret += replacements[i]
    x = end
  ret += s[x:] # the rest of string if present
  return ret


def _test_string_repl_positions():
  def _chk(s1, s2):
    if s1 != s2:
      print('STRINGS NOT EQUAL')
      print('got:      ' + s1)
      print('expected: ' + s2)
      raise RuntimeError()
    else:
      print('OK: ' + s1)

  s = string_repl_positions('0123456789ABCDEF', [(2, 3), (6, 9)], ['lol', 'fuck']) # SOME
  _chk(s, '01lol345fuck9ABCDEF')

  s = string_repl_positions('0123456789ABCDEF', [], []) # NOTHING
  _chk(s, '0123456789ABCDEF')

  s = string_repl_positions('0123456789ABCDEF', [(0, 16)], ['fu']) # ALL
  _chk(s, 'fu')

def test_common_string_repl_positions(argv):
  _test_string_repl_positions()

if __name__ == '__main__':
  test_common_string_repl_positions(sys.argv[1:])





