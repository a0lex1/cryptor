

class OptionStringException(Exception): pass
class EmptyOptionString(OptionStringException): pass
class PrefixTooLong(OptionStringException): pass
class BadCharsInName(OptionStringException): pass
class EmptyName(OptionStringException): pass

def validate_option_string(option_string, prefix='-', max_prefix_len=-1):
  assert(type(option_string) == str)
  if 0 == len(option_string):
    raise EmptyOptionString()
  n = 0
  while n < len(option_string) and option_string[n] == prefix:
    # "if max_prefix_len is set AND it equals to n"
    if (max_prefix_len != -1) and (n == max_prefix_len):
      raise PrefixTooLong()
    n += 1
  num_chars_in_name = 0
  for c in option_string[n:]:
    #print(c)
    if not c.isalnum() and not c == '_':
      raise BadCharsInName()
    num_chars_in_name += 1
  if 0 == num_chars_in_name:
    raise EmptyName()

# Use |exception_class| = None to expect success
def _test_expect(call_args, call_kwargs, exception_class:type=None):
  try:
    validate_option_string(*call_args, **call_kwargs)
  except Exception as e:
    if type(e) != exception_class:
      print('UNEXPECTED EXCEPTION:')
      print(e)
      raise RuntimeError(f'expected {exception_class=}, caught {type(e)}')


def test_validate_option_string(argv=None):
  _test_expect([''], {}, EmptyOptionString)
  _test_expect(['a'], {})
  _test_expect(['aa'], {})
  _test_expect(['aaaaaaaaa'], {})
  _test_expect(['-'], {}, EmptyName)
  _test_expect(['--'], {}, EmptyName)
  _test_expect(['---'], {}, EmptyName)
  _test_expect(['----'], {}, EmptyName)
  _test_expect([' '], {}, BadCharsInName)# == False
  _test_expect([' -'], {}, BadCharsInName)# == False
  _test_expect(['- '], {}, BadCharsInName)# == False

  _test_expect(['-lala'], {}, None)# == False
  _test_expect(['--lala'], {}, None)# == False
  _test_expect(['---lala'], {}, None)# == False
  _test_expect(['----lala'], {}, None)# == False

  _test_expect(['-a'], {})
  _test_expect(['--a'], {})
  _test_expect(['---a'], {})
  _test_expect(['----a'], {})
  _test_expect(['----a_b'], {})

  # IMPORTANT. argparse naturally would substitute `-` to `_` (so args added as `my-duck` would be args.my_duck),
  # BUT we restrict it
  _test_expect(['----a-b'], {}, BadCharsInName)

  # Test when my prefix is too long if you know what I mean
  _test_expect(['---aaa'], {'max_prefix_len': 5})
  _test_expect(['---aaa'], {'max_prefix_len': 4})
  _test_expect(['---aaa'], {'max_prefix_len': 3})
  _test_expect(['---aaa'], {'max_prefix_len': 2}, PrefixTooLong)

  _test_expect(['--aaa'], {'max_prefix_len': 3})
  _test_expect(['--aaa'], {'max_prefix_len': 2})
  _test_expect(['--aaa'], {'max_prefix_len': 1}, PrefixTooLong)
  _test_expect(['-aaa'], {'max_prefix_len': 1})
  _test_expect(['-aaa'], {'max_prefix_len': 0}, PrefixTooLong)
  _test_expect(['aaa'], {'max_prefix_len': 0})


if __name__ == '__main__':
  test_validate_option_string()

