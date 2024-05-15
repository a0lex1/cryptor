import argparse
from typing import List


class ArgparseNamespaceKeynamePredictor:
  def predict(self, option_strings: List[str]) -> str:
    raise NotImplementedError()



def _count_prefix_chars(optname:str):
  stop_count = False
  n = 0
  for i in range(len(optname)):
    if optname[i] == '-':
      if not stop_count:
        n += 1
    elif optname[i].isalnum() or optname[i] == '_':
      # good char
      stop_count = True
    else:
      raise RuntimeError(f'bad char in optname - `{optname[i]}` ({optname=}')
  if not stop_count:
    if n == 0:
      raise RuntimeError('empty optname')
    else:
      raise RuntimeError('no chars detected after prefix')
  return n



def _test_count_prefix_chars():
  #assert(_count_prefix_chars('') == -119) # raise 'empty optname'
  assert (_count_prefix_chars('a') == 0)
  assert (_count_prefix_chars('aa') == 0)
  assert (_count_prefix_chars('aaa') == 0)
  assert (_count_prefix_chars('-a') == 1)
  assert (_count_prefix_chars('-aa') == 1)
  assert (_count_prefix_chars('-aaa') == 1)
  assert (_count_prefix_chars('--a') == 2)
  assert (_count_prefix_chars('--aa') == 2)
  assert (_count_prefix_chars('--aaa') == 2)
  assert (_count_prefix_chars('---aaa') == 3)
  assert (_count_prefix_chars('----aaa') == 4)
  assert (_count_prefix_chars('AbcdEfg12345_324kleoP') == 0)
  assert (_count_prefix_chars('-AbcdEfg12345_324kleoP') == 1)
  assert (_count_prefix_chars('--AbcdEfg12345_324kleoP') == 2)
  assert (_count_prefix_chars('---AbcdEfg12345_324kleoP') == 3)



class ArgparseNamespaceKeynamePredictorEmulate(ArgparseNamespaceKeynamePredictor):
  def predict(self, option_strings: List[str]) -> str:
    parser = argparse.ArgumentParser()
    parser.add_argument(*option_strings, help='no help for bad people', default='DetectMe')
    if _count_prefix_chars(option_strings[0]) == 0:
      # 0 prefix chars means it's a POSITIONAL arg
      # we need to specity some dummy value in cmdline for it
      dummyargs = ['DoesNotMatter']
    else:
      # named args; don't specify them - we have default='DetectMe'
      dummyargs = []
    args = parser.parse_args(dummyargs)
    if len(args.__dict__) != 1:
      raise RuntimeError('need 1 element')
    return list(args.__dict__.keys())[0]




class ArgparseNamespaceKeynamePredictorProgrammed(ArgparseNamespaceKeynamePredictor):
  # Three or more prefixes is disallowed! E.g. if --- found, exception raised
  # option_strings -> ['-l', '--logging']
  # option_strings -> ['positional_args']
  def predict(self, option_strings: List[str]) -> str:
    # e.g. we need FIRST arg with --; if there is no one, use first with -
    if len(option_strings) == 0:
      raise RuntimeError('argparse wouldn\'t let you use empty *args in add_argument() call')
    if not option_strings[0].startswith('-'):
      # this is POSITIONAL arg, disallow any other items
      if len(option_strings) != 1:
        raise RuntimeError('first arg is positional, no more option_strings items allowed')
      # handle positional arg
      return option_strings[0]
    else:
      # The name of the option starts with '-'. This is named arg, check its other alias(es) (second item and others)
      # !) we are looking for double prefix (an option with double prefix overrides an option with single prefix)
      # !) no positional args, e.g. all further opts should be prefixed with - or --
      # !) we DISALLOW --- and more char prefixes, because it's too complex to find out how argparse manages it
      # !) we DISALLOW (by not handling it) prefixes made from chars other than '-' (e.g. ++, etc. - although argparse supports it)
      cur_keyname = None
      cur_pref_char_count = None
      for noptstr in range(0, len(option_strings)):
        optname = option_strings[noptstr]
        pref_char_count = _count_prefix_chars(optname)
        assert(pref_char_count > 0)
        if pref_char_count > 2:
          raise RuntimeError('more than two chars in prefix is conceptually disallowed')
        assert(pref_char_count == 1 or pref_char_count == 2)

        if cur_pref_char_count == None or pref_char_count > cur_pref_char_count:
          # Override if more chars in prefix (actually limited to 2)
          cur_keyname = optname.lstrip('-')
          cur_pref_char_count = pref_char_count

        if pref_char_count == 2:
          # We met -- option, override cur_keyname. In our concept, there is nothing that can
          # override double char prefix (--). Exit the loop.
          break
      # Done looping through option strings, cur_keyname contains the final option name
      return cur_keyname
    raise RuntimeError('NOT REACHED')




def _test_eq_two_predictors(option_strings:List[str], expected_optname):
  print('_test_eq_two_predictors(). ------------')
  p1 = ArgparseNamespaceKeynamePredictorEmulate()
  p2 = ArgparseNamespaceKeynamePredictorProgrammed()
  optname_emul = p1.predict(option_strings)
  optname_prg = p2.predict(option_strings)
  err = False
  if optname_emul != expected_optname:
    err = True
    print(f'ERROR!!! !!! {optname_emul=} != {expected_optname=}')
  else:
    print(f'OK! {optname_emul=} IS AS EXPECTED')
  if optname_prg != expected_optname:
    err = True
    print(f'ERROR!!! !!! {optname_prg=} != {expected_optname=}')
  else:
    print(f'OK! {optname_prg=} IS AS EXPECTED')
  if err:
    raise RuntimeError('see log')


def _test_predict_argparse_namespace_keyname():
  _test_eq_two_predictors(['-x', '-a', '-b', '-c'], 'x')
  _test_eq_two_predictors(['a'], 'a')
  _test_eq_two_predictors(['--x'], 'x')
  _test_eq_two_predictors(['--x', '-a'], 'x')
  _test_eq_two_predictors(['-a', '--x'], 'x')
  _test_eq_two_predictors(['--u', '--o', '--p'], 'u')
  _test_eq_two_predictors(['--u', '-a', '--i'], 'u')
  _test_eq_two_predictors(['-e', '--u', '-a', '--i'], 'u')


def test_argparse_prediction(argv=None):
  _test_count_prefix_chars()
  _test_predict_argparse_namespace_keyname()


if __name__ == '__main__':
  test_argparse_prediction()

