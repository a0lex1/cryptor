import argparse
from typing import List, Dict, Any

from c2.infra.arg_info import ArgInfo
from c2.infra.argparse_prediction import ArgparseNamespaceKeynamePredictorProgrammed


# A base class for building objects compatible with argparse.ArgumentParser
# Motivation to have both public and protected variants: cool to have both variants in code: you can either override add_to_argparser or override more specific _get_arginfos
# e.g. this is a kind of flexibility reservation
class ArgProcessor:
  # public interface; only <calling add_argument() with named args> are conceptually allowed (you should have conscience so this thing works)
  def add_to_argparser(self, parser:argparse.ArgumentParser):
    # default implementation (aggregate _get_arginfos)
    arginfos = self._get_arginfos()
    self.__mentioned = {} # {'testopt1': '<marker>', 'file_format': '<marker>', } Order important!
    for arginfo in arginfos:
      arginfo.validate_option_strings()
      arginfo.validate_addargument_kwargs()

      # Predict key name in parse_args() result namespace. How would argparse pick it?
      # The concept here is to try to stick to its public, but not
      # documented (for shortness IMHO) part. Was investigated manually
      # with testing.
      # Programmed predictor is faster (?).
      keyname_predictor = ArgparseNamespaceKeynamePredictorProgrammed()
      keyname = keyname_predictor.predict(arginfo.option_strings)

      ret = parser.add_argument(*arginfo.option_strings, **arginfo.addargument_kwargs)
      # ret is ignored
      if keyname in self.__mentioned:
        raise RuntimeError(f'duplicate {keyname=}')
      self.__mentioned[keyname] = '<marker>' # remember we've seen |keyname|, using dict cuz we want a hash table behind to speed up

  # only working with your private args are conceptually allowed. working with args not mentioned in add_to_argparser is a sin (you should have consience so this thing works)
  def set_parsed_args(self, args):
    # default implementation (aggregate _put_mentioned_parsed_args)
    argdict = {}
    for keyname in self.__mentioned:
      # the check of the both conditions is encapsulated in set_parsed_args. _put_mentioned_parsed_args gets guarantee that the key exists (value can be None) - in opposite to 'seems these two are both required conds' in cli_config_aggregator.py
      if keyname in args.__dict__ and args.__dict__[keyname] != None:
        argdict[keyname] = args.__dict__[keyname]
      else:
        argdict[keyname] = None
    self._put_mentioned_parsed_args(argdict)

  # protected funcs; called by public interface; physically restricts anything except .add_argument() to parser (we don't provide |parser|, we only describe vectors of arguments to parser.add_argument and call add_argument ourselves
  def _get_arginfos(self) -> List[ArgInfo]:
    raise NotImplementedError()

  # physically restricts anything than args mentioned in _get_arginfos() by building new |args| not including any others to it
  # argdict contains all mentioned args, but the values of some ones can be None(s) (in opposite to 'seems these two are both required conds' in cli_config_aggregator.py)
  def _put_mentioned_parsed_args(self, argdict:Dict[str, Any]) -> None:
    raise NotImplementedError()



class _TestArgProcessor(ArgProcessor):
  def _get_arginfos(self) -> List[ArgInfo]:
    return [ArgInfo(['-x', '--xavier'], {'type': int}),
            ArgInfo(['-y', '--you'], {'help': 'gay', 'type': str}), ]

  def _put_mentioned_parsed_args(self, argdict:Dict[str, Any]):
    # Did we just catch bug here? Is order guaranteed? Dict(s) are ordered in python since some version, right?
    # We fixed order by fixing ArgProcessor.__menitioned, so it should work now
    assert(list(argdict.keys()) == ['xavier', 'you']) # ensure nothing more than these two elements

    assert(not 'parsed_args' in self.__dict__)
    self.parsed_args = {}
    assert('parsed_args' in self.__dict__)
    
    self.parsed_args['xavier'] = argdict['xavier']
    self.parsed_args['you'] = argdict['you']



def _test_with(argv:List[str], expect_parsed_args:Dict[str, Any]):
  pr = _TestArgProcessor()
  parser = argparse.ArgumentParser()
  pr.add_to_argparser(parser)
  args = parser.parse_args(argv)
  pr.set_parsed_args(args)
  if pr.parsed_args != expect_parsed_args:
    print('Expected args:')
    print(expect_parsed_args)
    print('Got args:')
    print(pr.parsed_args)
    raise RuntimeError('pr.parsed_args != expected_parsed_args, see log!')


def test_arg_processor(argv=None):
  _test_with(['-x', '123', '-y', 'dumbass'], {'xavier': 123, 'you': 'dumbass'})
  _test_with(['--xavier', '123', '-y', 'dumbass'], {'xavier': 123, 'you': 'dumbass'})
  _test_with(['--xavier', '123', '--you', 'dumbass'], {'xavier': 123, 'you': 'dumbass'})


if __name__ == '__main__':
  test_arg_processor()














