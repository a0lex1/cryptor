import os, sys
from typing import List, Dict, Tuple


# deriveds should do _set_next_stage(None, None) to finish
class StageRunner:
  def __init__(self):
    self.__fn_next_stage = None
    self.__next_stage_name = None
    self.__flags = {}
    self.__counter = -1 # will be 0 after first proceed()

  ### interface

  # stage here means stage-to-be-executed, not stage-that-has-been-executed
  def stages_left(self) -> bool:
    return self.__fn_next_stage != None

  def stage_name(self) -> str:
    return self.__next_stage_name

  def stage_index(self): #delme
    return self.__counter


  def stage(self):
    # set all values to False before running every stage
    self.__set_flags_to_false()
    # remember old fn, we're gonna need to compare it
    oldfn = self.__fn_next_stage
    #
    # call user's handler
    #
    self.__fn_next_stage()
    # detect forget-to-set_next_stage mistake (causes dead loop)
    if self.__fn_next_stage == oldfn:
      raise RuntimeError(f'stupid programmer forget to call _proceed() at stage \'{self.__next_stage_name}\'')

  def get_flags(self) -> Dict[str, bool]:
    return self.__flags

  def get_changed_flags(self) -> List[str]:  # sugar
    return [key for key in self.get_flags().keys() if self.get_flags()[key] == True]

  ### sugar
  def all_stages(self, fn_prn=None):
    nstage = 0
    prn = lambda msg: fn_prn(msg) if fn_prn else None
    prn('running stages...')
    while self.stages_left():
      _flagshint = f' ({len(self.get_changed_flags())}/{len(self.get_flags())} flag(s) changed)' if len(
        self.get_changed_flags()) else ''
      prn(f'stage  {nstage}  {self.stage_name()}...{_flagshint}')
      self.stage()
      nstage += 1
    prn(f'all stages finished')

  ### protected for derived bros
  def _proceed_to_next_stage(self, fn_next_stage, title: str, description: str = None):
    assert (description == None)
    if not fn_next_stage:
      assert (title == None)
      assert (description == None)
    else:
      assert (type(title) == str)
    self.__fn_next_stage = fn_next_stage
    self.__next_stage_name = title
    self.__counter += 1

  def _add_flag(self, flagname):
    self.__flags[flagname] = None

  def _change_flag(self, flagname, state: bool):
    assert (flagname in self.__flags)
    assert (type(state) == bool)
    self.__flags[flagname] = state

  def _logprn(self, msg):
    raise RuntimeError('possible future will show how to better introduce this functionality')

  ### private for internal use
  def __set_flags_to_false(self):
    self.__flags = {k: False for k, _ in self.__flags.items()}


### Test code ###

class ApplePieMaker(StageRunner):
  def __init__(self):
    super().__init__()
    self._add_flag('need_to_rest')
    self._add_flag('kitchen_dirty')
    self._proceed_to_next_stage(self._buy_seeds, 'buying seeds')
    self._need_regrow = 3

  def _buy_seeds(self):
    print('[>>] buying seeds')
    self._change_flag('need_to_rest', True)
    self._proceed_to_next_stage(self._grow_apple_trees, 'growing apple trees')

  def _grow_apple_trees(self):
    print('[>>] growing seeds')
    self._proceed_to_next_stage(self._collect_apples, 'collecting apples')
    self._change_flag('need_to_rest', True)

  def _collect_apples(self):
    print('[>>] collecting apples')
    if self._need_regrow > 0:
      self._proceed_to_next_stage(self._grow_apple_trees, 'grow apple trees again')
      self._need_regrow -= 1
    else:
      self._proceed_to_next_stage(self._make_apple_pie, 'making apple pie')

  def _make_apple_pie(self):
    print('[>>] making final apple pie')
    self._change_flag('kitchen_dirty', True)
    self._proceed_to_next_stage(None, None)  # we're done


def _test1():
  print('making apple pie with ApplePieMaker')
  runner = ApplePieMaker()
  while runner.stages_left():
    runner.stage()
    if len(runner.get_changed_flags()):
      print('[  ] changed flags:', runner.get_changed_flags())
    if 'kitchen_dirty' in runner.get_changed_flags():
      print('+#+#+ cleaning kitchen')
    print()
  print('thx for using this freeware program')


def test_stage_runner2(argv):
  _test1()


if __name__ == '__main__':
  test_stage_runner2(sys.argv[1:])
