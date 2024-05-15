from typing import Dict, Callable

from c2.base.stage_runner import StageRunner


# Abstract object that executes the stages of StageRunner
class StageRunnerExecutor:
  def all_stages(self, stagerunner:StageRunner) -> None:
    raise NotImplementedError()

# A generic implementation of executor which
#   !) picks and executes dispatches (fns) when props changed
# changeprop_disp_map=>
#   { 'mouse_changed': lambda
#
class BasicStageRunnerExecutor(StageRunnerExecutor):
  def __init__(self, changeprop_disp_map:Dict[str, Callable[[Dict,], None]]):
    self.__changeprop_disp_map = changeprop_disp_map


  def all_stages(self, stagerunner:StageRunner) -> None:
    sr = stagerunner
    verif_stage_index = 0
    while sr.stages_left():
      assert(sr.stage_index() == verif_stage_index)
      numflags = len(sr.get_flags())
      numchangedflags = len(sr.get_changed_flags())
      print(f'before stage #{sr.stage_index()} \'{sr.stage_name()}\', {numflags}/{numchangedflags} flags changed')
      verif_stage_index += 1
      sr.stage()
      print('after stage')

      
def _test_stage_runner_executor():
  sr = StageRunner()
  
  my_map = {
    'titssize_changed': lambda prop:,
    'penis_full': lambda prop:
  }
  
  sre = StageRunnerExecutor(my_map)
  sre.all_stages(sr)


def _test():
  _test_stage_runner_executor()


if __name__ == '__main__':
  _test()

