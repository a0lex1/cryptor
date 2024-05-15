import shutil, os
from typing import List, Tuple

from c2._internal_config import get_tmp_dir
from c2.base.stage.handler_test_base import HandlerTestBase


class WriteHandlerTestBase(HandlerTestBase):
  def __init__(self):
    super().__init__()
    self._test_dir = get_tmp_dir() + '/test_text_write_handler' # use it in derived
    self._twh = None

  def _prepare(self):
    self.__recreate_test_dir()

  def _check_results(self):
    # verify output files
    expected_tups = self._get_expected_filecontent_tups() # [(path:str, content:str), ]
    for path, expected_content in expected_tups:
      actual_content = open(path, 'r').read()
      if actual_content != expected_content:
        print(f'Expected content of {path} is:')
        print(expected_content)
        print(f'But the ACTUAL content of {path} is:')
        print(actual_content)
        raise RuntimeError('actual_content != expected_content, see log')

  def __recreate_test_dir(self):
    if os.path.isdir(self._test_dir):
      shutil.rmtree(self._test_dir)
    os.makedirs(self._test_dir)

  # to implement in derived
  def _get_expected_filecontent_tups(self) -> List[Tuple[str, str]]:
    raise NotImplementedError()
