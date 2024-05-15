from c2.base.stage.write_handler_test_base import WriteHandlerTestBase
from c2.base.stage.prop_change_info import PropChangeInfo


# run this twice to ensure the file isn't blocked (e.g. no handle leak)
class WriteHandlerTest1(WriteHandlerTestBase):
  def __init__(self):
    super().__init__()
    self.__file_path = self._test_dir + '/foo_$(StageName)_bar.txt'

  def _init_text_write_handler(self):
    self._twh.init(['--file', self.__file_path])

  def _simulate_property_changes(self):
    twh = self._twh
    twh.handle_property_change(PropChangeInfo('myprop1', 'text', 'first stage'), 'hello from first stage A\nhello from first stage B\n')
    twh.handle_property_change(PropChangeInfo('myprop2', 'text', 'second stage'), 'hello from second stage A\nhello from second stage B\n')
    twh.handle_property_change(PropChangeInfo('myprop3', 'text', 'third stage'), 'hello from third stage A\nhello from third stage B\n')
    twh.handle_property_change(PropChangeInfo('myprop3', 'text', 'fourth stage'), 'hello from fourth stage A\nhello from fourth stage B\n')
    twh.handle_property_change(PropChangeInfo('myprop3', 'text', 'fifth stage'), 'hello from fifth stage A\nhello from fifth stage B\n')

  def _get_expected_filecontent_tups(self):
    test_dir = self._test_dir
    return [
      (test_dir + '/foo_first stage_bar.txt', 'hello from first stage A\nhello from first stage B\n'),
      (test_dir + '/foo_second stage_bar.txt', 'hello from second stage A\nhello from second stage B\n'),
      (test_dir + '/foo_third stage_bar.txt', 'hello from third stage A\nhello from third stage B\n'),
      (test_dir + '/foo_fourth stage_bar.txt', 'hello from fourth stage A\nhello from fourth stage B\n'),
      (test_dir + '/foo_fifth stage_bar.txt', 'hello from fifth stage A\nhello from fifth stage B\n')
    ]


# Instead of $(StageName) use TODOTODO in file name
class WriteHandlerTest2(WriteHandlerTestBase):
  def __init__(self):
    super().__init__()
    self.__file_path = self._test_dir + '/$(PropName)_($(CatName)).log'

  def _init_text_write_handler(self):
    self._twh.init(['--file', self.__file_path])

  def _simulate_property_changes(self):
    twh = self._twh
    twh.handle_property_change(PropChangeInfo('myprop1', 'text', 'first stage'), 'hello from first stage A\nhello from first stage B\n')
    twh.handle_property_change(PropChangeInfo('myprop2', 'text', 'second stage'), 'hello from second stage A\nhello from second stage B\n')
    twh.handle_property_change(PropChangeInfo('myprop3', 'text', 'third stage'), 'hello from third stage A\nhello from third stage B\n')
    twh.handle_property_change(PropChangeInfo('myprop3', 'text', 'fourth stage'), 'hello from fourth stage A\nhello from fourth stage B\n')
    twh.handle_property_change(PropChangeInfo('myprop3', 'text', 'fifth stage'), 'hello from fifth stage A\nhello from fifth stage B\n')

  def _get_expected_filecontent_tups(self):
    test_dir = self._test_dir
    return [
      (test_dir + '/myprop1_(text).log', 'hello from first stage A\nhello from first stage B\n'),
      (test_dir + '/myprop2_(text).log', 'hello from second stage A\nhello from second stage B\n'),
      (test_dir + '/myprop3_(text).log', 'hello from third stage A\nhello from third stage B\n'
                                       'hello from fourth stage A\nhello from fourth stage B\n'
                                       'hello from fifth stage A\nhello from fifth stage B\n')
    ]


def test_text_handlers(argv=None):
  # run twice
  test1 = WriteHandlerTest1()
  test1.execute()
  test1 = WriteHandlerTest1()
  test1.execute()

  test2 = WriteHandlerTest2()
  test2.execute()
  test2 = WriteHandlerTest2()
  test2.execute()


if __name__ == '__main__':
  test_text_handlers()

