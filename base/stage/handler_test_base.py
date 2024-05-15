from c2.base.stage.text_handlers import TextWriteHandler


class HandlerTestBase:
  def __init__(self):
    self._twh = None

  def execute(self):
    self._prepare()

    assert(self._twh == None)
    self._create_text_write_handler()

    assert(self._twh != None)
    self._init_text_write_handler()

    self._simulate_property_changes()

    self._uninit_text_write_handler()

    self._check_results()

  def _prepare(self):
    pass

  def _check_results(self):
    pass

  # Should set self._twh
  def _create_text_write_handler(self) -> None:
    self._twh = TextWriteHandler()

  def _init_text_write_handler(self):
    self._twh.init()

  def _uninit_text_write_handler(self):
    self._twh.uninit()

  def _simulate_property_changes(self):
    raise NotImplementedError()