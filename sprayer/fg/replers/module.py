from typing import Dict

from c2.sprayer.fg.replers.functions import ReplerHandler


class Module:
  def __init__(self):
    self._host = None
  def _connect_host(self, host:'ReplacerHost'):
    self._host = host
  def _get_handler_map(self) -> Dict[str, ReplerHandler]:
    raise NotImplementedError()

