from typing import IO, List


class MultiStreamWriter:
  def __init__(self, stms:List[IO]=None):
    if stms == None:
      stms = []
    self._stms = stms

  def add_stream(self, stm:IO):
    self._stms.append(stm)

  def write(self, msg):
    for stm in self._stms:
      stm.write(msg)

  def flush(self):
    for stm in self._stms:
      stm.flush()