from enum import Enum, auto


class Flow(Enum):
  EXEC     = auto()
  NOT_EXEC = auto()
  MAYBE    = auto()


