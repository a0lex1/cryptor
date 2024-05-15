from enum import Flag, auto


# The use of consts is controlled by EGFlag.CONSTS; the use of Var(s) is controlled by setting picker/sequencer to None

class EGFlag(Flag):
  CONSTS = auto() # Allow using consts in exprs
  ALLOW_COMPILE_TIME_CONSTS = auto() # Allow to generate compile-time solveable exprs (21*31278-3, etc.)
  #ALLOW_NAKED_CONSTS = auto() # obsolete; gone; expr containing const only5

EG_FLAG_DEFAULT = EGFlag.CONSTS

