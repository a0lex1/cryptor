from typing import List, Callable

from c2.sprayer.ccode.node import node_line, Node
from c2.base.stage_runner import StageRunner

'''
Reminder: rg.spraytab_procidxes is not like rolearr, namearr, etc. Its size is the number of spraytab procs.
rg.spraytab_procidxes maps every spraytab['procs'] to rolearr index (same index for other output arrs):

                         0       1       2
spraytab['procs'] =     ['init', 'work', 'shutdown']
rg.spraytab_procidxes = [ #5,    #1,     #3 ]
rg.rolearr    = [Role(), Role(), Role(), Role(), Role(), Role(), Role()]
rg.namearr    = ['nam1', 'nam2', 'nam3', 'nam4', 'nam5', 'nam6', 'nam7']
rg.nidarr     = [101,    102,    103,    104,    155,    160,    100] 
                 #0      #1      #2      #3      #4      #5      #6
(other rg. arr(s)...)

'''

# |spraytab| may be edited after RoleGen work! Don't reuse it!
# Every RoleGen should set _CALL(F) in |defs| because it's not defined statically in sprayed build
# RoleGen CAN change |spraytab|. Make a copy if you want original one
class RoleGen(StageRunner):
  def __init__(self, spraytab, fn_create_pxlx_line_node:Callable[[int, int], Node], opts, rng):
    super().__init__()
    self.spraytab = spraytab
    self._fn_create_pxlx_line_node = fn_create_pxlx_line_node
    self._opts = opts
    self._rng = rng

    # Interface: output properties
    self.rolearr = None
    self.spraytab_procidxes = None # see description above
    self.defs = None
    self.arglistarr = None
    self.fixed_var_names = None  # { Var( ): '_xarg', Var( ): 'hKey' }
    self.lvararr = None
    self.namearr = None
    self.specific_lines = None


  # helper for deriveds; they can use this to set self.defs['CALL(F)']
  def _make_call_def_for_args(self, args:List[str]):
    # #Weakness1
    #   A. needs trashing between lines ? <- needs RG to replace spraytab's _CALL()s instead of making defines
    #   B. need to obfuscate constants (5, etc.) <- will be done by changing XARG format
    return f'{{STK_CUR += 5; F##_ENTRY({", ".join(args)}); STK_CUR -= 5;}}'

