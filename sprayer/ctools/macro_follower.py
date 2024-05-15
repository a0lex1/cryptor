# defines not supported, but can be added (like DefinesCollector)
class MacroFollower:
  def __init__(self, defs=None):
    if defs == None:
      defs = []
    # stack is a list of tuples
    self.stack = []
    self.defs = defs
    pass
  def input_line(self, line):
    #print('self.stack =>', self.stack)
    self.skip_cur_line = True
    stk = self.stack
    if line.startswith('#ifdef '):
      macro_name = line.split(' ')[1]
      stk.append((macro_name, True)) #ifdef
    elif line.startswith('#ifndef '):
      macro_name = line.split(' ')[1]
      stk.append((macro_name, False)) #ifndef
    elif line.startswith('#else'): # invert most recent
      assert(len(stk) != 0)
      stk[-1] = (stk[-1][0], True if stk[-1][1] == False else False)
    elif line.startswith('#endif'):
      if len(stk) == 0:
        raise RuntimeError('#endif with no stack')
      del stk[-1]
    else:
      self.skip_cur_line = False
  # get opened ifdefs and ifndefs
  def need_to_skip_line(self):
    if self.skip_cur_line:
      return True
    stk = self.stack
    for macro_name, is_ifdef in stk:
      if is_ifdef:
        # something must be defined
        if not macro_name in self.defs:
          return True
      else:
        # something must NOT be defined
        if macro_name in self.defs:
          return True
    return False
