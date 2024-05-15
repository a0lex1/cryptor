import re

from c2.sprayer.ctools.macro_follower import MacroFollower
from c2.common.utils import strargs2map

# controlchars -> @@@, !!!, etc. --> commands will be //@@@, //!!!, etc.
class Preprocessor:
  def __init__(self, macro_follower:MacroFollower, controlchars, skip_comments=True):
    self._macro_follower = macro_follower
    self.controlchars = controlchars #TODO
    self._skip_comments = skip_comments

  # for derived: override these _handle_xxx functions with real code
  def _handle_normal_line(self, line):
    print(f'normal  line: {line}')

  def _handle_macro(self, macro_name, macro_opts):
    print(f'MACRO! {macro_name=} {macro_opts=}')


  # interface
  def input_line(self, line):
    # strip both rstrip (\n) and lstrip (leading whitespaces, required for control line parsing mechanism)
    line = line.rstrip()
    line = line.lstrip()

    if re.match('^\s*$', line):
      return # skip whitespacesonly line
    if f'// {self.controlchars}' in line:
      raise RuntimeError('suspicious line: it contains sequence `// @@@`, forgot to remove space?')

    self._macro_follower.input_line(line)  # #ifdef can be placed outside @@@proc and @@@staticvars

    if self._macro_follower.need_to_skip_line():
      return

    pre = f'//{self.controlchars}'
    pre_len = len(pre)
    if line[:pre_len] == pre:
      rest = line[pre_len:]
      m = re.match('([a-zA-Z0-9_]+) ?(.*?)$', rest)
      if m:
        ###################
        ### Macro line ###
        ###################
        macro = m[1]
        if len(m[2]):
          mopts = strargs2map(m[2])
        else:
          mopts = {}
          
        self._handle_macro(macro, mopts)

        return # DONE HANDLING CONTROL LINE

    # if we got here, the line isn't a control line, which means it's a NORMAL line
    ###################
    ### Normal line ###
    ###################
    if re.match(r'\s*\/\/.*?', line):
      if self._skip_comments:
        return # skip comment line

    self._handle_normal_line(line)

    return




